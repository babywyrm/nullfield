package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/policy"
)

// scopeRequestEngine allows every call and attaches a request-side SCOPE rule
// that changes the body length in both directions.
type scopeRequestEngine struct {
	strip  []string
	inject map[string]any
}

func (e scopeRequestEngine) Evaluate(_ context.Context, _ policy.Request) policy.Decision {
	return policy.Decision{
		Allowed: true,
		Scoped:  true,
		MatchedRule: &v1alpha1.Rule{
			Action: v1alpha1.ActionScope,
			Scope: &v1alpha1.ScopeConfig{
				Request: &v1alpha1.ScopeRequestConfig{
					StripArguments:  e.strip,
					InjectArguments: e.inject,
				},
			},
		},
	}
}

// toolsCallBodyWithArgs encodes a tools/call whose arguments are given.
func toolsCallBodyWithArgs(t *testing.T, toolName string, args map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"name": toolName, "arguments": args})
	if err != nil {
		t.Fatalf("marshal params: %v", err)
	}
	b, err := json.Marshal(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  MethodToolsCall,
		Params:  raw,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return b
}

// TestHandler_ScopeRequestReachesUpstream is a regression test for a rewritten
// request body being sent with the original Content-Length. ReverseProxy trusts
// ContentLength over the body it is handed, so a SCOPE rule that changed the
// body size made it abort with "ContentLength=N with Body length M" and the
// caller saw 502 with an empty body. Request-side SCOPE was unusable in proxy
// mode for any rule that actually modified anything.
func TestHandler_ScopeRequestReachesUpstream(t *testing.T) {
	cases := []struct {
		name    string
		strip   []string
		inject  map[string]any
		args    map[string]any
		wantHas []string
		wantNot []string
	}{
		{
			// Shrinks the body: the original Content-Length is too large.
			name:    "stripping shrinks the body",
			strip:   []string{"secret_key"},
			args:    map[string]any{"incident_id": "INC-1", "secret_key": "hunter2"},
			wantHas: []string{"INC-1"},
			wantNot: []string{"hunter2", "secret_key"},
		},
		{
			// Grows the body: the original Content-Length is too small.
			name:    "injecting grows the body",
			inject:  map[string]any{"read_only": "true"},
			args:    map[string]any{"incident_id": "INC-1"},
			wantHas: []string{"INC-1", "read_only", "true"},
		},
		{
			name:    "stripping and injecting together",
			strip:   []string{"secret_key"},
			inject:  map[string]any{"read_only": "true"},
			args:    map[string]any{"incident_id": "INC-1", "secret_key": "hunter2"},
			wantHas: []string{"INC-1", "read_only"},
			wantNot: []string{"hunter2"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var received []byte
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received, _ = io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`))
			}))
			defer upstream.Close()

			h := makeHandler(t, upstream,
				scopeRequestEngine{strip: tc.strip, inject: tc.inject},
				&identity.NoopVerifier{})

			body := toolsCallBodyWithArgs(t, "test_tool", tc.args)
			req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.ContentLength = int64(len(body))

			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body = %q", w.Code, w.Body.String())
			}
			if len(received) == 0 {
				t.Fatal("upstream received nothing; the proxy never forwarded the request")
			}

			got := string(received)
			for _, want := range tc.wantHas {
				if !bytes.Contains(received, []byte(want)) {
					t.Errorf("upstream body missing %q; got %s", want, got)
				}
			}
			for _, unwanted := range tc.wantNot {
				if bytes.Contains(received, []byte(unwanted)) {
					t.Errorf("upstream body still contains %q; got %s", unwanted, got)
				}
			}
		})
	}
}
