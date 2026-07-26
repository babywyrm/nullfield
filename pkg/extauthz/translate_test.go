package extauthz

import (
	"strconv"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/babywyrm/nullfield/pkg/policy"
)

// checkRequest builds a CheckRequest with a consistent size attribute, so a
// fixture cannot accidentally assert truncation it did not intend.
func checkRequest(principal, body string, headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Source: &authv3.AttributeContext_Peer{Principal: principal},
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  "POST",
					Path:    "/mcp",
					Host:    "mcp-server.zerotrust.svc.cluster.local",
					Headers: headers,
					Body:    body,
					Size:    int64(len(body)),
				},
			},
		},
	}
}

func TestEnvoysOwnPartialBodyHeaderIsAuthoritative(t *testing.T) {
	// Observed on live waypoint traffic. Envoy states this directly, so it
	// outranks anything we could infer from lengths.
	if !BodyTruncated(0, map[string]string{PartialBodyHeader: "true"}, "whatever fit") {
		t.Error("partial-body true must read as truncated")
	}
	if BodyTruncated(0, map[string]string{PartialBodyHeader: "false"}, "whatever fit") {
		t.Error("partial-body false must not read as truncated")
	}
}

func TestThePartialBodyHeaderOutranksTheLengthSignals(t *testing.T) {
	// A size attribute disagreeing with the body is exactly what happens when
	// Envoy buffers a large body it did NOT truncate, so believing size over
	// Envoy's own answer would deny legitimate traffic.
	headers := map[string]string{
		PartialBodyHeader: "false",
		"content-length":  "20000",
	}
	if BodyTruncated(20000, headers, "short") {
		t.Error("Envoy said the body was complete; the length signals must not override it")
	}
}

func TestBodyTruncatedWhenSizeExceedsWhatArrived(t *testing.T) {
	if !BodyTruncated(20000, map[string]string{}, "only the first 8k of it") {
		t.Fatal("expected truncation to be detected from the size attribute")
	}
}

func TestBodyNotTruncatedWhenSizeMatches(t *testing.T) {
	body := `{"jsonrpc":"2.0"}`
	if BodyTruncated(int64(len(body)), map[string]string{}, body) {
		t.Fatal("did not expect truncation when size matches the body")
	}
}

func TestContentLengthIsTheFallbackWhenSizeIsUnknown(t *testing.T) {
	// Envoy sets size to -1 when unknown, and leaves it at the proto3 zero when
	// simply unpopulated. Both must fall through to the header.
	for _, size := range []int64{-1, 0} {
		if !BodyTruncated(size, map[string]string{"content-length": "20000"}, "short") {
			t.Errorf("size %d: expected the content-length fallback to detect truncation", size)
		}
	}
}

func TestMissingLengthSignalsAreNotTreatedAsTruncation(t *testing.T) {
	// Chunked requests carry neither signal. Treating that as truncation would
	// deny every streamed request, which is its own outage.
	if BodyTruncated(0, map[string]string{}, "{}") {
		t.Fatal("absent length signals must not read as truncated")
	}
}

func TestUnparseableContentLengthIsNotTreatedAsTruncation(t *testing.T) {
	if BodyTruncated(-1, map[string]string{"content-length": "banana"}, "{}") {
		t.Fatal("unparseable content-length must not read as truncated")
	}
}

func TestTranslateExtractsTheToolCallAndTarget(t *testing.T) {
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"secrets.leak_config","arguments":{"path":"/etc/shadow"}}}`
	req := checkRequest("spiffe://cluster.local/ns/agents/sa/job-runner", body,
		map[string]string{"content-length": strconv.Itoa(len(body))})

	got, err := Translate(req)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if got.Policy.ToolName != "secrets.leak_config" {
		t.Errorf("tool = %q, want secrets.leak_config", got.Policy.ToolName)
	}
	if got.Policy.Transport != policy.TransportMCP {
		t.Errorf("transport = %q, want %q", got.Policy.Transport, policy.TransportMCP)
	}
	if got.Policy.Method != "tools/call" {
		t.Errorf("method = %q, want tools/call", got.Policy.Method)
	}
	if got.Policy.Target != "mcp-server.zerotrust.svc.cluster.local" {
		t.Errorf("target = %q, want the request host", got.Policy.Target)
	}
	if got.Policy.Arguments["path"] != "/etc/shadow" {
		t.Errorf("arguments not carried through: %+v", got.Policy.Arguments)
	}
	if got.Attestation == nil {
		t.Fatal("attestation is nil, want a mesh attestation")
	}
	if got.Attestation.Namespace != "agents" || got.Attestation.ServiceAccount != "job-runner" {
		t.Errorf("attestation = %+v, want agents/job-runner", got.Attestation)
	}
}

func TestTranslateRejectsATruncatedBody(t *testing.T) {
	req := checkRequest("spiffe://cluster.local/ns/agents/sa/job-runner",
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"`, map[string]string{})
	req.Attributes.Request.Http.Size = 99999

	if _, err := Translate(req); err == nil {
		t.Fatal("expected truncation to be an error so the caller fails closed")
	}
}

func TestTranslateReadsRawBodyWhenPackAsBytesIsSet(t *testing.T) {
	// Envoy populates RawBody instead of Body under pack_as_bytes. Reading only
	// Body would make every tools/call look like ordinary wire traffic, which is
	// a silent total loss of MCP coverage rather than a visible failure.
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"secrets.leak_config","arguments":{}}}`
	req := checkRequest("spiffe://cluster.local/ns/agents/sa/job-runner", "", map[string]string{})
	req.Attributes.Request.Http.RawBody = []byte(body)
	req.Attributes.Request.Http.Size = int64(len(body))

	got, err := Translate(req)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if got.Policy.ToolName != "secrets.leak_config" {
		t.Errorf("tool = %q, want secrets.leak_config from RawBody", got.Policy.ToolName)
	}
	if got.Policy.Transport != policy.TransportMCP {
		t.Errorf("transport = %q, want %q", got.Policy.Transport, policy.TransportMCP)
	}
}

func TestTranslateClassifiesNonMCPTrafficAsWireAPI(t *testing.T) {
	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Source: &authv3.AttributeContext_Peer{Principal: "spiffe://cluster.local/ns/agents/sa/job-runner"},
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "DELETE",
					Path:   "/repos/acme/widgets",
					Host:   "api.github.com",
				},
			},
		},
	}

	got, err := Translate(req)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if got.Policy.Transport != policy.TransportWireAPI {
		t.Errorf("transport = %q, want %q", got.Policy.Transport, policy.TransportWireAPI)
	}
	if got.Policy.Operation != "DELETE /repos/acme/widgets" {
		t.Errorf("operation = %q, want the method and path", got.Policy.Operation)
	}
	if got.Policy.ToolName != "" {
		t.Errorf("tool name = %q, want empty for non-MCP traffic", got.Policy.ToolName)
	}
}

func TestTranslateReturnsNoAttestationForAnUnauthenticatedPeer(t *testing.T) {
	got, err := Translate(checkRequest("", "{}", map[string]string{}))
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if got.Attestation != nil {
		t.Errorf("attestation = %+v, want nil when there is no peer principal", got.Attestation)
	}
}

func TestTranslateReturnsNoAttestationForAnUnparseablePrincipal(t *testing.T) {
	// A principal we cannot parse must not become a half-populated attestation
	// that reads downstream as an identified workload.
	got, err := Translate(checkRequest("some-opaque-principal", "{}", map[string]string{}))
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if got.Attestation != nil {
		t.Errorf("attestation = %+v, want nil for an unparseable principal", got.Attestation)
	}
}

func TestTranslateRejectsARequestWithNoHTTPAttributes(t *testing.T) {
	if _, err := Translate(&authv3.CheckRequest{}); err == nil {
		t.Fatal("expected an error when there are no HTTP attributes to read")
	}
}

func TestTranslateCarriesHeadersForTokenExtraction(t *testing.T) {
	got, err := Translate(checkRequest("", "{}", map[string]string{"authorization": "Bearer abc"}))
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if got.Headers.Get("Authorization") != "Bearer abc" {
		t.Errorf("headers did not survive translation: %+v", got.Headers)
	}
}
