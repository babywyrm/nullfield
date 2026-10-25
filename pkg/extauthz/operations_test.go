package extauthz

import (
	"os"
	"path/filepath"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/operations"
	"github.com/babywyrm/nullfield/pkg/policy"
)

func TestAMappedOperationReachesPolicyByName(t *testing.T) {
	dir := t.TempDir()
	m := "target: api.github.com\noperations:\n" +
		"  - name: repos.delete\n    method: DELETE\n    path: /repos/{owner}/{repo}\n"
	if err := os.WriteFile(filepath.Join(dir, "github.yaml"), []byte(m), 0o600); err != nil {
		t.Fatal(err)
	}
	ops, err := operations.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	s := NewServer(Config{
		Mode: ModeEnforce, Audit: rec, Operations: ops,
		Engine: policy.NewRuleEngine([]v1alpha1.Rule{
			{Action: v1alpha1.ActionDeny, CELExpression: `has(request.action) && request.action == "repos.delete" && request.params.repo == "widgets"`},
			{Action: v1alpha1.ActionAllow},
		}),
	})
	wire := func(method, path string) *authv3.CheckRequest {
		r := checkRequest(spiffeRunner, "", nil)
		h := r.Attributes.Request.Http
		h.Method, h.Path, h.Host = method, path, "api.github.com"
		return r
	}

	if got := status(t, s, wire("DELETE", "/repos/acme/gadgets")); got != codes.OK {
		t.Fatalf("another repo: %v, want OK", got)
	}
	if got := status(t, s, wire("DELETE", "/repos/acme/widgets")); got != codes.PermissionDenied {
		t.Fatalf("named delete: %v, want PermissionDenied", got)
	}
	if e := rec.events[len(rec.events)-1]; e.Action != "repos.delete" {
		t.Fatalf("audit action = %q, want repos.delete", e.Action)
	}
	if got := status(t, s, wire("DELETE", "/repos/acme/widgets/")); got != codes.PermissionDenied {
		t.Fatalf("trailing slash: %v, want PermissionDenied", got)
	}
	if e := rec.events[len(rec.events)-1]; e.Gate != GateOperation || e.ReasonClass != ReasonOperationAmbiguous {
		t.Fatalf("trailing slash refused by %s/%s, want %s/%s", e.Gate, e.ReasonClass, GateOperation, ReasonOperationAmbiguous)
	}
}
