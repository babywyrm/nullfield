package extauthz

import (
	"context"
	"errors"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/policy"
)

// clusterDNS answers reverse lookups the way CoreDNS does for Service VIPs.
func clusterDNS(_ context.Context, addr string) ([]string, error) {
	if name, ok := map[string]string{
		"10.43.0.10": "mcp-github.tools.svc.cluster.local.",
		"10.43.0.20": "run-controller.agents.svc.cluster.local.",
		"10.42.0.5":  "10-42-0-5.tools.pod.cluster.local.",
		"10.42.0.6":  "web-0.web.tools.svc.cluster.local.",
		"172.18.0.4": "demo-mcp-echo-1.demo_default.",
		"fd00::10":   "mcp-github.tools.svc.cluster.local.",
	}[addr]; ok {
		return []string{name}, nil
	}
	return nil, errors.New("no PTR")
}

func toAddress(host, addr string) *authv3.CheckRequest {
	req := checkRequest(spiffeRunner, toolsCallBody, nil)
	req.Attributes.Request.Http.Host = host
	req.Attributes.Destination = &authv3.AttributeContext_Peer{Address: &corev3.Address{
		Address: &corev3.Address_SocketAddress{SocketAddress: &corev3.SocketAddress{Address: addr}}}}
	return req
}

func TestAHostThatNamesAnotherServiceIsRefused(t *testing.T) {
	rec := &recorder{}
	allow := policy.NewRuleEngine([]v1alpha1.Rule{{Action: v1alpha1.ActionAllow}})
	s := NewServer(Config{Mode: ModeEnforce, Audit: rec, Engine: allow, LookupAddr: clusterDNS})

	// A waypoint routes on the address, so this reaches run-controller while
	// claiming to be mcp-github.
	if got := status(t, s, toAddress("mcp-github.tools.svc.cluster.local", "10.43.0.20")); got != codes.PermissionDenied {
		t.Fatalf("spoofed Host: %v, want PermissionDenied", got)
	}
	if e := rec.events[len(rec.events)-1]; e.Gate != GateTarget || e.ReasonClass != ReasonTargetMismatch {
		t.Errorf("recorded gate=%q class=%q", e.Gate, e.ReasonClass)
	}

	for _, host := range []string{
		"mcp-github", "mcp-github.tools", "mcp-github.tools.svc",
		"MCP-GitHub.tools.svc.cluster.local.:8080", "10.43.0.10",
	} {
		if got := status(t, s, toAddress(host, "10.43.0.10")); got != codes.OK {
			t.Errorf("Host %q to the service it names: %v, want OK", host, got)
		}
	}
	for _, host := range []string{"[fd00::10]", "[fd00::10]:80", "mcp-github"} {
		if got := status(t, s, toAddress(host, "fd00::10")); got != codes.OK {
			t.Errorf("Host %q to an IPv6 Service address: %v, want OK", host, got)
		}
	}
	for _, host := range []string{"mcp", "github.tools.svc.cluster.local", "mcp-github.tools.svc.cluster.local.evil"} {
		if got := status(t, s, toAddress(host, "10.43.0.10")); got != codes.PermissionDenied {
			t.Errorf("Host %q: %v, want PermissionDenied", host, got)
		}
	}
}

func TestADestinationDNSCannotNameIsLeftUnverified(t *testing.T) {
	allow := policy.NewRuleEngine([]v1alpha1.Rule{{Action: v1alpha1.ActionAllow}})
	s := NewServer(Config{Mode: ModeEnforce, Audit: &recorder{}, Engine: allow, LookupAddr: clusterDNS})

	// A ServiceEntry VIP has no PTR. A pod IP, which is the destination behind
	// a sidecar, a headless Service's pod name, and a compose container all
	// reverse-resolve, but not to a Service.
	for _, addr := range []string{"240.240.0.1", "10.42.0.5", "10.42.0.6", "172.18.0.4"} {
		tr, err := Translate(toAddress("mcp-echo", addr))
		if err != nil {
			t.Fatal(err)
		}
		if d := s.decide(t.Context(), tr); !d.Allowed || tr.Service != "" {
			t.Errorf("%s: allowed=%v service=%q, want allowed and no verified service", addr, d.Allowed, tr.Service)
		}
	}

	tr, _ := Translate(toAddress("mcp-github", "10.43.0.10"))
	if s.decide(t.Context(), tr); tr.Service != "mcp-github.tools.svc.cluster.local" {
		t.Fatalf("service = %q, want the reverse-resolved name", tr.Service)
	}
}
