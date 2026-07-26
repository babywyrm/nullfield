package extauthz

import (
	"context"
	"net"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/babywyrm/nullfield/pkg/policy"
)

// serve starts the real gRPC server on an ephemeral port and returns a client.
//
// The unit tests call Check directly, which proves the logic but not that the
// service is registered under the name Envoy looks up, nor that a CheckResponse
// survives protobuf serialization. Those are exactly the failures that only show
// up once a waypoint is pointed at it.
func serve(t *testing.T, mode Mode, d policy.Decision) (authv3.AuthorizationClient, *recorder) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	rec := &recorder{}
	srv := grpc.NewServer()
	authv3.RegisterAuthorizationServer(srv, NewServer(Config{
		Mode:   mode,
		Engine: &fakeEngine{decision: d},
		Audit:  rec,
	}))

	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient(listener.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return authv3.NewAuthorizationClient(conn), rec
}

func TestCheckOverRealGRPCAllowsInObserveModeAndRecordsTheCounterfactual(t *testing.T) {
	client, rec := serve(t, ModeObserve, policy.Decision{Allowed: false, Reason: "no matching rule"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Check(ctx, checkRequest(spiffeRunner, toolsCallBody, map[string]string{}))
	if err != nil {
		t.Fatalf("Check over gRPC: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(codes.OK) {
		t.Errorf("status = %d, want OK", resp.GetStatus().GetCode())
	}
	if resp.GetOkResponse() == nil {
		t.Error("expected an ok_response in the oneof, got none")
	}

	if len(rec.events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(rec.events))
	}
	if got := rec.events[0].WorkloadPrincipal; got != spiffeRunner {
		t.Errorf("principal = %q, want %q", got, spiffeRunner)
	}
	if got := rec.events[0].Counterfactual; got != "DENY" {
		t.Errorf("counterfactual = %q, want DENY", got)
	}
}

func TestCheckOverRealGRPCDeniesInEnforceModeWithAForbiddenBody(t *testing.T) {
	client, _ := serve(t, ModeEnforce, policy.Decision{Allowed: false, Reason: "no matching rule"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.Check(ctx, checkRequest(spiffeRunner, toolsCallBody, map[string]string{}))
	if err != nil {
		t.Fatalf("Check over gRPC: %v", err)
	}
	if resp.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Errorf("status = %d, want PermissionDenied", resp.GetStatus().GetCode())
	}
	denied := resp.GetDeniedResponse()
	if denied == nil {
		t.Fatal("expected a denied_response in the oneof, got none")
	}
	if denied.GetStatus().GetCode() != 403 {
		t.Errorf("HTTP status = %d, want 403", denied.GetStatus().GetCode())
	}
	if denied.GetBody() != "no matching rule" {
		t.Errorf("body = %q, want the decision reason", denied.GetBody())
	}
}

func TestCheckOverRealGRPCNeverReturnsAnErrorForAPolicyOutcome(t *testing.T) {
	// A gRPC error makes Envoy apply its own failure-mode default, which takes
	// the decision away from nullfield. Policy outcomes must always arrive as a
	// CheckResponse.
	client, _ := serve(t, ModeEnforce, policy.Decision{Allowed: false, Reason: "denied"})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// A request with no HTTP attributes at all is the worst-shaped input we can
	// hand it, and it still must not surface as a transport error.
	if _, err := client.Check(ctx, &authv3.CheckRequest{}); err != nil {
		t.Fatalf("an empty CheckRequest produced a gRPC error: %v", err)
	}
}
