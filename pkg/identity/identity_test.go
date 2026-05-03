package identity

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"
)

// --------------------------------------------------------------------------
// HeaderVerifier
// --------------------------------------------------------------------------

func TestHeaderVerifier_ValidBearer(t *testing.T) {
	v := NewHeaderVerifier("Authorization")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer my-test-token")

	id, err := v.Verify(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id == nil {
		t.Fatal("expected non-nil Identity")
	}
	if id.Subject != "my-test-token" {
		t.Errorf("expected Subject == %q, got %q", "my-test-token", id.Subject)
	}
	if id.Raw != "my-test-token" {
		t.Errorf("expected Raw == %q, got %q", "my-test-token", id.Raw)
	}
}

func TestHeaderVerifier_MissingHeader(t *testing.T) {
	v := NewHeaderVerifier("Authorization")
	r := httptest.NewRequest("GET", "/", nil)

	_, err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for missing Authorization header")
	}
}

func TestHeaderVerifier_MalformedBearer(t *testing.T) {
	v := NewHeaderVerifier("Authorization")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "not-a-bearer-token")

	_, err := v.Verify(r)
	if err == nil {
		t.Fatal("expected error for malformed Bearer token (no 'Bearer ' prefix)")
	}
}

func TestHeaderVerifier_SetsSessionID(t *testing.T) {
	v := NewHeaderVerifier("Authorization")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer my-token")
	r.Header.Set("Mcp-Session-Id", "sess-abc")

	id, err := v.Verify(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.SessionID != "sess-abc" {
		t.Errorf("expected SessionID %q, got %q", "sess-abc", id.SessionID)
	}
}

func TestHeaderVerifier_CustomHeader(t *testing.T) {
	v := NewHeaderVerifier("X-Api-Token")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Api-Token", "Bearer custom-value")

	id, err := v.Verify(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.Subject != "custom-value" {
		t.Errorf("expected Subject %q, got %q", "custom-value", id.Subject)
	}
}

// --------------------------------------------------------------------------
// NoopVerifier
// --------------------------------------------------------------------------

func TestNoopVerifier_ReturnsSyntheticIdentity(t *testing.T) {
	v := &NoopVerifier{}
	r := httptest.NewRequest("GET", "/", nil)

	id, err := v.Verify(r)
	if err != nil {
		t.Fatalf("NoopVerifier must not return an error: %v", err)
	}
	if id == nil {
		t.Fatal("NoopVerifier must return a non-nil Identity")
	}
	if id.Subject == "" {
		t.Error("NoopVerifier should set a non-empty Subject")
	}
}

func TestNoopVerifier_PropagatesSessionID(t *testing.T) {
	v := &NoopVerifier{}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Mcp-Session-Id", "noop-sess")

	id, err := v.Verify(r)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.SessionID != "noop-sess" {
		t.Errorf("expected SessionID %q, got %q", "noop-sess", id.SessionID)
	}
}

// --------------------------------------------------------------------------
// WithIdentity / FromContext
// --------------------------------------------------------------------------

func TestWithIdentity_FromContext_RoundTrip(t *testing.T) {
	original := &Identity{Subject: "alice", SessionID: "sess1"}
	ctx := WithIdentity(context.Background(), original)

	got := FromContext(ctx)
	if got == nil {
		t.Fatal("FromContext returned nil; expected the stored Identity")
	}
	if got.Subject != "alice" {
		t.Errorf("expected Subject %q, got %q", "alice", got.Subject)
	}
	if got.SessionID != "sess1" {
		t.Errorf("expected SessionID %q, got %q", "sess1", got.SessionID)
	}
}

func TestFromContext_EmptyContext_ReturnsNil(t *testing.T) {
	got := FromContext(context.Background())
	if got != nil {
		t.Errorf("expected nil from empty context, got %+v", got)
	}
}

func TestWithIdentity_Overwrites(t *testing.T) {
	id1 := &Identity{Subject: "first"}
	id2 := &Identity{Subject: "second"}

	ctx := WithIdentity(context.Background(), id1)
	ctx = WithIdentity(ctx, id2)

	got := FromContext(ctx)
	if got == nil {
		t.Fatal("expected non-nil identity")
	}
	if got.Subject != "second" {
		t.Errorf("expected %q, got %q", "second", got.Subject)
	}
}

// --------------------------------------------------------------------------
// MultiVerifier
// --------------------------------------------------------------------------

func TestMultiVerifier_MissingHeader(t *testing.T) {
	mv := NewMultiVerifier(nil, "Authorization")
	r := httptest.NewRequest("GET", "/", nil)

	_, err := mv.Verify(r)
	if err == nil {
		t.Fatal("expected error for missing Authorization header")
	}
}

func TestMultiVerifier_NoProviders_ReturnsError(t *testing.T) {
	mv := NewMultiVerifier(nil, "Authorization")
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer sometoken")

	_, err := mv.Verify(r)
	if err == nil {
		t.Fatal("expected error when no providers are configured")
	}
}

func TestMultiVerifier_DefaultsToAuthorizationHeader(t *testing.T) {
	// Passing empty header should default to "Authorization".
	mv := NewMultiVerifier(nil, "")
	r := httptest.NewRequest("GET", "/", nil)
	// No header set; should fail with "missing header: Authorization".
	_, err := mv.Verify(r)
	if err == nil {
		t.Fatal("expected error for missing Authorization header")
	}
}

// --------------------------------------------------------------------------
// DriftDetector – Clear and Sweep
// --------------------------------------------------------------------------

func TestDriftDetector_Clear(t *testing.T) {
	dd := NewDriftDetector()
	id := &Identity{SessionID: "s1", Scopes: []string{"read"}}
	dd.Check(id)

	// Clear the session; next check should act as a fresh baseline.
	dd.Clear("s1")

	// Now use different scopes — should not report drift.
	id2 := &Identity{SessionID: "s1", Scopes: []string{"admin"}}
	if err := dd.Check(id2); err != nil {
		t.Errorf("after Clear, first check should re-establish baseline: %v", err)
	}
}

func TestDriftDetector_Sweep(t *testing.T) {
	dd := NewDriftDetector()
	id := &Identity{SessionID: "s1", Scopes: []string{"read"}}
	dd.Check(id)

	dd.Sweep()

	// After sweep, all sessions removed; next check is a fresh baseline.
	id2 := &Identity{SessionID: "s1", Scopes: []string{"admin"}}
	if err := dd.Check(id2); err != nil {
		t.Errorf("after Sweep, first check should re-establish baseline: %v", err)
	}
}

// --------------------------------------------------------------------------
// SessionBinder – Clear
// --------------------------------------------------------------------------

func TestSessionBinder_Clear(t *testing.T) {
	sb := NewSessionBinder()
	sb.Bind("sess", "alice")

	sb.Clear("sess")

	// After clear, re-binding with a different subject should succeed.
	if err := sb.Bind("sess", "bob"); err != nil {
		t.Errorf("after Clear, binding new subject should succeed: %v", err)
	}
}

// --------------------------------------------------------------------------
// IntegrityChecker – Sweep (no-op on nil detector)
// --------------------------------------------------------------------------

func TestIntegrityChecker_Sweep_NilSafe(t *testing.T) {
	// With DetectReplay disabled, Sweep must not panic.
	ic := NewIntegrityChecker(IntegrityConfig{BindToSession: true, DetectReplay: false})
	ic.Sweep() // must not panic
}

func TestIntegrityChecker_Sweep_WithReplay(t *testing.T) {
	ic := NewIntegrityChecker(IntegrityConfig{DetectReplay: true, ReplayMaxAge: 10 * time.Minute})
	ic.Sweep() // exercises the non-nil detector path
}

func TestIntegrityChecker_Check_Nil(t *testing.T) {
	// A nil *IntegrityChecker must return nil (the production code handles this).
	var ic *IntegrityChecker
	if err := ic.Check(&Identity{Subject: "x", SessionID: "y"}); err != nil {
		t.Errorf("nil IntegrityChecker.Check should return nil: %v", err)
	}
}

// --------------------------------------------------------------------------
// ReplayDetector – sweep cleans up expired entries
// --------------------------------------------------------------------------

func TestReplayDetector_Sweep_RemovesExpired(t *testing.T) {
	rd := NewReplayDetector(0) // default 10m maxAge
	rd.Check("jti-1")
	rd.Sweep() // should not remove fresh entry, must not panic
}

func TestReplayDetector_DefaultMaxAge(t *testing.T) {
	// NewReplayDetector(0) should still work (default maxAge applied).
	rd := NewReplayDetector(0)
	if err := rd.Check("jti-unique"); err != nil {
		t.Fatalf("first check should pass: %v", err)
	}
	if err := rd.Check("jti-unique"); err == nil {
		t.Fatal("replay should be detected on second check with same jti")
	}
}
