package identity

import (
	"testing"
)

func TestDriftDetector_FirstCallBaseline(t *testing.T) {
	dd := NewDriftDetector()
	id := &Identity{SessionID: "s1", Scopes: []string{"read", "write"}, Groups: []string{"team-a"}}

	if err := dd.Check(id); err != nil {
		t.Fatalf("first call should set baseline, not error: %v", err)
	}
}

func TestDriftDetector_SameClaims(t *testing.T) {
	dd := NewDriftDetector()
	id := &Identity{SessionID: "s1", Scopes: []string{"read", "write"}, Groups: []string{"team-a"}}

	dd.Check(id)
	if err := dd.Check(id); err != nil {
		t.Fatalf("same claims should not drift: %v", err)
	}
}

func TestDriftDetector_ScopesDrifted(t *testing.T) {
	dd := NewDriftDetector()
	id1 := &Identity{SessionID: "s1", Scopes: []string{"read"}}
	id2 := &Identity{SessionID: "s1", Scopes: []string{"read", "admin"}}

	dd.Check(id1)
	err := dd.Check(id2)
	if err == nil {
		t.Fatal("scope change should be detected as drift")
	}
}

func TestDriftDetector_GroupsDrifted(t *testing.T) {
	dd := NewDriftDetector()
	id1 := &Identity{SessionID: "s1", Groups: []string{"users"}}
	id2 := &Identity{SessionID: "s1", Groups: []string{"users", "admins"}}

	dd.Check(id1)
	err := dd.Check(id2)
	if err == nil {
		t.Fatal("group change should be detected as drift")
	}
}

func TestDriftDetector_PerSessionIsolation(t *testing.T) {
	dd := NewDriftDetector()
	id1 := &Identity{SessionID: "s1", Scopes: []string{"read"}}
	id2 := &Identity{SessionID: "s2", Scopes: []string{"admin"}}

	dd.Check(id1)
	if err := dd.Check(id2); err != nil {
		t.Fatalf("different sessions should not cross-check: %v", err)
	}
}

func TestDriftDetector_OrderIndependent(t *testing.T) {
	dd := NewDriftDetector()
	id1 := &Identity{SessionID: "s1", Scopes: []string{"write", "read"}}
	id2 := &Identity{SessionID: "s1", Scopes: []string{"read", "write"}}

	dd.Check(id1)
	if err := dd.Check(id2); err != nil {
		t.Fatalf("same scopes in different order should not drift: %v", err)
	}
}

func TestDriftDetector_NilIdentity(t *testing.T) {
	dd := NewDriftDetector()
	if err := dd.Check(nil); err != nil {
		t.Fatalf("nil identity should not error: %v", err)
	}
}

func TestDriftDetector_EmptySession(t *testing.T) {
	dd := NewDriftDetector()
	id := &Identity{SessionID: "", Scopes: []string{"read"}}
	if err := dd.Check(id); err != nil {
		t.Fatalf("empty session should skip: %v", err)
	}
}
