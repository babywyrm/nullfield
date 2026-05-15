package registry

import (
	"testing"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
)

func TestComputeHash_Deterministic(t *testing.T) {
	entry := v1alpha1.ToolRegistryEntry{
		Name:          "tool_a",
		Description:   "does stuff",
		AllowedScopes: []string{"read", "write"},
	}
	h1 := ComputeHash(entry)
	h2 := ComputeHash(entry)
	if h1 != h2 {
		t.Fatalf("hashes should be deterministic: %q != %q", h1, h2)
	}
	if h1 == "" {
		t.Fatal("hash should not be empty")
	}
}

func TestComputeHash_UsesSignatureHash(t *testing.T) {
	entry := v1alpha1.ToolRegistryEntry{
		Name:          "tool_a",
		SignatureHash: "sha256:override",
	}
	h := ComputeHash(entry)
	if h != "sha256:override" {
		t.Fatalf("expected override hash, got %q", h)
	}
}

func TestComputeHash_DifferentEntriesHaveDifferentHashes(t *testing.T) {
	a := v1alpha1.ToolRegistryEntry{Name: "tool_a", Description: "version 1"}
	b := v1alpha1.ToolRegistryEntry{Name: "tool_a", Description: "version 2"}
	if ComputeHash(a) == ComputeHash(b) {
		t.Fatal("different descriptions should produce different hashes")
	}
}

func TestReconcile_NoDrift(t *testing.T) {
	reg := New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "tool_a", Description: "desc"})

	live := []v1alpha1.ToolRegistryEntry{
		{Name: "tool_a", Description: "desc"},
	}

	report := Reconcile(reg, live)
	if report.HasDrift() {
		t.Fatal("expected no drift when registry and live match")
	}
	if report.HasRugPull() {
		t.Fatal("expected no rug pull")
	}
}

func TestReconcile_DetectsAddedTool(t *testing.T) {
	reg := New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "tool_a"})

	live := []v1alpha1.ToolRegistryEntry{
		{Name: "tool_a"},
		{Name: "tool_b"},
	}

	report := Reconcile(reg, live)
	if !report.HasDrift() {
		t.Fatal("expected drift for added tool")
	}
	if len(report.Added) != 1 || report.Added[0].ToolName != "tool_b" {
		t.Fatalf("expected tool_b added, got %+v", report.Added)
	}
	if report.HasRugPull() {
		t.Fatal("added tool is not a rug pull")
	}
}

func TestReconcile_DetectsRemovedTool(t *testing.T) {
	reg := New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "tool_a"})
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "tool_b"})

	live := []v1alpha1.ToolRegistryEntry{
		{Name: "tool_a"},
	}

	report := Reconcile(reg, live)
	if !report.HasDrift() {
		t.Fatal("expected drift for removed tool")
	}
	if len(report.Removed) != 1 || report.Removed[0].ToolName != "tool_b" {
		t.Fatalf("expected tool_b removed, got %+v", report.Removed)
	}
}

func TestReconcile_DetectsRugPull(t *testing.T) {
	reg := New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "tool_a", Description: "safe version"})

	live := []v1alpha1.ToolRegistryEntry{
		{Name: "tool_a", Description: "MALICIOUS version"},
	}

	report := Reconcile(reg, live)
	if !report.HasRugPull() {
		t.Fatal("expected rug pull when tool description changes")
	}
	if len(report.Changed) != 1 {
		t.Fatalf("expected 1 changed tool, got %d", len(report.Changed))
	}
	if !report.Changed[0].IsRugPull() {
		t.Fatal("changed entry should be a rug pull")
	}
	if report.Changed[0].PreviousHash == "" || report.Changed[0].CurrentHash == "" {
		t.Fatal("rug pull entry should have both hashes")
	}
	if report.Changed[0].PreviousHash == report.Changed[0].CurrentHash {
		t.Fatal("hashes should differ for a rug pull")
	}
}

func TestReconcile_CombinedDrift(t *testing.T) {
	reg := New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "keep"})
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "changed", Description: "v1"})
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "removed"})

	live := []v1alpha1.ToolRegistryEntry{
		{Name: "keep"},
		{Name: "changed", Description: "v2"},
		{Name: "added"},
	}

	report := Reconcile(reg, live)
	if len(report.Added) != 1 {
		t.Errorf("expected 1 added, got %d", len(report.Added))
	}
	if len(report.Removed) != 1 {
		t.Errorf("expected 1 removed, got %d", len(report.Removed))
	}
	if len(report.Changed) != 1 {
		t.Errorf("expected 1 changed, got %d", len(report.Changed))
	}
}

func TestReconcile_EmptyLiveToolsReportsAllRemoved(t *testing.T) {
	reg := New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "tool_a"})
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "tool_b"})

	report := Reconcile(reg, nil)
	if len(report.Removed) != 2 {
		t.Fatalf("expected 2 removed, got %d", len(report.Removed))
	}
}

func TestReconcile_EmptyRegistryReportsAllAdded(t *testing.T) {
	reg := New()
	live := []v1alpha1.ToolRegistryEntry{
		{Name: "tool_a"},
		{Name: "tool_b"},
	}

	report := Reconcile(reg, live)
	if len(report.Added) != 2 {
		t.Fatalf("expected 2 added, got %d", len(report.Added))
	}
}

func TestDriftReport_RugPulls(t *testing.T) {
	report := DriftReport{
		Changed: []DriftEntry{
			{ToolName: "evil_tool", Type: DriftChanged},
		},
	}
	pulls := report.RugPulls()
	if len(pulls) != 1 || pulls[0].ToolName != "evil_tool" {
		t.Fatalf("expected evil_tool rug pull, got %+v", pulls)
	}
}

func TestLifecycleTracker_SnapshotAndHistory(t *testing.T) {
	reg := New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "tool_a", Description: "desc"})

	lt := NewLifecycleTracker(5)

	snap := lt.Snapshot(reg)
	if len(snap.Tools) != 1 {
		t.Fatalf("expected 1 tool in snapshot, got %d", len(snap.Tools))
	}
	if snap.Hashes["tool_a"] == "" {
		t.Fatal("hash should not be empty in snapshot")
	}

	hist := lt.History()
	if len(hist) != 1 {
		t.Fatalf("expected 1 snapshot in history, got %d", len(hist))
	}
}

func TestLifecycleTracker_MaxHistory(t *testing.T) {
	reg := New()
	reg.Register(v1alpha1.ToolRegistryEntry{Name: "t"})

	lt := NewLifecycleTracker(3)
	for i := 0; i < 5; i++ {
		lt.Snapshot(reg)
	}

	hist := lt.History()
	if len(hist) != 3 {
		t.Fatalf("expected history capped at 3, got %d", len(hist))
	}
}

func TestReconcile_SignatureHashOverride(t *testing.T) {
	reg := New()
	reg.Register(v1alpha1.ToolRegistryEntry{
		Name:          "tool_a",
		Description:   "desc",
		SignatureHash: "sha256:pinned",
	})

	live := []v1alpha1.ToolRegistryEntry{
		{Name: "tool_a", Description: "desc"},
	}

	report := Reconcile(reg, live)
	if !report.HasRugPull() {
		t.Fatal("pinned hash should differ from computed hash → rug pull")
	}
}

func TestReconcile_BothPinnedSameHash(t *testing.T) {
	reg := New()
	reg.Register(v1alpha1.ToolRegistryEntry{
		Name:          "tool_a",
		SignatureHash: "sha256:same",
	})

	live := []v1alpha1.ToolRegistryEntry{
		{Name: "tool_a", SignatureHash: "sha256:same"},
	}

	report := Reconcile(reg, live)
	if report.HasDrift() {
		t.Fatal("same pinned hashes should not cause drift")
	}
}

func TestReconcile_SortedOutput(t *testing.T) {
	reg := New()
	live := []v1alpha1.ToolRegistryEntry{
		{Name: "zulu"},
		{Name: "alpha"},
		{Name: "mike"},
	}

	report := Reconcile(reg, live)
	if len(report.Added) != 3 {
		t.Fatalf("expected 3 added, got %d", len(report.Added))
	}
	if report.Added[0].ToolName != "alpha" || report.Added[1].ToolName != "mike" || report.Added[2].ToolName != "zulu" {
		t.Fatalf("expected sorted output, got %v %v %v", report.Added[0].ToolName, report.Added[1].ToolName, report.Added[2].ToolName)
	}
}
