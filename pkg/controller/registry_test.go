package controller

import (
	"testing"
	"time"
)

func TestSidecarRegistry_Register(t *testing.T) {
	r := NewSidecarRegistry()

	r.Register(SidecarInfo{
		TargetName:      "target-a",
		TargetNamespace: "ns-1",
		PodName:         "pod-abc",
		Version:         "v0.1.0",
		ToolCount:       5,
		RuleCount:       3,
	})

	list := r.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 sidecar, got %d", len(list))
	}

	s := list[0]
	if s.PodName != "pod-abc" {
		t.Fatalf("expected PodName=pod-abc, got %s", s.PodName)
	}
	if s.TargetName != "target-a" {
		t.Fatalf("expected TargetName=target-a, got %s", s.TargetName)
	}
	if s.RegisteredAt.IsZero() {
		t.Fatal("RegisteredAt should be set")
	}
	if s.LastHeartbeat.IsZero() {
		t.Fatal("LastHeartbeat should be set")
	}
}

func TestSidecarRegistry_Sweep(t *testing.T) {
	r := NewSidecarRegistry()
	r.ttl = 30 * time.Millisecond

	r.Register(SidecarInfo{
		PodName:    "pod-stale",
		TargetName: "stale-target",
	})
	r.Register(SidecarInfo{
		PodName:    "pod-fresh",
		TargetName: "fresh-target",
	})

	time.Sleep(50 * time.Millisecond)

	r.Heartbeat("pod-fresh")

	removed := r.Sweep()
	if removed != 1 {
		t.Fatalf("expected 1 removed, got %d", removed)
	}

	list := r.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 remaining sidecar, got %d", len(list))
	}
	if list[0].PodName != "pod-fresh" {
		t.Fatalf("expected pod-fresh to survive, got %s", list[0].PodName)
	}
}
