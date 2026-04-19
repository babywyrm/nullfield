package registry

import (
	"os"
	"testing"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
)

func TestRegistry_RegisterAndCheck(t *testing.T) {
	r := New()
	r.Register(v1alpha1.ToolRegistryEntry{Name: "tool_a", Description: "test"})

	if !r.IsRegistered("tool_a") {
		t.Fatal("tool_a should be registered")
	}
	if r.IsRegistered("tool_b") {
		t.Fatal("tool_b should not be registered")
	}
}

func TestRegistry_Get(t *testing.T) {
	r := New()
	r.Register(v1alpha1.ToolRegistryEntry{Name: "tool_a", Description: "desc a"})

	entry, ok := r.Get("tool_a")
	if !ok {
		t.Fatal("tool_a should exist")
	}
	if entry.Description != "desc a" {
		t.Errorf("expected 'desc a', got %q", entry.Description)
	}

	_, ok = r.Get("nonexistent")
	if ok {
		t.Fatal("nonexistent should not exist")
	}
}

func TestRegistry_All(t *testing.T) {
	r := New()
	r.Register(v1alpha1.ToolRegistryEntry{Name: "a"})
	r.Register(v1alpha1.ToolRegistryEntry{Name: "b"})
	r.Register(v1alpha1.ToolRegistryEntry{Name: "c"})

	all := r.All()
	if len(all) != 3 {
		t.Errorf("expected 3 tools, got %d", len(all))
	}
}

func TestRegistry_LoadFromFile(t *testing.T) {
	yaml := `apiVersion: nullfield.io/v1alpha1
kind: ToolRegistry
metadata:
  name: test
tools:
  - name: tool_x
    description: Tool X
  - name: tool_y
    description: Tool Y
`
	f, err := os.CreateTemp("", "registry-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	r := New()
	if err := r.LoadFromFile(f.Name()); err != nil {
		t.Fatalf("load failed: %v", err)
	}

	if !r.IsRegistered("tool_x") {
		t.Fatal("tool_x should be registered")
	}
	if !r.IsRegistered("tool_y") {
		t.Fatal("tool_y should be registered")
	}
	if len(r.All()) != 2 {
		t.Errorf("expected 2 tools, got %d", len(r.All()))
	}
}

func TestRegistry_LoadReplacesPrevious(t *testing.T) {
	r := New()
	r.Register(v1alpha1.ToolRegistryEntry{Name: "old_tool"})

	yaml := `apiVersion: nullfield.io/v1alpha1
kind: ToolRegistry
metadata:
  name: test
tools:
  - name: new_tool
`
	f, _ := os.CreateTemp("", "registry-*.yaml")
	defer os.Remove(f.Name())
	f.WriteString(yaml)
	f.Close()

	r.LoadFromFile(f.Name())

	if r.IsRegistered("old_tool") {
		t.Fatal("old_tool should be replaced after reload")
	}
	if !r.IsRegistered("new_tool") {
		t.Fatal("new_tool should be registered after reload")
	}
}

func TestRegistry_EmptyIsNotRegistered(t *testing.T) {
	r := New()
	if r.IsRegistered("anything") {
		t.Fatal("empty registry should not match anything")
	}
}
