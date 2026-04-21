package proxy

import (
	"testing"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"github.com/babywyrm/nullfield/pkg/policy"
	"github.com/babywyrm/nullfield/pkg/registry"
)

func makeTestRoute(name, prefix string, tools []string) *Route {
	reg := registry.New()
	for _, t := range tools {
		reg.Register(v1alpha1.ToolRegistryEntry{Name: t})
	}
	return &Route{
		Name:       name,
		ToolPrefix: prefix,
		ToolNames:  tools,
		Engine:     policy.NewRuleEngine(nil),
		Registry:   reg,
	}
}

func TestRouter_ExactMatch(t *testing.T) {
	r := NewRouter([]*Route{
		makeTestRoute("github", "github.", []string{"github.create_pr", "github.list_repos"}),
		makeTestRoute("pagerduty", "pagerduty.", []string{"pagerduty.resolve"}),
	})

	route := r.Resolve("github.create_pr")
	if route == nil {
		t.Fatal("expected route for github.create_pr")
	}
	if route.Name != "github" {
		t.Fatalf("expected route 'github', got %q", route.Name)
	}

	route = r.Resolve("pagerduty.resolve")
	if route == nil {
		t.Fatal("expected route for pagerduty.resolve")
	}
	if route.Name != "pagerduty" {
		t.Fatalf("expected route 'pagerduty', got %q", route.Name)
	}
}

func TestRouter_PrefixMatch(t *testing.T) {
	r := NewRouter([]*Route{
		makeTestRoute("github", "github.", nil),
		makeTestRoute("jira", "jira.", nil),
	})

	route := r.Resolve("github.anything_new")
	if route == nil {
		t.Fatal("expected prefix match for github.anything_new")
	}
	if route.Name != "github" {
		t.Fatalf("expected route 'github', got %q", route.Name)
	}

	route = r.Resolve("jira.get_issue")
	if route == nil {
		t.Fatal("expected prefix match for jira.get_issue")
	}
	if route.Name != "jira" {
		t.Fatalf("expected route 'jira', got %q", route.Name)
	}
}

func TestRouter_ExactOverPrefix(t *testing.T) {
	r := NewRouter([]*Route{
		makeTestRoute("catchall", "github.", nil),
		makeTestRoute("special", "", []string{"github.deploy"}),
	})

	route := r.Resolve("github.deploy")
	if route == nil {
		t.Fatal("expected route for github.deploy")
	}
	if route.Name != "special" {
		t.Fatalf("exact match should win: expected 'special', got %q", route.Name)
	}

	route = r.Resolve("github.list_repos")
	if route == nil {
		t.Fatal("expected prefix match for github.list_repos")
	}
	if route.Name != "catchall" {
		t.Fatalf("expected 'catchall', got %q", route.Name)
	}
}

func TestRouter_NoMatch(t *testing.T) {
	r := NewRouter([]*Route{
		makeTestRoute("github", "github.", nil),
	})

	route := r.Resolve("slack.post_message")
	if route != nil {
		t.Fatalf("expected nil for unmatched tool, got route %q", route.Name)
	}
}

func TestRouter_AllRegisteredTools(t *testing.T) {
	r := NewRouter([]*Route{
		makeTestRoute("a", "a.", []string{"a.one", "a.two"}),
		makeTestRoute("b", "b.", []string{"b.one"}),
	})

	tools := r.AllRegisteredTools()
	if len(tools) != 3 {
		t.Fatalf("expected 3 tools, got %d: %v", len(tools), tools)
	}
}
