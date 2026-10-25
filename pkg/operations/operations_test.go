package operations

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const github = `
target: api.github.com
operations:
  - name: repos.get
    method: GET
    path: /repos/{owner}/{repo}
  - name: repos.delete
    method: DELETE
    path: /repos/{owner}/{repo}
  - name: issues.create
    method: POST
    path: /repos/{owner}/{repo}/issues
`

func load(t *testing.T, files map[string]string) (*Map, error) {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return LoadDir(dir)
}

func mustLoad(t *testing.T) *Map {
	t.Helper()
	m, err := load(t, map[string]string{"github.yaml": github})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestAnOperationIsNamedWithItsParameters(t *testing.T) {
	m := mustLoad(t)
	for _, tc := range []struct {
		target, op, name string
		params           map[string]string
	}{
		{"api.github.com", "DELETE /repos/acme/widgets", "repos.delete", map[string]string{"owner": "acme", "repo": "widgets"}},
		{"api.github.com", "GET /repos/acme/widgets", "repos.get", map[string]string{"owner": "acme", "repo": "widgets"}},
		{"api.github.com", "POST /repos/acme/widgets/issues?x=1", "issues.create", map[string]string{"owner": "acme", "repo": "widgets"}},
		// The host the mesh reports may carry a port, case or a trailing dot.
		{"API.GitHub.com:443", "GET /repos/acme/widgets", "repos.get", map[string]string{"owner": "acme", "repo": "widgets"}},
		{"api.github.com.", "GET /repos/acme/widgets", "repos.get", map[string]string{"owner": "acme", "repo": "widgets"}},
		// The upstream decodes the path, so the map matches what it will act on.
		{"api.github.com", "DELETE /rep%6Fs/acme/my%20repo", "repos.delete", map[string]string{"owner": "acme", "repo": "my repo"}},
	} {
		name, params, err := m.Resolve(tc.target, tc.op)
		if err != nil || name != tc.name || !reflect.DeepEqual(params, tc.params) {
			t.Errorf("Resolve(%q, %q) = %q, %v, %v; want %q, %v", tc.target, tc.op, name, params, err, tc.name, tc.params)
		}
	}
}

func TestACallTheMapDoesNotNameHasNoName(t *testing.T) {
	m := mustLoad(t)
	for _, tc := range [][2]string{
		{"api.github.com", "PATCH /repos/acme/widgets"},
		{"api.github.com", "GET /repos/acme"},
		{"api.github.com", "GET /"},
		{"slack.com", "DELETE /repos/acme/widgets"},
	} {
		name, params, err := m.Resolve(tc[0], tc[1])
		if err != nil || name != "" || params != nil {
			t.Errorf("Resolve(%q, %q) = %q, %v, %v; want unnamed", tc[0], tc[1], name, params, err)
		}
	}
}

// A path the map cannot read one way only is refused rather than left unnamed:
// a DENY on repos.delete must not be dodged by a spelling the upstream still
// routes to the same repository.
func TestAnAmbiguousPathOnAMappedTargetIsRefused(t *testing.T) {
	m := mustLoad(t)
	for _, op := range []string{
		"DELETE /repos/acme/widgets/",
		"DELETE /repos//acme/widgets",
		"DELETE /repos/acme/./widgets",
		"DELETE /repos/acme/x/../widgets",
		"DELETE /repos/acme%2Fwidgets/x",
		"DELETE /repos/acme/%2E%2E",
		"DELETE /repos/acme/%zz",
		"DELETE repos/acme/widgets",
		"DELETE",
	} {
		if _, _, err := m.Resolve("api.github.com", op); !errors.Is(err, ErrAmbiguous) {
			t.Errorf("Resolve(%q) err = %v, want ErrAmbiguous", op, err)
		}
	}
	// The same spelling on a target with no map is not this package's to judge.
	if _, _, err := m.Resolve("slack.com", "DELETE /a//b"); err != nil {
		t.Errorf("unmapped target: %v", err)
	}
}

func TestABadMapRefusesToLoad(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"empty directory":    {},
		"unknown field":      {"a.yaml": "target: x\nopertions: []\n"},
		"no target":          {"a.yaml": "operations: [{name: a, method: GET, path: /a}]\n"},
		"no operations":      {"a.yaml": "target: x\n"},
		"no name":            {"a.yaml": "target: x\noperations: [{method: GET, path: /a}]\n"},
		"no method":          {"a.yaml": "target: x\noperations: [{name: a, path: /a}]\n"},
		"relative path":      {"a.yaml": "target: x\noperations: [{name: a, method: GET, path: a}]\n"},
		"empty segment":      {"a.yaml": "target: x\noperations: [{name: a, method: GET, path: /a//b}]\n"},
		"empty parameter":    {"a.yaml": one("/a/{}")},
		"repeat parameter":   {"a.yaml": one("/{a}/{a}")},
		"target twice":       {"a.yaml": github, "b.yml": github},
		"target with a port": {"a.yaml": "target: x:443\noperations: [{name: a, method: GET, path: /a}]\n"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := load(t, files); err == nil {
				t.Fatal("loaded, want an error")
			}
		})
	}
}

func TestTheFirstMatchingOperationWins(t *testing.T) {
	m, err := load(t, map[string]string{"a.yaml": `
target: api.github.com
operations:
  - {name: hooks.list, method: GET, path: "/repos/{owner}/{repo}/hooks"}
  - {name: repos.sub, method: GET, path: "/repos/{owner}/{repo}/{sub}"}
`, "README.md": "not a map"})
	if err != nil {
		t.Fatal(err)
	}
	if name, _, _ := m.Resolve("api.github.com", "GET /repos/a/b/hooks"); name != "hooks.list" {
		t.Fatalf("got %q, want hooks.list", name)
	}
	if name, _, _ := m.Resolve("api.github.com", "GET /repos/a/b/pulls"); !strings.HasPrefix(name, "repos.sub") {
		t.Fatalf("got %q, want repos.sub", name)
	}
}

func one(path string) string {
	return "target: x\noperations:\n  - name: a\n    method: GET\n    path: \"" + path + "\"\n"
}

func TestAValidSingleOperationLoads(t *testing.T) {
	if _, err := load(t, map[string]string{"a.yaml": one("/a/{b}")}); err != nil {
		t.Fatal(err)
	}
}

func TestTheShippedExamplesLoad(t *testing.T) {
	m, err := LoadDir("../../examples/operations")
	if err != nil {
		t.Fatal(err)
	}
	if name, _, _ := m.Resolve("api.github.com", "DELETE /repos/acme/widgets"); name != "repos.delete" {
		t.Fatalf("got %q, want repos.delete", name)
	}
}
