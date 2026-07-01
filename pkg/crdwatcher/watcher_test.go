package crdwatcher

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func testWatcher(handler http.Handler) *Watcher {
	ts := httptest.NewTLSServer(handler)
	return &Watcher{
		apiBase:   ts.URL,
		token:     "test-token",
		namespace: "default",
		client:    ts.Client(),
		logger:    slog.New(slog.NewJSONHandler(io.Discard, nil)),
	}
}

func TestSyncPolicies_CreateConfigMap(t *testing.T) {
	var mu sync.Mutex
	var created map[string]any

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apis/nullfield.io/v1alpha1/namespaces/default/nullfieldpolicies" {
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{
						"metadata": map[string]any{"name": "test-policy", "namespace": "default"},
						"spec": map[string]any{
							"rules": []map[string]any{
								{"action": "DENY", "toolNames": []string{"*"}},
							},
						},
					},
				},
			})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/default/configmaps/nullfield-policy-test-policy" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			json.Unmarshal(body, &created)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			w.Write(body)
			return
		}
		// Default handler for registries
		json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
	})

	watcher := testWatcher(handler)
	watcher.syncPolicies(context.Background())

	mu.Lock()
	defer mu.Unlock()

	if created == nil {
		t.Fatal("expected ConfigMap to be created")
	}
	meta := created["metadata"].(map[string]any)
	if meta["name"] != "nullfield-policy-test-policy" {
		t.Fatalf("expected CM name 'nullfield-policy-test-policy', got %v", meta["name"])
	}
	data := created["data"].(map[string]any)
	if _, ok := data["policy.yaml"]; !ok {
		t.Fatal("expected 'policy.yaml' key in ConfigMap data")
	}
	labels := meta["labels"].(map[string]any)
	if labels["nullfield.io/managed-by"] != "crd-controller" {
		t.Fatal("expected managed-by label")
	}
}

func TestSyncRegistries_CreateConfigMap(t *testing.T) {
	var mu sync.Mutex
	var created map[string]any

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apis/nullfield.io/v1alpha1/namespaces/default/toolregistries" {
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{
						"metadata": map[string]any{"name": "test-registry", "namespace": "default"},
						"tools": []map[string]any{
							{"name": "test.tool", "description": "A test tool"},
						},
					},
				},
			})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/default/configmaps/nullfield-registry-test-registry" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			json.Unmarshal(body, &created)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			w.Write(body)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
	})

	watcher := testWatcher(handler)
	watcher.syncRegistries(context.Background())

	mu.Lock()
	defer mu.Unlock()

	if created == nil {
		t.Fatal("expected ConfigMap to be created")
	}
	meta := created["metadata"].(map[string]any)
	if meta["name"] != "nullfield-registry-test-registry" {
		t.Fatalf("expected CM name 'nullfield-registry-test-registry', got %v", meta["name"])
	}
	data := created["data"].(map[string]any)
	if _, ok := data["tools.yaml"]; !ok {
		t.Fatal("expected 'tools.yaml' key in ConfigMap data")
	}
}

func TestSyncAgenticFlows_CreateCompiledConfigMap(t *testing.T) {
	var mu sync.Mutex
	var created map[string]any

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apis/nullfield.io/v1alpha1/namespaces/default/agenticflows" {
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{
						"apiVersion": "nullfield.io/v1alpha1",
						"kind":       "AgenticFlow",
						"metadata": map[string]any{
							"name":      "astra-jira",
							"namespace": "default",
						},
						"spec": map[string]any{
							"tools": []map[string]any{
								{"name": "mcp-atlassian.read_issue", "action": "ALLOW"},
							},
						},
					},
				},
			})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/default/configmaps/nullfield-flow-astra-jira" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			json.Unmarshal(body, &created)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			w.Write(body)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
	})

	watcher := testWatcher(handler)
	watcher.syncAgenticFlows(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if created == nil {
		t.Fatal("expected ConfigMap to be created")
	}
	meta := created["metadata"].(map[string]any)
	if meta["name"] != "nullfield-flow-astra-jira" {
		t.Fatalf("expected CM name nullfield-flow-astra-jira, got %v", meta["name"])
	}
	labels := meta["labels"].(map[string]any)
	if labels["nullfield.io/source-kind"] != "AgenticFlow" {
		t.Fatalf("source-kind label = %v", labels["nullfield.io/source-kind"])
	}
	data := created["data"].(map[string]any)
	for _, key := range []string{"compiled.yaml", "policy.yaml", "tools.yaml"} {
		if _, ok := data[key]; !ok {
			t.Fatalf("expected %q key in ConfigMap data", key)
		}
	}
	if !strings.Contains(data["policy.yaml"].(string), "kind: NullfieldPolicy") {
		t.Fatalf("policy.yaml did not contain compiled policy:\n%s", data["policy.yaml"])
	}
	if !strings.Contains(data["tools.yaml"].(string), "kind: ToolRegistry") {
		t.Fatalf("tools.yaml did not contain compiled registry:\n%s", data["tools.yaml"])
	}
}

func TestSyncPolicies_UpdateExistingConfigMap(t *testing.T) {
	var mu sync.Mutex
	var updated bool

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apis/nullfield.io/v1alpha1/namespaces/default/nullfieldpolicies" {
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{
						"metadata": map[string]any{"name": "existing", "namespace": "default"},
						"spec": map[string]any{
							"rules": []map[string]any{{"action": "ALLOW", "toolNames": []string{"test"}}},
						},
					},
				},
			})
			return
		}
		if r.Method == http.MethodGet && r.URL.Path == "/api/v1/namespaces/default/configmaps/nullfield-policy-existing" {
			json.NewEncoder(w).Encode(map[string]any{
				"metadata": map[string]any{"name": "nullfield-policy-existing"},
				"data":     map[string]string{"policy.yaml": "old"},
			})
			return
		}
		if r.Method == http.MethodPut {
			mu.Lock()
			updated = true
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
	})

	watcher := testWatcher(handler)
	watcher.syncPolicies(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if !updated {
		t.Fatal("expected ConfigMap to be updated via PUT")
	}
}

func TestSyncPolicies_EmptyList(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
	})

	watcher := testWatcher(handler)
	watcher.syncPolicies(context.Background())
	// Should not panic or error
}

func TestSyncPolicies_APIError(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	})

	watcher := testWatcher(handler)
	watcher.syncPolicies(context.Background())
	// Should log warning but not panic
}

// --- Sidecar bridge tests (2026-04-27) -------------------------------------
//
// These verify the active-policy bridge: pick a NullfieldPolicy by label and
// write it to a target ConfigMap key the sidecar mounts.

func TestSyncActivePolicy_PicksLabeledAndWrites(t *testing.T) {
	var mu sync.Mutex
	var posted map[string]any

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apis/nullfield.io/v1alpha1/namespaces/default/nullfieldpolicies" {
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{
						// Wrong label — should be ignored.
						"metadata": map[string]any{
							"name":      "decoy",
							"namespace": "default",
							"labels":    map[string]any{"nullfield.io/active-for": "other-sidecar"},
						},
						"spec": map[string]any{"rules": []map[string]any{{"action": "ALLOW"}}},
					},
					{
						// Match.
						"metadata": map[string]any{
							"name":      "lane-4-chain-starter",
							"namespace": "default",
							"labels":    map[string]any{"nullfield.io/active-for": "brain-gateway"},
						},
						"spec": map[string]any{
							"rules": []map[string]any{
								{"action": "DENY", "mcpMethod": "tools/call",
									"delegation": map[string]any{"maxDepth": 2}},
							},
						},
					},
				},
			})
			return
		}
		if r.Method == http.MethodGet &&
			r.URL.Path == "/api/v1/namespaces/default/configmaps/nullfield-active-policy" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodPost &&
			r.URL.Path == "/api/v1/namespaces/default/configmaps" {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			json.Unmarshal(body, &posted)
			mu.Unlock()
			w.WriteHeader(http.StatusCreated)
			w.Write(body)
			return
		}
		// Registries + per-policy sync paths: return empty.
		json.NewEncoder(w).Encode(map[string]any{"items": []any{}})
	})

	w := testWatcher(handler)
	w.activeTargetCM = "nullfield-active-policy"
	w.activeTargetCMKey = "policy.yaml"
	w.activeTargetLabel = "brain-gateway"

	w.syncActivePolicy(context.Background())

	mu.Lock()
	defer mu.Unlock()
	if posted == nil {
		t.Fatal("expected ConfigMap POST, got none")
	}
	meta, _ := posted["metadata"].(map[string]any)
	if name, _ := meta["name"].(string); name != "nullfield-active-policy" {
		t.Errorf("wrong target ConfigMap name: %v", name)
	}
	labels, _ := meta["labels"].(map[string]any)
	if src, _ := labels["nullfield.io/active-source"].(string); src != "lane-4-chain-starter" {
		t.Errorf("active-source label should name the picked policy, got %v", src)
	}
	data, _ := posted["data"].(map[string]any)
	yamlBlob, _ := data["policy.yaml"].(string)
	if yamlBlob == "" {
		t.Fatal("policy.yaml key must be populated")
	}
	if !contains(yamlBlob, "lane-4-chain-starter") {
		t.Errorf("policy.yaml should embed the picked policy name; got: %s", yamlBlob[:min(120, len(yamlBlob))])
	}
	if !contains(yamlBlob, "maxDepth") {
		t.Error("policy.yaml should round-trip the new delegation.maxDepth primitive")
	}
}

func TestSyncActivePolicy_NoOpWhenDisabled(t *testing.T) {
	called := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	w := testWatcher(handler)
	// Defaults: activeTargetCM and activeTargetLabel both empty.
	w.syncActivePolicy(context.Background())
	if called {
		t.Error("syncActivePolicy must not call the API when the bridge is disabled")
	}
}

func TestSyncActivePolicy_NoMatchDoesNotClobber(t *testing.T) {
	var posted bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/apis/nullfield.io/v1alpha1/namespaces/default/nullfieldpolicies" {
			json.NewEncoder(w).Encode(map[string]any{
				"items": []map[string]any{
					{
						"metadata": map[string]any{
							"name":   "wrong-label",
							"labels": map[string]any{"nullfield.io/active-for": "other"},
						},
						"spec": map[string]any{"rules": []any{}},
					},
				},
			})
			return
		}
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			posted = true
		}
		w.WriteHeader(http.StatusOK)
	})
	w := testWatcher(handler)
	w.activeTargetCM = "nullfield-active-policy"
	w.activeTargetCMKey = "policy.yaml"
	w.activeTargetLabel = "brain-gateway"

	w.syncActivePolicy(context.Background())
	if posted {
		t.Error("must not write the target ConfigMap when no policy matches the label")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(s) > 0 && stringContains(s, sub)))
}

func stringContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
