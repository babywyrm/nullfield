package crdwatcher

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
