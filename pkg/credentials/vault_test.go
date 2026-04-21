package credentials

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVaultProvider_TokenAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/v1/secret/data/db-password" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"data": map[string]any{
					"value": "super-secret-db-pass",
				},
			},
		})
	}))
	defer server.Close()

	vp, err := NewVaultProvider(VaultConfig{
		Addr:       server.URL,
		Token:      "test-token",
		AuthMethod: "token",
	})
	if err != nil {
		t.Fatalf("provider init failed: %v", err)
	}

	val, err := vp.Fetch(context.Background(), "secret/data/db-password")
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}
	if val != "super-secret-db-pass" {
		t.Fatalf("expected 'super-secret-db-pass', got %q", val)
	}
}

func TestVaultProvider_KVv1(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"value": "kv1-secret",
			},
		})
	}))
	defer server.Close()

	vp, err := NewVaultProvider(VaultConfig{
		Addr:       server.URL,
		Token:      "t",
		AuthMethod: "token",
	})
	if err != nil {
		t.Fatalf("provider init failed: %v", err)
	}

	val, err := vp.Fetch(context.Background(), "secret/mykey")
	if err != nil {
		t.Fatalf("fetch failed: %v", err)
	}
	if val != "kv1-secret" {
		t.Fatalf("expected 'kv1-secret', got %q", val)
	}
}

func TestVaultProvider_404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer server.Close()

	vp, err := NewVaultProvider(VaultConfig{
		Addr:       server.URL,
		Token:      "t",
		AuthMethod: "token",
	})
	if err != nil {
		t.Fatalf("provider init failed: %v", err)
	}

	_, err = vp.Fetch(context.Background(), "secret/missing")
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestVaultProvider_EmptyAddr(t *testing.T) {
	_, err := NewVaultProvider(VaultConfig{Addr: ""})
	if err == nil {
		t.Fatal("expected error for empty address")
	}
}
