package scope

import (
	"strings"
	"testing"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
)

func TestModifyRequest_StripArguments(t *testing.T) {
	args := map[string]any{"name": "test", "password": "secret123", "mode": "read"}
	cfg := &v1alpha1.ScopeRequestConfig{
		StripArguments: []string{"password"},
	}

	result, mods := ModifyRequest(args, cfg)

	if _, exists := result["password"]; exists {
		t.Fatal("password should be stripped")
	}
	if result["name"] != "test" {
		t.Error("name should be preserved")
	}
	if len(mods.StrippedArgs) != 1 || mods.StrippedArgs[0] != "password" {
		t.Errorf("expected stripped=[password], got %v", mods.StrippedArgs)
	}
}

func TestModifyRequest_InjectArguments(t *testing.T) {
	args := map[string]any{"name": "test"}
	cfg := &v1alpha1.ScopeRequestConfig{
		InjectArguments: map[string]any{"read_only": "true", "scope": "limited"},
	}

	result, mods := ModifyRequest(args, cfg)

	if result["read_only"] != "true" {
		t.Error("read_only should be injected")
	}
	if result["scope"] != "limited" {
		t.Error("scope should be injected")
	}
	if len(mods.InjectedArgs) != 2 {
		t.Errorf("expected 2 injected args, got %d", len(mods.InjectedArgs))
	}
}

func TestModifyRequest_StripAndInject(t *testing.T) {
	args := map[string]any{"target": "prod", "admin_key": "abc123"}
	cfg := &v1alpha1.ScopeRequestConfig{
		StripArguments:  []string{"admin_key"},
		InjectArguments: map[string]any{"read_only": "true"},
	}

	result, mods := ModifyRequest(args, cfg)

	if _, exists := result["admin_key"]; exists {
		t.Fatal("admin_key should be stripped")
	}
	if result["read_only"] != "true" {
		t.Error("read_only should be injected")
	}
	if result["target"] != "prod" {
		t.Error("target should be preserved")
	}
	if len(mods.StrippedArgs) != 1 || len(mods.InjectedArgs) != 1 {
		t.Errorf("expected 1 stripped + 1 injected, got %v + %v", mods.StrippedArgs, mods.InjectedArgs)
	}
}

func TestModifyRequest_NilConfig(t *testing.T) {
	args := map[string]any{"name": "test"}
	result, mods := ModifyRequest(args, nil)

	if result["name"] != "test" {
		t.Error("nil config should return args unchanged")
	}
	if len(mods.StrippedArgs) != 0 || len(mods.InjectedArgs) != 0 {
		t.Error("nil config should have no modifications")
	}
}

func TestModifyRequest_OriginalUnchanged(t *testing.T) {
	args := map[string]any{"name": "test", "secret": "val"}
	cfg := &v1alpha1.ScopeRequestConfig{StripArguments: []string{"secret"}}

	ModifyRequest(args, cfg)

	if _, exists := args["secret"]; !exists {
		t.Fatal("original args should not be mutated")
	}
}

func TestModifyResponse_RedactPatterns(t *testing.T) {
	body := []byte(`{"result":{"text":"password: abc123, api_key: xyz789, name: safe"}}`)
	cfg := &v1alpha1.ScopeResponseConfig{
		RedactPatterns: []string{"password", "api_key"},
	}

	result, count := ModifyResponse(body, cfg)

	if count == 0 {
		t.Fatal("expected redactions")
	}
	text := string(result)
	if strings.Contains(text, "abc123") {
		t.Error("password value should be redacted")
	}
	if strings.Contains(text, "xyz789") {
		t.Error("api_key value should be redacted")
	}
	if !strings.Contains(text, "safe") {
		t.Error("non-matching values should be preserved")
	}
}

func TestModifyResponse_CustomReplacement(t *testing.T) {
	body := []byte(`{"text":"secret: hunter2"}`)
	cfg := &v1alpha1.ScopeResponseConfig{
		RedactPatterns:    []string{"secret"},
		RedactReplacement: "***REMOVED***",
	}

	result, _ := ModifyResponse(body, cfg)
	if !strings.Contains(string(result), "***REMOVED***") {
		t.Error("custom replacement should be used")
	}
}

func TestModifyResponse_NilConfig(t *testing.T) {
	body := []byte(`{"text":"secret: value"}`)
	result, count := ModifyResponse(body, nil)

	if string(result) != string(body) {
		t.Error("nil config should return body unchanged")
	}
	if count != 0 {
		t.Error("nil config should have zero redactions")
	}
}

func TestRebuildRequestBody(t *testing.T) {
	original := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test","arguments":{"key":"old"}}}`)
	newArgs := map[string]any{"key": "new", "extra": "injected"}

	result, err := RebuildRequestBody(original, newArgs)
	if err != nil {
		t.Fatalf("rebuild failed: %v", err)
	}

	text := string(result)
	if !strings.Contains(text, `"new"`) {
		t.Error("new argument value should be present")
	}
	if !strings.Contains(text, `"injected"`) {
		t.Error("injected argument should be present")
	}
	if strings.Contains(text, `"old"`) {
		t.Error("old argument value should be replaced")
	}
}
