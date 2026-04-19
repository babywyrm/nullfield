package proxy

import (
	"encoding/json"
	"testing"
)

func TestParseToolsCall_Valid(t *testing.T) {
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  json.RawMessage(`{"name":"test_tool","arguments":{"key":"value"}}`),
	}

	tc, err := ParseToolsCall(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tc.Name != "test_tool" {
		t.Errorf("expected test_tool, got %s", tc.Name)
	}
	if tc.Arguments["key"] != "value" {
		t.Errorf("expected argument key=value, got %v", tc.Arguments["key"])
	}
}

func TestParseToolsCall_WrongMethod(t *testing.T) {
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
		Params:  json.RawMessage(`{}`),
	}

	_, err := ParseToolsCall(req)
	if err == nil {
		t.Fatal("expected error for non-tools/call method")
	}
}

func TestParseToolsCall_MissingName(t *testing.T) {
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  json.RawMessage(`{"arguments":{}}`),
	}

	_, err := ParseToolsCall(req)
	if err == nil {
		t.Fatal("expected error for missing tool name")
	}
}

func TestParseToolsCall_InvalidJSON(t *testing.T) {
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params:  json.RawMessage(`not json`),
	}

	_, err := ParseToolsCall(req)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNewErrorResponse(t *testing.T) {
	resp := NewErrorResponse(42, ErrCodePolicyDenied, "test denial")

	if resp.JSONRPC != "2.0" {
		t.Errorf("expected 2.0, got %s", resp.JSONRPC)
	}
	if resp.ID != 42 {
		t.Errorf("expected ID 42, got %v", resp.ID)
	}
	if resp.Error == nil {
		t.Fatal("expected error in response")
	}
	if resp.Error.Code != ErrCodePolicyDenied {
		t.Errorf("expected code %d, got %d", ErrCodePolicyDenied, resp.Error.Code)
	}
	if resp.Error.Message != "test denial" {
		t.Errorf("expected 'test denial', got %q", resp.Error.Message)
	}
}

func TestErrorCodes(t *testing.T) {
	codes := map[int]string{
		ErrCodePolicyDenied:   "policy denied",
		ErrCodeIdentityFailed: "identity failed",
		ErrCodeCircuitOpen:    "circuit open",
		ErrCodeToolUnknown:    "tool unknown",
		ErrCodeRateLimited:    "rate limited",
		ErrCodeHoldTimeout:    "hold timeout",
		ErrCodeScopeViolation: "scope violation",
	}

	for code, name := range codes {
		if code >= -31999 || code <= -32100 {
			t.Errorf("error code %d (%s) outside application-defined range", code, name)
		}
	}
}
