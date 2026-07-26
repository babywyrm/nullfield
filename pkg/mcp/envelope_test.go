package mcp

import (
	"encoding/json"
	"testing"
)

func TestParseToolsCallExtractsNameAndArguments(t *testing.T) {
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  MethodToolsCall,
		Params:  json.RawMessage(`{"name":"github.create_pr","arguments":{"repo":"x/y"}}`),
	}

	params, err := ParseToolsCall(req)
	if err != nil {
		t.Fatalf("ParseToolsCall: %v", err)
	}
	if params.Name != "github.create_pr" {
		t.Errorf("name = %q, want github.create_pr", params.Name)
	}
	if params.Arguments["repo"] != "x/y" {
		t.Errorf("arguments[repo] = %v, want x/y", params.Arguments["repo"])
	}
}

func TestParseToolsCallRejectsAnotherMethod(t *testing.T) {
	req := &JSONRPCRequest{Method: MethodToolsList}
	if _, err := ParseToolsCall(req); err == nil {
		t.Fatal("expected an error for a non-tools/call method")
	}
}

func TestParseToolsCallRequiresAToolName(t *testing.T) {
	req := &JSONRPCRequest{
		Method: MethodToolsCall,
		Params: json.RawMessage(`{"arguments":{}}`),
	}
	if _, err := ParseToolsCall(req); err == nil {
		t.Fatal("expected an error when the tool name is absent")
	}
}

func TestParseToolsCallRejectsUnparseableParams(t *testing.T) {
	req := &JSONRPCRequest{
		Method: MethodToolsCall,
		Params: json.RawMessage(`{"name":`),
	}
	if _, err := ParseToolsCall(req); err == nil {
		t.Fatal("expected an error for truncated params")
	}
}

func TestNewErrorResponsePreservesTheRequestID(t *testing.T) {
	// The caller correlates the error with its request by id; dropping it turns
	// a denial into an unattributable failure.
	resp := NewErrorResponse(7, ErrCodePolicyDenied, "denied")
	if resp.ID != 7 {
		t.Errorf("id = %v, want 7", resp.ID)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("jsonrpc = %q, want 2.0", resp.JSONRPC)
	}
	if resp.Error == nil || resp.Error.Code != ErrCodePolicyDenied {
		t.Fatalf("error = %+v, want code %d", resp.Error, ErrCodePolicyDenied)
	}
}
