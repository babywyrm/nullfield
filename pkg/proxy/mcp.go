package proxy

import (
	"encoding/json"
	"fmt"
)

// JSON-RPC 2.0 envelope for MCP messages.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// MCP-specific method constants.
const (
	MethodToolsCall      = "tools/call"
	MethodToolsList      = "tools/list"
	MethodResourcesRead  = "resources/read"
	MethodResourcesList  = "resources/list"
	MethodPromptsGet     = "prompts/get"
	MethodPromptsList    = "prompts/list"
	MethodInitialize     = "initialize"
	MethodPing           = "ping"
)

// ToolsCallParams is the params object for tools/call.
type ToolsCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// ParseToolsCall extracts tool call parameters from a JSON-RPC request.
func ParseToolsCall(req *JSONRPCRequest) (*ToolsCallParams, error) {
	if req.Method != MethodToolsCall {
		return nil, fmt.Errorf("not a tools/call request: %s", req.Method)
	}
	var params ToolsCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, fmt.Errorf("invalid tools/call params: %w", err)
	}
	if params.Name == "" {
		return nil, fmt.Errorf("tools/call missing tool name")
	}
	return &params, nil
}

// NewErrorResponse builds a JSON-RPC error response.
func NewErrorResponse(id any, code int, message string) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
		},
	}
}

// Standard JSON-RPC error codes.
const (
	ErrCodeParse      = -32700
	ErrCodeInvalidReq = -32600
	ErrCodeMethodNF   = -32601
	ErrCodeInvalidPar = -32602
	ErrCodeInternal   = -32603
)

// Nullfield-specific error codes (application-defined range).
const (
	ErrCodePolicyDenied   = -32000
	ErrCodeIdentityFailed = -32001
	ErrCodeCircuitOpen    = -32002
	ErrCodeToolUnknown    = -32003
	ErrCodeRateLimited    = -32004
	ErrCodeHoldTimeout    = -32005
	ErrCodeScopeViolation  = -32006
	ErrCodeInspectionBlock = -32007
)
