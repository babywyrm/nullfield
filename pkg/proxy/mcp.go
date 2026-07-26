package proxy

import "github.com/babywyrm/nullfield/pkg/mcp"

// The MCP envelope moved to pkg/mcp so the ext_authz decision service can parse
// a tools/call without importing this package. These aliases keep the entire
// prior surface of this file intact, so no call site or test changes.

type (
	JSONRPCRequest  = mcp.JSONRPCRequest
	JSONRPCResponse = mcp.JSONRPCResponse
	JSONRPCError    = mcp.JSONRPCError
	ToolsCallParams = mcp.ToolsCallParams
)

// MCP-specific method constants.
const (
	MethodToolsCall     = mcp.MethodToolsCall
	MethodToolsList     = mcp.MethodToolsList
	MethodResourcesRead = mcp.MethodResourcesRead
	MethodResourcesList = mcp.MethodResourcesList
	MethodPromptsGet    = mcp.MethodPromptsGet
	MethodPromptsList   = mcp.MethodPromptsList
	MethodInitialize    = mcp.MethodInitialize
	MethodPing          = mcp.MethodPing
)

// Standard JSON-RPC error codes.
const (
	ErrCodeParse      = mcp.ErrCodeParse
	ErrCodeInvalidReq = mcp.ErrCodeInvalidReq
	ErrCodeMethodNF   = mcp.ErrCodeMethodNF
	ErrCodeInvalidPar = mcp.ErrCodeInvalidPar
	ErrCodeInternal   = mcp.ErrCodeInternal
)

// Nullfield-specific error codes (application-defined range).
const (
	ErrCodePolicyDenied    = mcp.ErrCodePolicyDenied
	ErrCodeIdentityFailed  = mcp.ErrCodeIdentityFailed
	ErrCodeCircuitOpen     = mcp.ErrCodeCircuitOpen
	ErrCodeToolUnknown     = mcp.ErrCodeToolUnknown
	ErrCodeRateLimited     = mcp.ErrCodeRateLimited
	ErrCodeHoldTimeout     = mcp.ErrCodeHoldTimeout
	ErrCodeScopeViolation  = mcp.ErrCodeScopeViolation
	ErrCodeInspectionBlock = mcp.ErrCodeInspectionBlock
)

// ParseToolsCall extracts tool call parameters from a JSON-RPC request.
func ParseToolsCall(req *JSONRPCRequest) (*ToolsCallParams, error) {
	return mcp.ParseToolsCall(req)
}

// NewErrorResponse builds a JSON-RPC error response.
func NewErrorResponse(id any, code int, message string) *JSONRPCResponse {
	return mcp.NewErrorResponse(id, code, message)
}
