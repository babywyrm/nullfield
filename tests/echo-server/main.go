package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

type jsonrpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonrpcResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id,omitempty"`
	Result  any    `json:"result,omitempty"`
}

type toolResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolsListResult struct {
	Tools []toolDef `json:"tools"`
}

type toolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		var req jsonrpcRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "not json-rpc", http.StatusBadRequest)
			return
		}

		logger.Info("received", "method", req.Method, "id", req.ID)

		var result any

		switch req.Method {
		case "initialize":
			result = map[string]any{
				"protocolVersion": "2025-03-26",
				"serverInfo": map[string]string{
					"name":    "echo-mcp-server",
					"version": "0.1.0",
				},
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
			}

		case "tools/list":
			result = toolsListResult{
				Tools: []toolDef{
					{
						Name:        "echo",
						Description: "Echoes back the input",
						InputSchema: map[string]any{
							"type": "object",
							"properties": map[string]any{
								"message": map[string]string{"type": "string"},
							},
						},
					},
					{
						Name:        "github_create_pr",
						Description: "Simulated: create a GitHub PR",
						InputSchema: map[string]any{
							"type": "object",
							"properties": map[string]any{
								"repo":  map[string]string{"type": "string"},
								"title": map[string]string{"type": "string"},
							},
						},
					},
					{
						Name:        "pagerduty_resolve",
						Description: "Simulated: resolve a PagerDuty incident",
						InputSchema: map[string]any{
							"type": "object",
							"properties": map[string]any{
								"incident_id": map[string]string{"type": "string"},
							},
						},
					},
					{
						Name:        "dangerous_tool",
						Description: "This tool should be blocked by nullfield policy",
						InputSchema: map[string]any{
							"type":       "object",
							"properties": map[string]any{},
						},
					},
				},
			}

		case "tools/call":
			var params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			}
			json.Unmarshal(req.Params, &params)

			result = toolResult{
				Content: []contentBlock{
					{
						Type: "text",
						Text: fmt.Sprintf("echo-server executed tool=%q args=%v at %s",
							params.Name, params.Arguments, time.Now().Format(time.RFC3339)),
					},
				},
			}

		case "ping":
			result = map[string]any{}

		default:
			result = map[string]any{"echo": req.Method}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jsonrpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  result,
		})
	})

	logger.Info("echo-mcp-server starting", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}
