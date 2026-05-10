package scope

import (
	"encoding/json"
	"regexp"
	"strings"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
)

// _redirectArgNames is the set of argument names that commonly carry URLs
// which may be used in open-redirect or SSRF patterns (MCP-T41).
var _redirectArgNames = map[string]bool{
	"url": true, "uri": true, "redirect": true,
	"location": true, "target": true, "cdn_url": true,
	"war_url": true, "webhook_url": true, "callback_url": true,
}

// _isRedirectLike returns true when the string value looks like an HTTP URL
// that could carry a redirect destination.
func _isRedirectLike(v string) bool {
	return strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://")
}

// Modifications tracks what was changed for the audit trail.
type Modifications struct {
	StrippedArgs []string `json:"stripped,omitempty"`
	InjectedArgs []string `json:"injected,omitempty"`
	RedactedCount int     `json:"redacted,omitempty"`
}

// ModifyRequest applies request-side scope rules to tool call arguments.
// Returns the modified arguments and a record of what changed.
func ModifyRequest(args map[string]any, cfg *v1alpha1.ScopeRequestConfig) (map[string]any, Modifications) {
	var mods Modifications
	if cfg == nil || args == nil {
		return args, mods
	}

	result := make(map[string]any, len(args))
	for k, v := range args {
		result[k] = v
	}

	for _, key := range cfg.StripArguments {
		if _, exists := result[key]; exists {
			delete(result, key)
			mods.StrippedArgs = append(mods.StrippedArgs, key)
		}
	}

	for key, val := range cfg.InjectArguments {
		result[key] = val
		mods.InjectedArgs = append(mods.InjectedArgs, key)
	}

	// blockRedirects: strip URL-typed args carrying redirect-prone values.
	// Defends against MCP-T41 (AI governance gate bypass via open redirect).
	if cfg.BlockRedirects {
		for k, v := range result {
			if _redirectArgNames[strings.ToLower(k)] {
				if s, ok := v.(string); ok && _isRedirectLike(s) {
					delete(result, k)
					mods.StrippedArgs = append(mods.StrippedArgs, k)
				}
			}
		}
	}

	return result, mods
}

// ModifyResponse applies response-side scope rules to the JSON-RPC result.
// Operates on the raw response body bytes and returns the modified bytes.
func ModifyResponse(body []byte, cfg *v1alpha1.ScopeResponseConfig) ([]byte, int) {
	if cfg == nil || len(cfg.RedactPatterns) == 0 {
		return body, 0
	}

	replacement := cfg.RedactReplacement
	if replacement == "" {
		replacement = "[REDACTED]"
	}

	totalRedacted := 0
	text := string(body)

	for _, pattern := range cfg.RedactPatterns {
		re, err := regexp.Compile("(?i)" + pattern + `\s*["']?\s*[:=]\s*["']?[^"',}\s]+["']?`)
		if err != nil {
			continue
		}
		matches := re.FindAllString(text, -1)
		if len(matches) > 0 {
			text = re.ReplaceAllString(text, replacement)
			totalRedacted += len(matches)
		}
	}

	if totalRedacted == 0 {
		// Try simple substring replacement for patterns that appear as values.
		for _, pattern := range cfg.RedactPatterns {
			re, err := regexp.Compile("(?i)" + pattern)
			if err != nil {
				continue
			}
			matches := re.FindAllString(text, -1)
			if len(matches) > 0 {
				text = re.ReplaceAllString(text, replacement)
				totalRedacted += len(matches)
			}
		}
	}

	return []byte(text), totalRedacted
}

// RebuildRequestBody takes the original JSON-RPC request body and replaces
// the tool call arguments with the modified ones.
func RebuildRequestBody(originalBody []byte, modifiedArgs map[string]any) ([]byte, error) {
	var req map[string]any
	if err := json.Unmarshal(originalBody, &req); err != nil {
		return originalBody, err
	}

	params, ok := req["params"].(map[string]any)
	if !ok {
		return originalBody, nil
	}
	params["arguments"] = modifiedArgs
	req["params"] = params

	return json.Marshal(req)
}

// ContainsSensitive checks if a string contains any of the given patterns.
func ContainsSensitive(s string, patterns []string) bool {
	lower := strings.ToLower(s)
	for _, p := range patterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
