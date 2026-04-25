// Package inspection detects sensitive content in MCP tool responses
// before they reach the LLM. It checks for credential material, PII,
// system prompt fragments, internal paths, and infrastructure details.
package inspection

import (
	"regexp"
	"strings"
)

// Finding represents a detected sensitive pattern in a response.
type Finding struct {
	Category string
	Pattern  string
	Match    string
	Severity string
}

// Inspector analyzes response content for sensitive data.
type Inspector struct {
	rules []rule
}

type rule struct {
	category string
	severity string
	pattern  *regexp.Regexp
	label    string
}

// Config controls which inspection rules are enabled.
type Config struct {
	DetectCredentials bool     `json:"detectCredentials,omitempty" yaml:"detectCredentials,omitempty"`
	DetectPII         bool     `json:"detectPII,omitempty" yaml:"detectPII,omitempty"`
	DetectPromptLeak  bool     `json:"detectPromptLeak,omitempty" yaml:"detectPromptLeak,omitempty"`
	DetectInternalPaths bool   `json:"detectInternalPaths,omitempty" yaml:"detectInternalPaths,omitempty"`
	CustomPatterns    []string `json:"customPatterns,omitempty" yaml:"customPatterns,omitempty"`
}

// DefaultConfig enables all detection categories.
func DefaultConfig() Config {
	return Config{
		DetectCredentials:   true,
		DetectPII:           true,
		DetectPromptLeak:    true,
		DetectInternalPaths: true,
	}
}

// New creates an Inspector from a Config.
func New(cfg Config) *Inspector {
	var rules []rule

	if cfg.DetectCredentials {
		rules = append(rules, credentialRules...)
	}
	if cfg.DetectPII {
		rules = append(rules, piiRules...)
	}
	if cfg.DetectPromptLeak {
		rules = append(rules, promptLeakRules...)
	}
	if cfg.DetectInternalPaths {
		rules = append(rules, internalPathRules...)
	}

	for _, p := range cfg.CustomPatterns {
		re, err := regexp.Compile(p)
		if err == nil {
			rules = append(rules, rule{
				category: "custom",
				severity: "HIGH",
				pattern:  re,
				label:    p,
			})
		}
	}

	return &Inspector{rules: rules}
}

// Inspect analyzes text content and returns all findings.
func (i *Inspector) Inspect(content string) []Finding {
	var findings []Finding
	for _, r := range i.rules {
		matches := r.pattern.FindAllString(content, 3)
		for _, m := range matches {
			if len(m) > 100 {
				m = m[:100] + "..."
			}
			findings = append(findings, Finding{
				Category: r.category,
				Pattern:  r.label,
				Match:    m,
				Severity: r.severity,
			})
		}
	}
	return findings
}

// Redact replaces all detected patterns with a replacement string.
func (i *Inspector) Redact(content, replacement string) (string, int) {
	if replacement == "" {
		replacement = "[REDACTED]"
	}
	count := 0
	result := content
	for _, r := range i.rules {
		if r.pattern.MatchString(result) {
			matches := r.pattern.FindAllString(result, -1)
			count += len(matches)
			result = r.pattern.ReplaceAllString(result, replacement)
		}
	}
	return result, count
}

// HasSensitiveContent returns true if the content contains any detectable
// sensitive patterns.
func (i *Inspector) HasSensitiveContent(content string) bool {
	for _, r := range i.rules {
		if r.pattern.MatchString(content) {
			return true
		}
	}
	return false
}

var credentialRules = []rule{
	{category: "credential", severity: "CRITICAL", pattern: regexp.MustCompile(`-----BEGIN\s+(?:\w+\s+)?PRIVATE KEY-----`), label: "private_key_header"},
	{category: "credential", severity: "CRITICAL", pattern: regexp.MustCompile(`(?i)(?:password|passwd|secret|api[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key)\s*[:=]\s*["']?[^\s"']{8,}`), label: "credential_assignment"},
	{category: "credential", severity: "HIGH", pattern: regexp.MustCompile(`(?:sk|pk|ak|rk)-[a-zA-Z0-9]{20,}`), label: "api_key_pattern"},
	{category: "credential", severity: "HIGH", pattern: regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9._\-]{20,}`), label: "bearer_token"},
	{category: "credential", severity: "HIGH", pattern: regexp.MustCompile(`(?i)(?:aws|gcp|azure)[_-](?:secret|key|token)[_-]?\w*\s*[:=]\s*\S+`), label: "cloud_credential"},
}

var piiRules = []rule{
	{category: "pii", severity: "HIGH", pattern: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), label: "ssn_pattern"},
	{category: "pii", severity: "MEDIUM", pattern: regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b`), label: "email_address"},
	{category: "pii", severity: "MEDIUM", pattern: regexp.MustCompile(`\b(?:\d{4}[- ]?){3}\d{4}\b`), label: "credit_card_pattern"},
}

var promptLeakRules = []rule{
	{category: "prompt_leak", severity: "HIGH", pattern: regexp.MustCompile(`(?i)(?:system\s+prompt|you\s+are\s+an?\s+(?:AI|assistant|model)|instructions?:\s*(?:you|do\s+not|never|always))`), label: "system_prompt_fragment"},
	{category: "prompt_leak", severity: "MEDIUM", pattern: regexp.MustCompile(`(?i)(?:respond\s+only\s+with|do\s+not\s+reveal|never\s+disclose|keep\s+(?:this|these)\s+(?:secret|private|confidential))`), label: "instruction_leak"},
}

var internalPathRules = []rule{
	{category: "internal_path", severity: "HIGH", pattern: regexp.MustCompile(`/var/run/secrets/kubernetes`), label: "k8s_sa_path"},
	{category: "internal_path", severity: "MEDIUM", pattern: regexp.MustCompile(`/etc/(?:shadow|passwd|ssl/private|teleport|nullfield)`), label: "sensitive_etc_path"},
	{category: "internal_path", severity: "MEDIUM", pattern: regexp.MustCompile(`(?i)(?:\w+\.svc\.cluster\.local|kubernetes\.default)`), label: "k8s_internal_dns"},
	{category: "internal_path", severity: "MEDIUM", pattern: regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}:\d{4,5}`), label: "internal_ip_port"},
}

// Summarize returns a human-readable summary of findings.
func Summarize(findings []Finding) string {
	if len(findings) == 0 {
		return "no sensitive content detected"
	}
	cats := map[string]int{}
	for _, f := range findings {
		cats[f.Category]++
	}
	var parts []string
	for cat, count := range cats {
		parts = append(parts, strings.ReplaceAll(cat, "_", " ")+": "+strings.Repeat("*", count))
	}
	return strings.Join(parts, ", ")
}
