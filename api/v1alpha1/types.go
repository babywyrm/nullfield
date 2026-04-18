package v1alpha1

import "time"

// NullfieldPolicy defines the top-level policy applied to a set of pods.
type NullfieldPolicy struct {
	APIVersion string              `json:"apiVersion" yaml:"apiVersion"`
	Kind       string              `json:"kind" yaml:"kind"`
	Metadata   Metadata            `json:"metadata" yaml:"metadata"`
	Spec       NullfieldPolicySpec `json:"spec" yaml:"spec"`
}

type Metadata struct {
	Name      string            `json:"name" yaml:"name"`
	Namespace string            `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
}

type NullfieldPolicySpec struct {
	Selector       Selector       `json:"selector" yaml:"selector"`
	Rules          []Rule         `json:"rules" yaml:"rules"`
	CircuitBreaker CircuitBreaker `json:"circuitBreaker,omitempty" yaml:"circuitBreaker,omitempty"`
	Audit          AuditConfig    `json:"audit,omitempty" yaml:"audit,omitempty"`
}

type Selector struct {
	MatchLabels map[string]string `json:"matchLabels" yaml:"matchLabels"`
}

// Action is ALLOW or DENY.
type Action string

const (
	ActionAllow Action = "ALLOW"
	ActionDeny  Action = "DENY"
)

// Direction is INBOUND or OUTBOUND.
type Direction string

const (
	DirectionInbound  Direction = "INBOUND"
	DirectionOutbound Direction = "OUTBOUND"
)

type Rule struct {
	Action          Action          `json:"action" yaml:"action"`
	MCPMethod       string          `json:"mcpMethod,omitempty" yaml:"mcpMethod,omitempty"`
	ToolNames       []string        `json:"toolNames,omitempty" yaml:"toolNames,omitempty"`
	Direction       Direction       `json:"direction,omitempty" yaml:"direction,omitempty"`
	Destination     string          `json:"destination,omitempty" yaml:"destination,omitempty"`
	RequireIdentity bool            `json:"requireIdentity,omitempty" yaml:"requireIdentity,omitempty"`
	MaxCallsPerMin  int             `json:"maxCallsPerMinute,omitempty" yaml:"maxCallsPerMinute,omitempty"`
	CELExpression   string          `json:"celExpression,omitempty" yaml:"celExpression,omitempty"`
	InjectCred      *CredentialRef  `json:"injectCredential,omitempty" yaml:"injectCredential,omitempty"`
	ParamRules      []ParamRule     `json:"paramRules,omitempty" yaml:"paramRules,omitempty"`
}

type CredentialRef struct {
	SecretRef string `json:"secretRef" yaml:"secretRef"`
	From      string `json:"from" yaml:"from"`
}

type ParamRule struct {
	Name      string `json:"name" yaml:"name"`
	Required  bool   `json:"required,omitempty" yaml:"required,omitempty"`
	MaxLength int    `json:"maxLength,omitempty" yaml:"maxLength,omitempty"`
	Pattern   string `json:"pattern,omitempty" yaml:"pattern,omitempty"`
}

type CircuitBreaker struct {
	MaxToolCallsPerSession int           `json:"maxToolCallsPerSession,omitempty" yaml:"maxToolCallsPerSession,omitempty"`
	MaxSessionDuration     time.Duration `json:"maxSessionDuration,omitempty" yaml:"maxSessionDuration,omitempty"`
	OnTrip                 string        `json:"onTrip,omitempty" yaml:"onTrip,omitempty"`
}

// AuditLogLevel controls verbosity.
type AuditLogLevel string

const (
	AuditFull    AuditLogLevel = "FULL"
	AuditSummary AuditLogLevel = "SUMMARY"
	AuditNone    AuditLogLevel = "NONE"
)

type AuditConfig struct {
	EmitTo   string        `json:"emitTo,omitempty" yaml:"emitTo,omitempty"`
	LogLevel AuditLogLevel `json:"logLevel,omitempty" yaml:"logLevel,omitempty"`
}

// ToolRegistryEntry defines a registered, approved tool.
type ToolRegistryEntry struct {
	Name           string   `json:"name" yaml:"name"`
	Description    string   `json:"description,omitempty" yaml:"description,omitempty"`
	AllowedScopes  []string `json:"allowedScopes,omitempty" yaml:"allowedScopes,omitempty"`
	SignatureHash  string   `json:"signatureHash,omitempty" yaml:"signatureHash,omitempty"`
	MaxCallsPerMin int      `json:"maxCallsPerMinute,omitempty" yaml:"maxCallsPerMinute,omitempty"`
}

// ToolRegistry is the full tool manifest.
type ToolRegistry struct {
	APIVersion string              `json:"apiVersion" yaml:"apiVersion"`
	Kind       string              `json:"kind" yaml:"kind"`
	Metadata   Metadata            `json:"metadata" yaml:"metadata"`
	Tools      []ToolRegistryEntry `json:"tools" yaml:"tools"`
}
