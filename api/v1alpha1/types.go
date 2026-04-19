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
	Selector       Selector         `json:"selector" yaml:"selector"`
	Identity       *IdentityConfig  `json:"identity,omitempty" yaml:"identity,omitempty"`
	Integrity      *IntegrityConfig `json:"integrity,omitempty" yaml:"integrity,omitempty"`
	Anomaly        *AnomalyConfig   `json:"anomaly,omitempty" yaml:"anomaly,omitempty"`
	Rules          []Rule           `json:"rules" yaml:"rules"`
	CircuitBreaker CircuitBreaker   `json:"circuitBreaker,omitempty" yaml:"circuitBreaker,omitempty"`
	Audit          AuditConfig      `json:"audit,omitempty" yaml:"audit,omitempty"`
}

// AnomalyConfig configures opt-in anomaly detection patterns.
// When Enabled is false (default), no anomaly tracking occurs.
type AnomalyConfig struct {
	Enabled  bool            `json:"enabled" yaml:"enabled"`
	Velocity *VelocityConfig `json:"velocity,omitempty" yaml:"velocity,omitempty"`
}

type VelocityConfig struct {
	Threshold   int    `json:"threshold,omitempty" yaml:"threshold,omitempty"`
	AlertAction string `json:"alertAction,omitempty" yaml:"alertAction,omitempty"`
}

// IdentityConfig configures opt-in JWT/OIDC identity validation.
// When Enabled is false (default), nullfield uses noop or header-only verification.
type IdentityConfig struct {
	Enabled    bool               `json:"enabled" yaml:"enabled"`
	Providers  []IdentityProvider `json:"providers,omitempty" yaml:"providers,omitempty"`
	Validation *ValidationConfig  `json:"validation,omitempty" yaml:"validation,omitempty"`
}

type IdentityProvider struct {
	Name      string   `json:"name" yaml:"name"`
	Issuer    string   `json:"issuer" yaml:"issuer"`
	JWKSURI   string   `json:"jwksUri" yaml:"jwksUri"`
	Audiences []string `json:"audiences,omitempty" yaml:"audiences,omitempty"`
	ClockSkew string   `json:"clockSkew,omitempty" yaml:"clockSkew,omitempty"`
}

type ValidationConfig struct {
	RequireSignature bool     `json:"requireSignature,omitempty" yaml:"requireSignature,omitempty"`
	AllowedAlgorithms []string `json:"allowedAlgorithms,omitempty" yaml:"allowedAlgorithms,omitempty"`
	RequireExpiry    bool     `json:"requireExpiry,omitempty" yaml:"requireExpiry,omitempty"`
	MaxLifetime      string   `json:"maxLifetime,omitempty" yaml:"maxLifetime,omitempty"`
	RequireAudience  bool     `json:"requireAudience,omitempty" yaml:"requireAudience,omitempty"`
}

// IntegrityConfig configures opt-in token integrity checks.
// When Enabled is false (default), no session binding or replay detection occurs.
type IntegrityConfig struct {
	Enabled         bool `json:"enabled" yaml:"enabled"`
	BindToSession   bool `json:"bindToSession,omitempty" yaml:"bindToSession,omitempty"`
	DetectReplay    bool `json:"detectReplay,omitempty" yaml:"detectReplay,omitempty"`
	ChainValidation bool `json:"chainValidation,omitempty" yaml:"chainValidation,omitempty"`
}

// WhenCondition specifies optional conditions a rule must match.
// All specified fields must match (AND logic). Absent fields match anything.
type WhenCondition struct {
	IdentityType string         `json:"identity,omitempty" yaml:"identity,omitempty"`
	Provider     string         `json:"provider,omitempty" yaml:"provider,omitempty"`
	Claims       map[string]any `json:"claims,omitempty" yaml:"claims,omitempty"`
}

type Selector struct {
	MatchLabels map[string]string `json:"matchLabels" yaml:"matchLabels"`
}

// Action defines what nullfield does with a tool call.
type Action string

const (
	ActionAllow  Action = "ALLOW"
	ActionDeny   Action = "DENY"
	ActionHold   Action = "HOLD"
	ActionScope  Action = "SCOPE"
)

// HoldConfig configures the HOLD action — park a request for human approval.
type HoldConfig struct {
	Timeout   string       `json:"timeout,omitempty" yaml:"timeout,omitempty"`
	OnTimeout string       `json:"onTimeout,omitempty" yaml:"onTimeout,omitempty"`
	Notify    *NotifyConfig `json:"notify,omitempty" yaml:"notify,omitempty"`
}

type NotifyConfig struct {
	Webhook  string `json:"webhook,omitempty" yaml:"webhook,omitempty"`
	AdminAPI bool   `json:"adminAPI,omitempty" yaml:"adminAPI,omitempty"`
}

// BudgetConfig attaches resource limits to an ALLOW rule.
// The tool call is allowed only if the budget has room.
type BudgetConfig struct {
	PerIdentity *BudgetLimits `json:"perIdentity,omitempty" yaml:"perIdentity,omitempty"`
	PerSession  *BudgetLimits `json:"perSession,omitempty" yaml:"perSession,omitempty"`
	OnExhausted string        `json:"onExhausted,omitempty" yaml:"onExhausted,omitempty"`
}

type BudgetLimits struct {
	MaxCallsPerHour int `json:"maxCallsPerHour,omitempty" yaml:"maxCallsPerHour,omitempty"`
	MaxCallsPerDay  int `json:"maxCallsPerDay,omitempty" yaml:"maxCallsPerDay,omitempty"`
	MaxTokensPerDay int `json:"maxTokensPerDay,omitempty" yaml:"maxTokensPerDay,omitempty"`
}

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
	When            *WhenCondition  `json:"when,omitempty" yaml:"when,omitempty"`
	Hold            *HoldConfig     `json:"hold,omitempty" yaml:"hold,omitempty"`
	Budget          *BudgetConfig   `json:"budget,omitempty" yaml:"budget,omitempty"`
	Reason          string          `json:"reason,omitempty" yaml:"reason,omitempty"`
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
