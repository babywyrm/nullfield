package flow

import (
	"bytes"
	"fmt"
	"strings"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"gopkg.in/yaml.v3"
)

const (
	KindAgenticFlow     = "AgenticFlow"
	KindNullfieldPolicy = "NullfieldPolicy"
	KindToolRegistry    = "ToolRegistry"
	DefaultMCPMethod    = "tools/call"
)

// AgenticFlow is a higher-level intent document for one agentic path.
// It compiles into the existing NullfieldPolicy and ToolRegistry surfaces.
type AgenticFlow struct {
	APIVersion string            `json:"apiVersion" yaml:"apiVersion"`
	Kind       string            `json:"kind" yaml:"kind"`
	Metadata   v1alpha1.Metadata `json:"metadata" yaml:"metadata"`
	Spec       FlowSpec          `json:"spec" yaml:"spec"`
}

type FlowSpec struct {
	Selector        v1alpha1.Selector         `json:"selector" yaml:"selector"`
	Lane            string                    `json:"lane,omitempty" yaml:"lane,omitempty"`
	Transport       string                    `json:"transport,omitempty" yaml:"transport,omitempty"`
	RequireIdentity *bool                     `json:"requireIdentity,omitempty" yaml:"requireIdentity,omitempty"`
	Identity        *v1alpha1.IdentityConfig  `json:"identity,omitempty" yaml:"identity,omitempty"`
	Integrity       *v1alpha1.IntegrityConfig `json:"integrity,omitempty" yaml:"integrity,omitempty"`
	Anomaly         *v1alpha1.AnomalyConfig   `json:"anomaly,omitempty" yaml:"anomaly,omitempty"`
	Audit           v1alpha1.AuditConfig      `json:"audit,omitempty" yaml:"audit,omitempty"`
	Tools           []FlowTool                `json:"tools" yaml:"tools"`
}

type FlowTool struct {
	Name           string                   `json:"name" yaml:"name"`
	Description    string                   `json:"description,omitempty" yaml:"description,omitempty"`
	Action         v1alpha1.Action          `json:"action" yaml:"action"`
	MCPMethod      string                   `json:"mcpMethod,omitempty" yaml:"mcpMethod,omitempty"`
	When           *v1alpha1.WhenCondition  `json:"when,omitempty" yaml:"when,omitempty"`
	Hold           *v1alpha1.HoldConfig     `json:"hold,omitempty" yaml:"hold,omitempty"`
	Scope          *v1alpha1.ScopeConfig    `json:"scope,omitempty" yaml:"scope,omitempty"`
	Budget         *v1alpha1.BudgetConfig   `json:"budget,omitempty" yaml:"budget,omitempty"`
	Credentials    []v1alpha1.CredentialRef `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	AllowedScopes  []string                 `json:"allowedScopes,omitempty" yaml:"allowedScopes,omitempty"`
	SignatureHash  string                   `json:"signatureHash,omitempty" yaml:"signatureHash,omitempty"`
	MaxCallsPerMin int                      `json:"maxCallsPerMinute,omitempty" yaml:"maxCallsPerMinute,omitempty"`
	AuditLabels    map[string]string        `json:"auditLabels,omitempty" yaml:"auditLabels,omitempty"`
	Reason         string                   `json:"reason,omitempty" yaml:"reason,omitempty"`
}

type Artifacts struct {
	Policy   v1alpha1.NullfieldPolicy
	Registry v1alpha1.ToolRegistry
}

func LoadYAML(data []byte) (AgenticFlow, error) {
	var doc AgenticFlow
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return AgenticFlow{}, err
	}
	return doc, nil
}

func MarshalArtifactsYAML(artifacts Artifacts) ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(artifacts.Policy); err != nil {
		return nil, err
	}
	if err := enc.Encode(artifacts.Registry); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func Compile(doc AgenticFlow) (Artifacts, error) {
	if doc.Metadata.Name == "" {
		return Artifacts{}, fmt.Errorf("metadata.name is required")
	}
	if len(doc.Spec.Tools) == 0 {
		return Artifacts{}, fmt.Errorf("spec.tools must declare at least one tool")
	}

	metadata := doc.Metadata
	metadata.Labels = mergeLabels(metadata.Labels, flowLabels(doc.Spec))

	rules := make([]v1alpha1.Rule, 0, len(doc.Spec.Tools)+1)
	tools := make([]v1alpha1.ToolRegistryEntry, 0, len(doc.Spec.Tools))
	requireIdentity := true
	if doc.Spec.RequireIdentity != nil {
		requireIdentity = *doc.Spec.RequireIdentity
	}

	for _, tool := range doc.Spec.Tools {
		if tool.Name == "" {
			return Artifacts{}, fmt.Errorf("tool name is required")
		}
		action := tool.Action
		if action == "" {
			action = v1alpha1.ActionAllow
		}
		if len(tool.Credentials) > 0 {
			action = v1alpha1.ActionScope
		}

		rule := v1alpha1.Rule{
			ID:              ruleID(tool.Name, action),
			Action:          action,
			MCPMethod:       defaultString(tool.MCPMethod, DefaultMCPMethod),
			ToolNames:       []string{tool.Name},
			RequireIdentity: requireIdentity,
			When:            tool.When,
			Hold:            tool.Hold,
			Scope:           tool.Scope,
			Budget:          tool.Budget,
			AuditLabels:     cloneStringMap(tool.AuditLabels),
			Reason:          tool.Reason,
		}

		if len(tool.Credentials) > 0 {
			rule.Scope = ensureScopeRequest(rule.Scope)
			rule.Scope.Request.InjectCredentials = append(rule.Scope.Request.InjectCredentials, tool.Credentials...)
		}

		rules = append(rules, rule)
		tools = append(tools, v1alpha1.ToolRegistryEntry{
			Name:           tool.Name,
			Description:    tool.Description,
			AllowedScopes:  append([]string(nil), tool.AllowedScopes...),
			SignatureHash:  tool.SignatureHash,
			MaxCallsPerMin: tool.MaxCallsPerMin,
		})
	}

	rules = append(rules, v1alpha1.Rule{
		ID:        "default-deny",
		Action:    v1alpha1.ActionDeny,
		MCPMethod: DefaultMCPMethod,
		ToolNames: []string{"*"},
		Reason:    "no matching agentic flow rule",
	})

	return Artifacts{
		Policy: v1alpha1.NullfieldPolicy{
			APIVersion: doc.APIVersion,
			Kind:       KindNullfieldPolicy,
			Metadata:   metadata,
			Spec: v1alpha1.NullfieldPolicySpec{
				Selector:  doc.Spec.Selector,
				Identity:  doc.Spec.Identity,
				Integrity: doc.Spec.Integrity,
				Anomaly:   doc.Spec.Anomaly,
				Audit:     doc.Spec.Audit,
				Rules:     rules,
			},
		},
		Registry: v1alpha1.ToolRegistry{
			APIVersion: doc.APIVersion,
			Kind:       KindToolRegistry,
			Metadata:   metadata,
			Tools:      tools,
		},
	}, nil
}

func ensureScopeRequest(scope *v1alpha1.ScopeConfig) *v1alpha1.ScopeConfig {
	if scope == nil {
		scope = &v1alpha1.ScopeConfig{}
	}
	if scope.Request == nil {
		scope.Request = &v1alpha1.ScopeRequestConfig{}
	}
	return scope
}

func flowLabels(spec FlowSpec) map[string]string {
	labels := map[string]string{}
	if spec.Lane != "" {
		labels["nullfield.io/lane"] = spec.Lane
	}
	if spec.Transport != "" {
		labels["nullfield.io/transport"] = spec.Transport
	}
	if len(labels) == 0 {
		return nil
	}
	return labels
}

func mergeLabels(base, overlay map[string]string) map[string]string {
	out := cloneStringMap(base)
	if out == nil {
		out = map[string]string{}
	}
	for k, v := range overlay {
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func ruleID(toolName string, action v1alpha1.Action) string {
	parts := strings.FieldsFunc(strings.ToLower(toolName), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	return strings.Join(append(parts, strings.ToLower(string(action))), "-")
}
