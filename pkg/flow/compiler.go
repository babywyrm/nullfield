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
	Network         *NetworkSpec              `json:"network,omitempty" yaml:"network,omitempty"`
	Mesh            *MeshSpec                 `json:"mesh,omitempty" yaml:"mesh,omitempty"`
	Credentials     []FlowCredential          `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	Identity        *v1alpha1.IdentityConfig  `json:"identity,omitempty" yaml:"identity,omitempty"`
	Integrity       *v1alpha1.IntegrityConfig `json:"integrity,omitempty" yaml:"integrity,omitempty"`
	Anomaly         *v1alpha1.AnomalyConfig   `json:"anomaly,omitempty" yaml:"anomaly,omitempty"`
	Audit           v1alpha1.AuditConfig      `json:"audit,omitempty" yaml:"audit,omitempty"`
	Tools           []FlowTool                `json:"tools" yaml:"tools"`
}

type NetworkSpec struct {
	Egress []EgressDestination `json:"egress,omitempty" yaml:"egress,omitempty"`
}

type EgressDestination struct {
	Name  string `json:"name,omitempty" yaml:"name,omitempty"`
	CIDR  string `json:"cidr" yaml:"cidr"`
	Ports []int  `json:"ports,omitempty" yaml:"ports,omitempty"`
}

type MeshSpec struct {
	Istio *IstioAuthzSpec `json:"istio,omitempty" yaml:"istio,omitempty"`
}

type IstioAuthzSpec struct {
	Principals []string `json:"principals,omitempty" yaml:"principals,omitempty"`
	Ports      []int    `json:"ports,omitempty" yaml:"ports,omitempty"`
}

type FlowCredential struct {
	Name        string            `json:"name" yaml:"name"`
	From        string            `json:"from" yaml:"from"`
	SecretRef   string            `json:"secretRef" yaml:"secretRef"`
	InjectAs    string            `json:"injectAs,omitempty" yaml:"injectAs,omitempty"`
	OAuth       *OAuthSpec        `json:"oauth,omitempty" yaml:"oauth,omitempty"`
	AuditLabels map[string]string `json:"auditLabels,omitempty" yaml:"auditLabels,omitempty"`
}

type OAuthSpec struct {
	Issuer       string   `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	TokenURL     string   `json:"tokenUrl,omitempty" yaml:"tokenUrl,omitempty"`
	Audience     string   `json:"audience,omitempty" yaml:"audience,omitempty"`
	Scopes       []string `json:"scopes,omitempty" yaml:"scopes,omitempty"`
	SubjectToken string   `json:"subjectToken,omitempty" yaml:"subjectToken,omitempty"`
	ActorClaim   string   `json:"actorClaim,omitempty" yaml:"actorClaim,omitempty"`
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
	CredentialRefs []string                 `json:"credentialRefs,omitempty" yaml:"credentialRefs,omitempty"`
	Credentials    []v1alpha1.CredentialRef `json:"credentials,omitempty" yaml:"credentials,omitempty"`
	AllowedScopes  []string                 `json:"allowedScopes,omitempty" yaml:"allowedScopes,omitempty"`
	SignatureHash  string                   `json:"signatureHash,omitempty" yaml:"signatureHash,omitempty"`
	MaxCallsPerMin int                      `json:"maxCallsPerMinute,omitempty" yaml:"maxCallsPerMinute,omitempty"`
	AuditLabels    map[string]string        `json:"auditLabels,omitempty" yaml:"auditLabels,omitempty"`
	Reason         string                   `json:"reason,omitempty" yaml:"reason,omitempty"`
}

type Artifacts struct {
	Policy                     v1alpha1.NullfieldPolicy
	Registry                   v1alpha1.ToolRegistry
	NetworkPolicies            []NetworkPolicy
	IstioAuthorizationPolicies []IstioAuthorizationPolicy
}

type NetworkPolicy struct {
	APIVersion string            `json:"apiVersion" yaml:"apiVersion"`
	Kind       string            `json:"kind" yaml:"kind"`
	Metadata   v1alpha1.Metadata `json:"metadata" yaml:"metadata"`
	Spec       NetworkPolicySpec `json:"spec" yaml:"spec"`
}

type NetworkPolicySpec struct {
	PodSelector v1alpha1.Selector `json:"podSelector" yaml:"podSelector"`
	PolicyTypes []string          `json:"policyTypes" yaml:"policyTypes"`
	Egress      []NetworkEgress   `json:"egress" yaml:"egress"`
}

type NetworkEgress struct {
	To    []NetworkPeer `json:"to" yaml:"to"`
	Ports []NetworkPort `json:"ports,omitempty" yaml:"ports,omitempty"`
}

type NetworkPeer struct {
	IPBlock IPBlock `json:"ipBlock" yaml:"ipBlock"`
}

type IPBlock struct {
	CIDR string `json:"cidr" yaml:"cidr"`
}

type NetworkPort struct {
	Protocol string `json:"protocol" yaml:"protocol"`
	Port     int    `json:"port" yaml:"port"`
}

type IstioAuthorizationPolicy struct {
	APIVersion string                       `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                       `json:"kind" yaml:"kind"`
	Metadata   v1alpha1.Metadata            `json:"metadata" yaml:"metadata"`
	Spec       IstioAuthorizationPolicySpec `json:"spec" yaml:"spec"`
}

type IstioAuthorizationPolicySpec struct {
	Selector IstioSelector `json:"selector" yaml:"selector"`
	Action   string        `json:"action" yaml:"action"`
	Rules    []IstioRule   `json:"rules" yaml:"rules"`
}

type IstioSelector struct {
	MatchLabels map[string]string `json:"matchLabels" yaml:"matchLabels"`
}

type IstioRule struct {
	From []IstioFrom `json:"from,omitempty" yaml:"from,omitempty"`
	To   []IstioTo   `json:"to,omitempty" yaml:"to,omitempty"`
}

type IstioFrom struct {
	Source IstioSource `json:"source" yaml:"source"`
}

type IstioSource struct {
	Principals []string `json:"principals,omitempty" yaml:"principals,omitempty"`
}

type IstioTo struct {
	Operation IstioOperation `json:"operation" yaml:"operation"`
}

type IstioOperation struct {
	Ports []string `json:"ports,omitempty" yaml:"ports,omitempty"`
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
	for _, networkPolicy := range artifacts.NetworkPolicies {
		if err := enc.Encode(networkPolicy); err != nil {
			return nil, err
		}
	}
	for _, authzPolicy := range artifacts.IstioAuthorizationPolicies {
		if err := enc.Encode(authzPolicy); err != nil {
			return nil, err
		}
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
	if err := validateExplicitControlIntent(doc.Spec); err != nil {
		return Artifacts{}, err
	}

	metadata := doc.Metadata
	metadata.Labels = mergeLabels(metadata.Labels, flowLabels(doc.Spec))

	rules := make([]v1alpha1.Rule, 0, len(doc.Spec.Tools)+1)
	tools := make([]v1alpha1.ToolRegistryEntry, 0, len(doc.Spec.Tools))
	credentials, err := credentialMap(doc.Spec.Credentials)
	if err != nil {
		return Artifacts{}, err
	}
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
		resolvedCredentials, credentialLabels, err := resolveToolCredentials(tool, credentials)
		if err != nil {
			return Artifacts{}, err
		}
		if len(resolvedCredentials) > 0 {
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
			AuditLabels:     mergeLabels(tool.AuditLabels, credentialLabels),
			Reason:          tool.Reason,
		}

		if len(resolvedCredentials) > 0 {
			rule.Scope = ensureScopeRequest(rule.Scope)
			rule.Scope.Request.InjectCredentials = append(rule.Scope.Request.InjectCredentials, resolvedCredentials...)
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
		NetworkPolicies:            compileNetworkPolicies(doc, metadata),
		IstioAuthorizationPolicies: compileIstioAuthorizationPolicies(doc, metadata),
	}, nil
}

func validateExplicitControlIntent(spec FlowSpec) error {
	if spec.Network != nil && len(spec.Network.Egress) > 0 {
		if len(spec.Selector.MatchLabels) == 0 {
			return fmt.Errorf("spec.selector.matchLabels is required when spec.network.egress is declared")
		}
		for _, dest := range spec.Network.Egress {
			if dest.CIDR == "" {
				return fmt.Errorf("spec.network.egress[].cidr is required")
			}
			if len(dest.Ports) == 0 {
				return fmt.Errorf("spec.network.egress[].ports is required")
			}
		}
	}

	if spec.Mesh != nil && spec.Mesh.Istio != nil {
		if len(spec.Selector.MatchLabels) == 0 {
			return fmt.Errorf("spec.selector.matchLabels is required when spec.mesh.istio is declared")
		}
		if len(spec.Mesh.Istio.Principals) == 0 {
			return fmt.Errorf("spec.mesh.istio.principals is required")
		}
		if len(spec.Mesh.Istio.Ports) == 0 {
			return fmt.Errorf("spec.mesh.istio.ports is required")
		}
	}

	return nil
}

func credentialMap(credentials []FlowCredential) (map[string]FlowCredential, error) {
	out := make(map[string]FlowCredential, len(credentials))
	for _, credential := range credentials {
		if credential.Name == "" {
			return nil, fmt.Errorf("spec.credentials[].name is required")
		}
		if credential.From == "" {
			return nil, fmt.Errorf("spec.credentials[%q].from is required", credential.Name)
		}
		if credential.SecretRef == "" {
			return nil, fmt.Errorf("spec.credentials[%q].secretRef is required", credential.Name)
		}
		if _, exists := out[credential.Name]; exists {
			return nil, fmt.Errorf("duplicate credential declaration: %s", credential.Name)
		}
		out[credential.Name] = credential
	}
	return out, nil
}

func resolveToolCredentials(tool FlowTool, credentials map[string]FlowCredential) ([]v1alpha1.CredentialRef, map[string]string, error) {
	refs := append([]v1alpha1.CredentialRef(nil), tool.Credentials...)
	labels := map[string]string{}

	for _, name := range tool.CredentialRefs {
		credential, ok := credentials[name]
		if !ok {
			return nil, nil, fmt.Errorf("tool %q references undeclared credential %q", tool.Name, name)
		}
		refs = append(refs, v1alpha1.CredentialRef{
			From:      credential.From,
			SecretRef: credential.SecretRef,
			InjectAs:  credential.InjectAs,
		})
		labels = mergeLabels(labels, credentialLabels(credential))
	}

	if len(labels) == 0 {
		labels = nil
	}
	return refs, labels, nil
}

func credentialLabels(credential FlowCredential) map[string]string {
	labels := cloneStringMap(credential.AuditLabels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels["credential"] = credential.Name
	if credential.OAuth != nil {
		if credential.OAuth.Issuer != "" {
			labels["oauth_issuer"] = credential.OAuth.Issuer
		}
		if credential.OAuth.Audience != "" {
			labels["oauth_audience"] = credential.OAuth.Audience
		}
		if len(credential.OAuth.Scopes) > 0 {
			labels["oauth_scopes"] = strings.Join(credential.OAuth.Scopes, " ")
		}
	}
	return labels
}

func compileNetworkPolicies(doc AgenticFlow, metadata v1alpha1.Metadata) []NetworkPolicy {
	if doc.Spec.Network == nil || len(doc.Spec.Network.Egress) == 0 {
		return nil
	}
	egress := make([]NetworkEgress, 0, len(doc.Spec.Network.Egress))
	for _, dest := range doc.Spec.Network.Egress {
		if dest.CIDR == "" {
			continue
		}
		egress = append(egress, NetworkEgress{
			To:    []NetworkPeer{{IPBlock: IPBlock{CIDR: dest.CIDR}}},
			Ports: networkPorts(dest.Ports),
		})
	}
	if len(egress) == 0 {
		return nil
	}
	return []NetworkPolicy{{
		APIVersion: "networking.k8s.io/v1",
		Kind:       "NetworkPolicy",
		Metadata:   namedMetadata(metadata, metadata.Name+"-egress"),
		Spec: NetworkPolicySpec{
			PodSelector: v1alpha1.Selector{MatchLabels: cloneStringMap(doc.Spec.Selector.MatchLabels)},
			PolicyTypes: []string{"Egress"},
			Egress:      egress,
		},
	}}
}

func compileIstioAuthorizationPolicies(doc AgenticFlow, metadata v1alpha1.Metadata) []IstioAuthorizationPolicy {
	if doc.Spec.Mesh == nil || doc.Spec.Mesh.Istio == nil {
		return nil
	}
	istio := doc.Spec.Mesh.Istio
	if len(istio.Principals) == 0 && len(istio.Ports) == 0 {
		return nil
	}
	return []IstioAuthorizationPolicy{{
		APIVersion: "security.istio.io/v1beta1",
		Kind:       "AuthorizationPolicy",
		Metadata:   namedMetadata(metadata, metadata.Name+"-authz"),
		Spec: IstioAuthorizationPolicySpec{
			Selector: IstioSelector{MatchLabels: cloneStringMap(doc.Spec.Selector.MatchLabels)},
			Action:   "ALLOW",
			Rules: []IstioRule{{
				From: []IstioFrom{{Source: IstioSource{Principals: append([]string(nil), istio.Principals...)}}},
				To:   []IstioTo{{Operation: IstioOperation{Ports: stringPorts(istio.Ports)}}},
			}},
		},
	}}
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

func networkPorts(ports []int) []NetworkPort {
	out := make([]NetworkPort, 0, len(ports))
	for _, port := range ports {
		out = append(out, NetworkPort{Protocol: "TCP", Port: port})
	}
	return out
}

func stringPorts(ports []int) []string {
	out := make([]string, 0, len(ports))
	for _, port := range ports {
		out = append(out, fmt.Sprintf("%d", port))
	}
	return out
}

func namedMetadata(metadata v1alpha1.Metadata, name string) v1alpha1.Metadata {
	out := metadata
	out.Name = name
	out.Labels = cloneStringMap(metadata.Labels)
	return out
}

func ruleID(toolName string, action v1alpha1.Action) string {
	parts := strings.FieldsFunc(strings.ToLower(toolName), func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	})
	return strings.Join(append(parts, strings.ToLower(string(action))), "-")
}
