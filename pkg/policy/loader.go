package policy

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"gopkg.in/yaml.v3"
)

// LoadFromFile reads a NullfieldPolicy YAML and returns the rules.
// Retained for backward compatibility.
func LoadFromFile(path string) ([]v1alpha1.Rule, error) {
	spec, err := LoadSpecFromFile(path)
	if err != nil {
		return nil, err
	}
	return spec.Rules, nil
}

// LoadSpecFromFile reads a NullfieldPolicy YAML and returns the full spec,
// including identity config, integrity config, and rules.
func LoadSpecFromFile(path string) (*v1alpha1.NullfieldPolicySpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy file: %w", err)
	}
	return ParseSpec(data)
}

// ParseSpec parses a NullfieldPolicy document and refuses one that sets
// anything nullfield would not enforce: an unknown key, or a known field with
// nothing behind it. Either would read as a control and act as none.
func ParseSpec(data []byte) (*v1alpha1.NullfieldPolicySpec, error) {
	var pol v1alpha1.NullfieldPolicy
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&pol); err != nil {
		return nil, fmt.Errorf("parse policy file: %w", err)
	}

	if len(pol.Spec.Rules) == 0 {
		return nil, fmt.Errorf("policy file contains no rules")
	}
	if err := validate(&pol.Spec); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return &pol.Spec, nil
}

// LoadProxySpecFromFile is LoadSpecFromFile for the proxy and gateway, which
// also refuse what they cannot enforce. They see no attested workload, so a
// run token there could not be bound to one.
func LoadProxySpecFromFile(path string) (*v1alpha1.NullfieldPolicySpec, error) {
	spec, err := LoadSpecFromFile(path)
	if err != nil {
		return nil, err
	}
	if spec.RunToken != nil {
		return nil, fmt.Errorf("policy: runToken is enforced by nullfield-extauthz only: the proxy has no attested workload to bind it to")
	}
	return spec, nil
}

func validate(s *v1alpha1.NullfieldPolicySpec) error {
	for i, r := range s.Rules {
		for _, f := range []struct {
			name string
			set  bool
		}{
			{"direction", r.Direction != ""},
			{"destination", r.Destination != ""},
			{"injectCredential", r.InjectCred != nil},
			{"paramRules", len(r.ParamRules) > 0},
			{"hold.notify", r.Hold != nil && r.Hold.Notify != nil},
		} {
			if f.set {
				return fmt.Errorf("rule %d sets %s, which is not enforced; remove it", i, f.name)
			}
		}
		if r.CELExpression != "" {
			if _, err := compileCEL(r.CELExpression); err != nil {
				return fmt.Errorf("rule %d: celExpression: %w", i, err)
			}
		}
		if b := r.Budget; b != nil && b.OnExhausted != "" && b.OnExhausted != "DENY" {
			return fmt.Errorf("rule %d: budget.onExhausted %q is not supported; an exhausted budget always denies", i, b.OnExhausted)
		}
	}
	switch s.CircuitBreaker.OnTrip {
	case "", "DENY", "REJECT":
	default:
		return fmt.Errorf("circuitBreaker.onTrip %q is not performed; a tripped breaker refuses calls (DENY). To end the workload, have its controller act on the circuit.tripped signal (docs/signals.md)", s.CircuitBreaker.OnTrip)
	}
	if s.Integrity != nil && s.Integrity.ChainValidation {
		return fmt.Errorf("integrity.chainValidation is not enforced; use per-rule identity and delegation guards")
	}
	if s.Anomaly != nil && len(s.Anomaly.Sequences) > 0 {
		return fmt.Errorf("anomaly.sequences is not enforced; remove it")
	}

	if rt := s.RunToken; rt != nil {
		if rt.JWKSURI == "" || rt.Audience == "" {
			return fmt.Errorf("runToken needs jwksUri and audience (the trust domain); without either nothing is verified")
		}
		for name, d := range map[string]string{"maxLifetime": rt.MaxLifetime, "clockSkew": rt.ClockSkew} {
			if _, err := time.ParseDuration(d); d != "" && err != nil {
				return fmt.Errorf("runToken.%s: %w", name, err)
			}
		}
		for _, svc := range rt.ForwardTo {
			if !isServiceFQDN(svc) {
				return fmt.Errorf("runToken.forwardTo %q must be a full Service name (name.namespace.svc.<domain>); short names and external hosts cannot be verified from a destination VIP", svc)
			}
		}
		for i, d := range rt.Delegates {
			if !isSPIFFEPrincipal(d.Workload) {
				return fmt.Errorf("runToken.delegates[%d].workload %q must be an exact SPIFFE ID (spiffe://<domain>/ns/<ns>/sa/<sa>)", i, d.Workload)
			}
			if len(d.For) == 0 {
				return fmt.Errorf("runToken.delegates[%d] (%s) must list at least one caller in for", i, d.Workload)
			}
			for _, f := range d.For {
				if !isSPIFFEPattern(f) {
					return fmt.Errorf("runToken.delegates[%d].for %q must be a SPIFFE ID or prefix ending in /*", i, f)
				}
			}
		}
	}

	id := s.Identity
	if id == nil {
		return nil
	}
	for _, p := range id.Providers {
		if p.ClockSkew != "" {
			if _, err := time.ParseDuration(p.ClockSkew); err != nil {
				return fmt.Errorf("provider %q: clockSkew: %w", p.Name, err)
			}
		}
		if id.Validation != nil && id.Validation.RequireAudience && len(p.Audiences) == 0 {
			return fmt.Errorf("provider %q: requireAudience is set but the provider lists no audiences, so any audience would pass", p.Name)
		}
	}
	if v := id.Validation; v != nil && v.MaxLifetime != "" {
		if _, err := time.ParseDuration(v.MaxLifetime); err != nil {
			return fmt.Errorf("identity.validation.maxLifetime: %w", err)
		}
	}
	return nil
}

func isServiceFQDN(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if strings.ContainsAny(name, "*:[]/ ") {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 4 || labels[2] != "svc" {
		return false
	}
	for _, l := range labels {
		if l == "" {
			return false
		}
	}
	return true
}

func isSPIFFEPrincipal(s string) bool {
	if !strings.HasPrefix(s, "spiffe://") || strings.ContainsAny(s, "* ") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(s, "spiffe://"), "/")
	return len(parts) == 5 && parts[0] != "" && parts[1] == "ns" && parts[2] != "" && parts[3] == "sa" && parts[4] != ""
}

func isSPIFFEPattern(s string) bool {
	if prefix, ok := strings.CutSuffix(s, "/*"); ok {
		return isSPIFFEPrincipal(prefix + "/x")
	}
	return isSPIFFEPrincipal(s)
}
