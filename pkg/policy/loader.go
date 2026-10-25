package policy

import (
	"bytes"
	"fmt"
	"os"
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
		return fmt.Errorf("circuitBreaker.onTrip %q is not performed; a tripped breaker refuses calls (DENY), and nothing acts outside the proxy", s.CircuitBreaker.OnTrip)
	}
	if s.Integrity != nil && s.Integrity.ChainValidation {
		return fmt.Errorf("integrity.chainValidation is not enforced; use per-rule identity and delegation guards")
	}
	if s.Anomaly != nil && len(s.Anomaly.Sequences) > 0 {
		return fmt.Errorf("anomaly.sequences is not enforced; remove it")
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
