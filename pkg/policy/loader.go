package policy

import (
	"fmt"
	"os"

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

	var pol v1alpha1.NullfieldPolicy
	if err := yaml.Unmarshal(data, &pol); err != nil {
		return nil, fmt.Errorf("parse policy file: %w", err)
	}

	if len(pol.Spec.Rules) == 0 {
		return nil, fmt.Errorf("policy file contains no rules")
	}

	return &pol.Spec, nil
}
