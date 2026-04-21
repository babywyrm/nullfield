package proxy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadGatewayConfig reads a gateway routes configuration file.
func LoadGatewayConfig(path string) (*GatewayConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read gateway config: %w", err)
	}

	var cfg GatewayConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse gateway config: %w", err)
	}

	if len(cfg.Gateway.Routes) == 0 {
		return nil, fmt.Errorf("gateway config has no routes")
	}

	for i, r := range cfg.Gateway.Routes {
		if r.Name == "" {
			return nil, fmt.Errorf("route %d: name is required", i)
		}
		if r.Upstream == "" {
			return nil, fmt.Errorf("route %q: upstream is required", r.Name)
		}
		if r.ToolPrefix == "" && len(r.ToolNames) == 0 {
			return nil, fmt.Errorf("route %q: toolPrefix or toolNames is required", r.Name)
		}
	}

	return &cfg, nil
}
