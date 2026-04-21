package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr string
	UpstreamAddr string
	AdminAddr string

	PolicyPath string
	ToolRegistryPath string

	AuditEndpoint string
	AuditLogLevel string

	IdentityTokenHeader string
	IdentityJWKSURL string

	CircuitMaxCalls int
	CircuitMaxDuration time.Duration

	VaultAddr       string
	VaultRole       string
	VaultAuthMethod string
	CredentialCacheTTL time.Duration

	TLSCertFile string
	TLSKeyFile  string

	ControllerAddr string
}

func Load() (*Config, error) {
	c := &Config{
		ListenAddr:          envOr("NULLFIELD_LISTEN_ADDR", ":9090"),
		UpstreamAddr:        envOr("NULLFIELD_UPSTREAM_ADDR", "localhost:8080"),
		AdminAddr:           envOr("NULLFIELD_ADMIN_ADDR", ":9091"),
		PolicyPath:          envOr("NULLFIELD_POLICY_PATH", "/etc/nullfield/policy.yaml"),
		ToolRegistryPath:    envOr("NULLFIELD_REGISTRY_PATH", "/etc/nullfield/tools.yaml"),
		AuditEndpoint:       envOr("NULLFIELD_AUDIT_ENDPOINT", ""),
		AuditLogLevel:       envOr("NULLFIELD_AUDIT_LOG_LEVEL", "FULL"),
		IdentityTokenHeader: envOr("NULLFIELD_IDENTITY_HEADER", "Authorization"),
		IdentityJWKSURL:     envOr("NULLFIELD_JWKS_URL", ""),
		VaultAddr:           envOr("NULLFIELD_VAULT_ADDR", ""),
		VaultRole:           envOr("NULLFIELD_VAULT_ROLE", ""),
		VaultAuthMethod:     envOr("NULLFIELD_VAULT_AUTH_METHOD", ""),
		TLSCertFile:         envOr("NULLFIELD_TLS_CERT", ""),
		TLSKeyFile:          envOr("NULLFIELD_TLS_KEY", ""),
		ControllerAddr:      envOr("NULLFIELD_CONTROLLER_ADDR", ""),
	}

	maxCalls, err := strconv.Atoi(envOr("NULLFIELD_CIRCUIT_MAX_CALLS", "100"))
	if err != nil {
		return nil, fmt.Errorf("invalid NULLFIELD_CIRCUIT_MAX_CALLS: %w", err)
	}
	c.CircuitMaxCalls = maxCalls

	maxDur, err := time.ParseDuration(envOr("NULLFIELD_CIRCUIT_MAX_DURATION", "5m"))
	if err != nil {
		return nil, fmt.Errorf("invalid NULLFIELD_CIRCUIT_MAX_DURATION: %w", err)
	}
	c.CircuitMaxDuration = maxDur

	credTTL, err := time.ParseDuration(envOr("NULLFIELD_CREDENTIAL_CACHE_TTL", "5m"))
	if err != nil {
		return nil, fmt.Errorf("invalid NULLFIELD_CREDENTIAL_CACHE_TTL: %w", err)
	}
	c.CredentialCacheTTL = credTTL

	if c.UpstreamAddr == "" {
		return nil, fmt.Errorf("NULLFIELD_UPSTREAM_ADDR is required")
	}

	return c, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
