package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr   string
	UpstreamAddr string
	AdminAddr    string

	PolicyPath       string
	ToolRegistryPath string

	AuditEndpoint string
	AuditLogLevel string

	IdentityTokenHeader   string
	IdentityJWKSURL       string
	IdentityJWKSIssuer    string
	IdentityJWKSAudiences []string
	IdentityTrustHeader   bool

	CircuitMaxCalls    int
	CircuitMaxDuration time.Duration

	VaultAddr          string
	VaultRole          string
	VaultAuthMethod    string
	CredentialCacheTTL time.Duration

	TLSCertFile string
	TLSKeyFile  string

	RoutesPath string

	ControllerAddr string

	// ExtAuthzListenAddr is where the ext_authz decision service serves gRPC.
	// It must match the port in the Istio extensionProvider.
	ExtAuthzListenAddr string
	// ExtAuthzMode is no-op, observe, or enforce. Validation lives in
	// pkg/extauthz, which defaults anything it does not recognise to observe.
	ExtAuthzMode string
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
		IdentityJWKSIssuer:  envOr("NULLFIELD_JWKS_ISSUER", ""),
		IdentityTrustHeader: envOr("NULLFIELD_TRUST_HEADER_IDENTITY", "") == "true",
		VaultAddr:           envOr("NULLFIELD_VAULT_ADDR", ""),
		VaultRole:           envOr("NULLFIELD_VAULT_ROLE", ""),
		VaultAuthMethod:     envOr("NULLFIELD_VAULT_AUTH_METHOD", ""),
		TLSCertFile:         envOr("NULLFIELD_TLS_CERT", ""),
		TLSKeyFile:          envOr("NULLFIELD_TLS_KEY", ""),
		RoutesPath:          envOr("NULLFIELD_ROUTES_PATH", ""),
		ControllerAddr:      envOr("NULLFIELD_CONTROLLER_ADDR", ""),
		ExtAuthzListenAddr:  envOr("NULLFIELD_EXTAUTHZ_LISTEN_ADDR", ":9191"),
		ExtAuthzMode:        envOr("NULLFIELD_EXTAUTHZ_MODE", "observe"),
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

	if aud := envOr("NULLFIELD_JWKS_AUDIENCE", ""); aud != "" {
		for _, a := range strings.Split(aud, ",") {
			if a = strings.TrimSpace(a); a != "" {
				c.IdentityJWKSAudiences = append(c.IdentityJWKSAudiences, a)
			}
		}
	}

	if c.UpstreamAddr == "" && c.RoutesPath == "" {
		return nil, fmt.Errorf("NULLFIELD_UPSTREAM_ADDR or NULLFIELD_ROUTES_PATH is required")
	}

	return c, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
