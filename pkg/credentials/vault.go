package credentials

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// VaultProvider fetches secrets from HashiCorp Vault using the HTTP API.
// Supports Kubernetes auth method (uses pod ServiceAccount token) and
// token auth (via VAULT_TOKEN env var).
type VaultProvider struct {
	addr       string
	token      string
	role       string
	authMethod string
	httpClient *http.Client
}

type VaultConfig struct {
	Addr       string // VAULT_ADDR or NULLFIELD_VAULT_ADDR
	Token      string // VAULT_TOKEN (for token auth)
	Role       string // Vault role for K8s auth
	AuthMethod string // "kubernetes" or "token"
}

func NewVaultProvider(cfg VaultConfig) (*VaultProvider, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("vault address is required")
	}
	cfg.Addr = strings.TrimRight(cfg.Addr, "/")

	if cfg.AuthMethod == "" {
		if cfg.Token != "" {
			cfg.AuthMethod = "token"
		} else {
			cfg.AuthMethod = "kubernetes"
		}
	}

	return &VaultProvider{
		addr:       cfg.Addr,
		token:      cfg.Token,
		role:       cfg.Role,
		authMethod: cfg.AuthMethod,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (p *VaultProvider) Fetch(ctx context.Context, ref string) (string, error) {
	token, err := p.resolveToken(ctx)
	if err != nil {
		return "", fmt.Errorf("vault auth failed: %w", err)
	}

	url := p.addr + "/v1/" + ref
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("vault request build failed: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("vault response read failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault returned %d: %s", resp.StatusCode, string(body))
	}

	var vaultResp vaultSecretResponse
	if err := json.Unmarshal(body, &vaultResp); err != nil {
		return "", fmt.Errorf("vault response parse failed: %w", err)
	}

	// KV v2 wraps data in data.data, KV v1 puts it in data directly.
	if inner, ok := vaultResp.Data["data"]; ok {
		if m, ok := inner.(map[string]any); ok {
			if val, ok := m["value"]; ok {
				return fmt.Sprint(val), nil
			}
			// Return first value if no "value" key.
			for _, v := range m {
				return fmt.Sprint(v), nil
			}
		}
	}

	if val, ok := vaultResp.Data["value"]; ok {
		return fmt.Sprint(val), nil
	}
	for _, v := range vaultResp.Data {
		return fmt.Sprint(v), nil
	}

	return "", fmt.Errorf("vault secret %q has no extractable value", ref)
}

func (p *VaultProvider) resolveToken(ctx context.Context) (string, error) {
	if p.authMethod == "token" && p.token != "" {
		return p.token, nil
	}

	saToken, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return "", fmt.Errorf("cannot read SA token for vault k8s auth: %w", err)
	}

	loginPayload := fmt.Sprintf(`{"jwt":"%s","role":"%s"}`, strings.TrimSpace(string(saToken)), p.role)
	url := p.addr + "/v1/auth/kubernetes/login"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(loginPayload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault k8s login failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault k8s login returned %d: %s", resp.StatusCode, string(body))
	}

	var loginResp vaultLoginResponse
	if err := json.Unmarshal(body, &loginResp); err != nil {
		return "", fmt.Errorf("vault login parse failed: %w", err)
	}
	if loginResp.Auth.ClientToken == "" {
		return "", fmt.Errorf("vault k8s login returned empty token")
	}

	p.token = loginResp.Auth.ClientToken
	return p.token, nil
}

type vaultSecretResponse struct {
	Data map[string]any `json:"data"`
}

type vaultLoginResponse struct {
	Auth struct {
		ClientToken string `json:"client_token"`
	} `json:"auth"`
}
