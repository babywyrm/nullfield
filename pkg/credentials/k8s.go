package credentials

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// K8sSecretProvider fetches secrets from the Kubernetes API using the
// in-cluster ServiceAccount token. No client-go dependency required.
type K8sSecretProvider struct {
	apiHost    string
	token      string
	namespace  string
	httpClient *http.Client
}

type K8sConfig struct {
	Namespace string // Override namespace (default: pod's own namespace)
}

func NewK8sSecretProvider(cfg K8sConfig) (*K8sSecretProvider, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("not running in-cluster: KUBERNETES_SERVICE_HOST/PORT not set")
	}

	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("cannot read SA token: %w", err)
	}

	ns := cfg.Namespace
	if ns == "" {
		nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			return nil, fmt.Errorf("cannot read pod namespace: %w", err)
		}
		ns = strings.TrimSpace(string(nsBytes))
	}

	return &K8sSecretProvider{
		apiHost:   fmt.Sprintf("https://%s:%s", host, port),
		token:     strings.TrimSpace(string(token)),
		namespace: ns,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: false,
				},
			},
		},
	}, nil
}

// Fetch reads a secret key. ref format: "secret-name/key" or just "secret-name"
// (returns the first data key).
func (p *K8sSecretProvider) Fetch(ctx context.Context, ref string) (string, error) {
	parts := strings.SplitN(ref, "/", 2)
	secretName := parts[0]
	var keyName string
	if len(parts) > 1 {
		keyName = parts[1]
	}

	url := fmt.Sprintf("%s/api/v1/namespaces/%s/secrets/%s", p.apiHost, p.namespace, secretName)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("k8s secret request build failed: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+p.token)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("k8s secret request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("k8s secret response read failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("k8s secret API returned %d: %s", resp.StatusCode, string(body))
	}

	var secret k8sSecret
	if err := json.Unmarshal(body, &secret); err != nil {
		return "", fmt.Errorf("k8s secret parse failed: %w", err)
	}

	if keyName != "" {
		encoded, ok := secret.Data[keyName]
		if !ok {
			return "", fmt.Errorf("key %q not found in secret %q", keyName, secretName)
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", fmt.Errorf("k8s secret decode failed: %w", err)
		}
		return string(decoded), nil
	}

	for _, v := range secret.Data {
		decoded, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return "", fmt.Errorf("k8s secret decode failed: %w", err)
		}
		return string(decoded), nil
	}

	return "", fmt.Errorf("secret %q has no data keys", secretName)
}

type k8sSecret struct {
	Data map[string]string `json:"data"`
}
