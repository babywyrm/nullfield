// Package kube is a minimal Kubernetes API client: the service account's
// token and CA, and nothing else. No client-go.
package kube

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

const serviceAccount = "/var/run/secrets/kubernetes.io/serviceaccount/"

// Config locates the API server and the credentials to call it.
type Config struct {
	APIServer string
	TokenFile string
	CAFile    string
}

// InCluster is the pod's own service account.
func InCluster() (Config, error) {
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return Config{}, errors.New("kube: not running in-cluster: KUBERNETES_SERVICE_HOST/PORT not set")
	}
	return Config{
		APIServer: "https://" + host + ":" + port,
		TokenFile: serviceAccount + "token",
		CAFile:    serviceAccount + "ca.crt",
	}, nil
}

// Namespace is the pod's own namespace.
func Namespace() (string, error) {
	b, err := os.ReadFile(serviceAccount + "namespace")
	return strings.TrimSpace(string(b)), err
}

// Client calls the API server with the current token.
type Client struct {
	Base  string
	HTTP  *http.Client
	Token func() (string, error)
}

// New verifies the API server against the CA, and reads the token on every
// request, because a projected token rotates under a running process.
func New(cfg Config) (*Client, error) {
	ca, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, fmt.Errorf("kube: API server CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("kube: no certificates in %s", cfg.CAFile)
	}
	return &Client{
		Base: cfg.APIServer,
		HTTP: &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
		},
		Token: func() (string, error) {
			b, err := os.ReadFile(cfg.TokenFile)
			return strings.TrimSpace(string(b)), err
		},
	}, nil
}

// Do sends req with the service account's bearer token.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	token, err := c.Token()
	if err != nil {
		return nil, fmt.Errorf("kube: service account token: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return c.HTTP.Do(req)
}
