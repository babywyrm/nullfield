package kube

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// server is a TLS server standing in for the API server, with its CA and a
// token file written where the Config points.
func server(t *testing.T, h http.HandlerFunc) Config {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	cfg := Config{APIServer: srv.URL, CAFile: filepath.Join(dir, "ca.crt"), TokenFile: filepath.Join(dir, "token")}
	write(t, cfg.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	write(t, cfg.TokenFile, []byte("token-1\n"))
	return cfg
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func get(t *testing.T, c *Client) error {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, c.Base+"/api", nil)
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
	}
	return err
}

func TestAClientSendsTheCurrentToken(t *testing.T) {
	var auth string
	cfg := server(t, func(_ http.ResponseWriter, r *http.Request) { auth = r.Header.Get("Authorization") })
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, c); err != nil || auth != "Bearer token-1" {
		t.Fatalf("err = %v, auth = %q", err, auth)
	}
	// The projected token rotates under a running process.
	write(t, cfg.TokenFile, []byte("token-2"))
	if err := get(t, c); err != nil || auth != "Bearer token-2" {
		t.Fatalf("rotated token not used: err = %v, auth = %q", err, auth)
	}
}

func TestAClientRefusesAServerTheCADoesNotVouchFor(t *testing.T) {
	cfg := server(t, func(http.ResponseWriter, *http.Request) {})
	// httptest servers share one certificate, so the other CA is generated.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other"},
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	write(t, cfg.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := get(t, c); err == nil {
		t.Fatal("connected to a server the CA does not vouch for")
	}
}

func TestAClientNeedsACA(t *testing.T) {
	cfg := server(t, func(http.ResponseWriter, *http.Request) {})
	write(t, cfg.CAFile, []byte("not a certificate"))
	if _, err := New(cfg); err == nil {
		t.Fatal("built a client with no CA")
	}
	cfg.CAFile = filepath.Join(t.TempDir(), "missing")
	if _, err := New(cfg); err == nil {
		t.Fatal("built a client with a missing CA")
	}
}

func TestInClusterNeedsTheServiceEnvironment(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := InCluster(); err == nil {
		t.Fatal("in-cluster config built off-cluster")
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	cfg, err := InCluster()
	if err != nil || cfg.APIServer != "https://10.0.0.1:443" {
		t.Fatalf("cfg = %+v, err = %v", cfg, err)
	}
}
