package signals

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/babywyrm/nullfield/pkg/audit"
)

const runner = "spiffe://cluster.local/ns/agents/sa/job-runner"

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

func trip() audit.Event {
	return audit.Event{Type: audit.EventCircuitTripped, RunID: "run-1", Gate: "circuit",
		ReasonClass: "circuit_open", Reason: "session limit reached",
		WorkloadPrincipal: runner, Attester: "mesh-spiffe"}
}

func TestASinkDeliversOnlyItsTypesAndRetries(t *testing.T) {
	got := make(chan audit.Event, 4)
	attempts := 0
	s := NewSink("test", []audit.EventType{audit.EventCircuitTripped}, func(_ context.Context, e audit.Event) error {
		attempts++
		if attempts < 3 {
			return errors.New("receiver down")
		}
		got <- e
		return nil
	}, quiet)
	s.backoff = time.Millisecond

	s.Emit(context.Background(), audit.Event{Type: audit.EventArbiterDecision})
	s.Emit(context.Background(), trip())

	select {
	case e := <-got:
		if e.RunID != "run-1" {
			t.Fatalf("delivered %+v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the trip was not delivered after retries")
	}
	if attempts != 3 {
		t.Fatalf("%d attempts, want 3: the decision event must not be delivered", attempts)
	}
}

func TestAWebhookIsSignedOverTimestampAndBody(t *testing.T) {
	secret := []byte("s3cret")
	var verified bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(r.Header.Get("X-Nullfield-Timestamp") + "."))
		mac.Write(body)
		want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		verified = hmac.Equal([]byte(r.Header.Get("X-Nullfield-Signature")), []byte(want))
		var e audit.Event
		if json.Unmarshal(body, &e) != nil || e.RunID != "run-1" {
			verified = false
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	w, err := NewWebhook(srv.URL, secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Deliver(context.Background(), trip()); err != nil {
		t.Fatal(err)
	}
	if !verified {
		t.Fatal("the receiver could not verify the signature")
	}
}

func TestAWebhookFailureIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	w, _ := NewWebhook(srv.URL, []byte("k"))
	if err := w.Deliver(context.Background(), trip()); err == nil {
		t.Fatal("a 502 was treated as delivered")
	}
}

func TestAnUnsignedWebhookRefusesToStart(t *testing.T) {
	if _, err := NewWebhook("https://controller.example/hook", nil); err == nil {
		t.Fatal("a webhook with no secret was accepted")
	}
	if _, err := NewWebhook("controller/hook", []byte("k")); err == nil {
		t.Fatal("a URL with no scheme was accepted")
	}
}

// apiServer is a TLS server standing in for the API server, with its CA and a
// token file written where KubeConfig points.
func apiServer(t *testing.T, h http.HandlerFunc) KubeConfig {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	cfg := KubeConfig{APIServer: srv.URL, CAFile: filepath.Join(dir, "ca.crt"), TokenFile: filepath.Join(dir, "token")}
	if err := os.WriteFile(cfg.CAFile, ca, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.TokenFile, []byte("token-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestAKubernetesEventIsAttachedToTheRunsServiceAccount(t *testing.T) {
	type event struct {
		Metadata struct {
			Namespace   string            `json:"namespace"`
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Reason    string `json:"reason"`
		Type      string `json:"type"`
		Note      string `json:"note"`
		Regarding struct {
			Kind, Namespace, Name string
		} `json:"regarding"`
	}
	var got event
	var path, auth string
	cfg := apiServer(t, func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
	})
	k, err := NewKubeEvents(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Deliver(context.Background(), trip()); err != nil {
		t.Fatal(err)
	}
	if path != "/apis/events.k8s.io/v1/namespaces/agents/events" || auth != "Bearer token-1" {
		t.Fatalf("POST %s with %q", path, auth)
	}
	if got.Regarding.Kind != "ServiceAccount" || got.Regarding.Namespace != "agents" || got.Regarding.Name != "job-runner" {
		t.Fatalf("regarding = %+v", got.Regarding)
	}
	if got.Reason != "CircuitTripped" || got.Type != "Warning" || got.Metadata.Annotations["nullfield.io/run-id"] != "run-1" {
		t.Fatalf("event = %+v", got)
	}

	// The projected token rotates; each delivery reads the current one.
	if err := os.WriteFile(cfg.TokenFile, []byte("token-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = k.Deliver(context.Background(), trip())
	if auth != "Bearer token-2" {
		t.Fatalf("rotated token not used: %q", auth)
	}
}

func TestAKubernetesEventIsNotSentToAnUntrustedServer(t *testing.T) {
	cfg := apiServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusCreated) })
	// httptest servers share one certificate, so the other CA is generated.
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "other"},
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CAFile = filepath.Join(t.TempDir(), "other.crt")
	if err := os.WriteFile(cfg.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := NewKubeEvents(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Deliver(context.Background(), trip()); err == nil {
		t.Fatal("delivered to a server the CA does not vouch for")
	}
}

func TestAnEventWithNoAttestedWorkloadHasNothingToAttachTo(t *testing.T) {
	called := false
	cfg := apiServer(t, func(w http.ResponseWriter, _ *http.Request) { called = true })
	k, _ := NewKubeEvents(cfg)
	// A principal the mesh presented but nobody vouched for names no one.
	unattested := trip()
	unattested.Attester = ""
	unparsed := trip()
	unparsed.WorkloadPrincipal = "not-a-spiffe-id"
	for _, e := range []audit.Event{unattested, unparsed} {
		if err := k.Deliver(context.Background(), e); err != nil || called {
			t.Fatalf("%q: err = %v, called = %v; want skipped", e.WorkloadPrincipal, err, called)
		}
	}
}
