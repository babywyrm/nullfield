package signals

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/kube"
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
// token file written where kube.Config points.
func apiServer(t *testing.T, h http.HandlerFunc) kube.Config {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	cfg := kube.Config{APIServer: srv.URL, CAFile: filepath.Join(dir, "ca.crt"), TokenFile: filepath.Join(dir, "token")}
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

func TestSignalsAskedForAndNotBuildableRefuseToStart(t *testing.T) {
	both := Options{Emits: []audit.EventType{audit.EventCircuitTripped, audit.EventArbiterDecision}, KubeEvents: true}
	for name, tc := range map[string]struct {
		opts Options
		env  map[string]string
	}{
		"a type this binary never emits": {both, map[string]string{"NULLFIELD_SIGNAL_EVENTS": "circuit.trip"}},
		"a webhook with no secret":       {both, map[string]string{"NULLFIELD_SIGNAL_WEBHOOK_URL": "https://controller/hook"}},
		"Kubernetes Events off-cluster":  {both, map[string]string{"NULLFIELD_SIGNAL_KUBE_EVENTS": "true", "KUBERNETES_SERVICE_HOST": ""}},
		"Kubernetes Events where the workload could forge them": {
			Options{Emits: both.Emits}, map[string]string{"NULLFIELD_SIGNAL_KUBE_EVENTS": "true"}},
	} {
		t.Run(name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			if _, err := FromEnv(quiet, tc.opts); err == nil {
				t.Fatal("started")
			}
		})
	}

	t.Run("none asked for", func(t *testing.T) {
		if sinks, err := FromEnv(quiet, both); err != nil || len(sinks) != 0 {
			t.Fatalf("sinks = %d, err = %v", len(sinks), err)
		}
	})
	t.Run("a signed webhook", func(t *testing.T) {
		secret := filepath.Join(t.TempDir(), "secret")
		if err := os.WriteFile(secret, []byte("k\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("NULLFIELD_SIGNAL_WEBHOOK_URL", "https://controller/hook")
		t.Setenv("NULLFIELD_SIGNAL_WEBHOOK_SECRET_FILE", secret)
		t.Setenv("NULLFIELD_SIGNAL_EVENTS", "circuit.tripped, arbiter.decision")
		if sinks, err := FromEnv(quiet, both); err != nil || len(sinks) != 1 {
			t.Fatalf("sinks = %d, err = %v", len(sinks), err)
		}
	})
}
