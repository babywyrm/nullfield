// Package signals delivers selected decision events to whoever acts on them,
// such as the controller that owns a run's pod. Delivery is asynchronous and
// never delays a decision.
package signals

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/babywyrm/nullfield/pkg/audit"
	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/kube"
)

// Deliver sends one event. An error is retried.
type Deliver func(ctx context.Context, e audit.Event) error

const (
	queueSize = 256
	retries   = 4
)

// Sink is an audit.Emitter that delivers the event types it was given.
type Sink struct {
	name    string
	types   map[audit.EventType]bool
	queue   chan audit.Event
	deliver Deliver
	logger  *slog.Logger
	backoff time.Duration
}

// NewSink starts a sink with one delivery worker.
func NewSink(name string, types []audit.EventType, deliver Deliver, logger *slog.Logger) *Sink {
	s := &Sink{name: name, types: map[audit.EventType]bool{}, queue: make(chan audit.Event, queueSize),
		deliver: deliver, logger: logger, backoff: time.Second}
	for _, t := range types {
		s.types[t] = true
	}
	go s.run()
	return s
}

// Emit queues an event of a selected type.
//
// ponytail: a full queue drops the event rather than blocking a decision, and
// a process exit loses what is queued. A receiver that must not miss a trip
// should also reconcile from the audit stream.
func (s *Sink) Emit(_ context.Context, e audit.Event) {
	if !s.types[e.Type] {
		return
	}
	select {
	case s.queue <- e:
	default:
		s.logger.Error("signal dropped: queue full", "sink", s.name, "type", e.Type, "run_id", e.RunID)
	}
}

func (s *Sink) run() {
	for e := range s.queue {
		for attempt := 0; ; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := s.deliver(ctx, e)
			cancel()
			if err == nil {
				break
			}
			if attempt == retries {
				s.logger.Error("signal not delivered", "sink", s.name, "type", e.Type, "run_id", e.RunID, "error", err)
				break
			}
			time.Sleep(s.backoff << attempt)
		}
	}
}

// Webhook posts events as JSON, signed so the receiver can tell them from a
// forgery: X-Nullfield-Signature is "sha256=" and the hex HMAC-SHA256 of
// X-Nullfield-Timestamp, ".", and the body. Receivers should reject stale
// timestamps to stop replays.
type Webhook struct {
	url    string
	secret []byte
	client *http.Client
}

// NewWebhook refuses an unsigned webhook: a signal that ends a run must not be
// forgeable by anything that can reach the receiver.
func NewWebhook(target string, secret []byte) (*Webhook, error) {
	if len(secret) == 0 {
		return nil, errors.New("signals: a webhook needs a signing secret")
	}
	if u, err := url.Parse(target); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("signals: webhook URL %q must be http or https with a host", target)
	}
	return &Webhook{url: target, secret: secret, client: &http.Client{Timeout: 10 * time.Second}}, nil
}

// Deliver posts one event.
func (w *Webhook) Deliver(ctx context.Context, e audit.Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, w.secret)
	mac.Write([]byte(ts + "."))
	mac.Write(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Nullfield-Timestamp", ts)
	req.Header.Set("X-Nullfield-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	return send(w.client, req)
}

// KubeEvents records events.k8s.io Events on the ServiceAccount of the
// workload a decision was about, annotated with the run, so the controller
// that owns the run can watch for them.
type KubeEvents struct {
	api      *kube.Client
	instance string
}

// NewKubeEvents calls the API server cfg names, verified against its CA.
func NewKubeEvents(cfg kube.Config) (*KubeEvents, error) {
	api, err := kube.New(cfg)
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	return &KubeEvents{api: api, instance: host}, nil
}

// Deliver records one event. An event about no attested workload has nothing
// to attach to and is skipped.
func (k *KubeEvents) Deliver(ctx context.Context, e audit.Event) error {
	att, ok := identity.MeshAttester{}.Attest(e.WorkloadPrincipal)
	if !ok || e.Attester == "" {
		return nil
	}
	note := e.Reason
	if e.RunID != "" {
		note = "run " + e.RunID + ": " + note
	}
	if len(note) > 1024 {
		note = note[:1024]
	}
	annotations := map[string]string{"nullfield.io/workload": e.WorkloadPrincipal}
	for k, v := range map[string]string{"nullfield.io/run-id": e.RunID, "nullfield.io/action": e.Action,
		"nullfield.io/reason-class": e.ReasonClass, "nullfield.io/target": e.Target} {
		if v != "" {
			annotations[k] = v
		}
	}
	body, err := json.Marshal(map[string]any{
		"apiVersion": "events.k8s.io/v1",
		"kind":       "Event",
		"metadata": map[string]any{
			"generateName": "nullfield-", "namespace": att.Namespace, "annotations": annotations,
		},
		"eventTime":           time.Now().UTC().Format("2006-01-02T15:04:05.000000Z07:00"),
		"reportingController": "nullfield.io/extauthz",
		"reportingInstance":   k.instance,
		"action":              "Decide",
		"reason":              reason(e.Type),
		"type":                "Warning",
		"note":                note,
		"regarding": map[string]string{
			"apiVersion": "v1", "kind": "ServiceAccount", "namespace": att.Namespace, "name": att.ServiceAccount,
		},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		k.api.Base+"/apis/events.k8s.io/v1/namespaces/"+url.PathEscape(att.Namespace)+"/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return check(k.api.Do(req))
}

// reason turns circuit.tripped into CircuitTripped.
func reason(t audit.EventType) string {
	var b strings.Builder
	for _, part := range strings.FieldsFunc(string(t), func(r rune) bool { return r == '.' || r == '_' }) {
		b.WriteString(strings.ToUpper(part[:1]) + part[1:])
	}
	return b.String()
}

func send(c *http.Client, req *http.Request) error {
	return check(c.Do(req))
}

func check(resp *http.Response, err error) error {
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: %s: %s", resp.Request.Method, resp.Request.URL.Path, resp.Status, bytes.TrimSpace(msg))
	}
	return nil
}

// Options says what a binary can signal.
type Options struct {
	// Emits lists the event types the binary produces; NULLFIELD_SIGNAL_EVENTS
	// may select only from these.
	Emits []audit.EventType
	// KubeEvents is whether the binary may record Kubernetes Events. Only one
	// with an attested caller and its own service account should: Events
	// carry no creator, so a sidecar sharing the agent's account would let
	// the agent forge them.
	KubeEvents bool
}

// FromEnv builds the channels the environment asks for. A channel asked for
// and not buildable, or an event type the binary never emits, is an error
// rather than a signal that never comes.
func FromEnv(logger *slog.Logger, opts Options) ([]audit.Emitter, error) {
	emits := map[audit.EventType]bool{}
	for _, t := range opts.Emits {
		emits[t] = true
	}
	types := []audit.EventType{audit.EventCircuitTripped}
	if v := os.Getenv("NULLFIELD_SIGNAL_EVENTS"); v != "" {
		types = nil
		for _, t := range strings.Split(v, ",") {
			t := audit.EventType(strings.TrimSpace(t))
			if !emits[t] {
				return nil, fmt.Errorf("NULLFIELD_SIGNAL_EVENTS: %q is not an event this binary emits", t)
			}
			types = append(types, t)
		}
	}

	var sinks []audit.Emitter
	if os.Getenv("NULLFIELD_SIGNAL_KUBE_EVENTS") == "true" {
		if !opts.KubeEvents {
			return nil, errors.New("NULLFIELD_SIGNAL_KUBE_EVENTS: not supported here; it shares a service account with the workload, which could forge Events. Use the webhook")
		}
		cfg, err := kube.InCluster()
		if err != nil {
			return nil, err
		}
		k, err := NewKubeEvents(cfg)
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, NewSink("kube-events", types, k.Deliver, logger))
		logger.Info("signalling as Kubernetes Events", "types", types)
	}
	if u := os.Getenv("NULLFIELD_SIGNAL_WEBHOOK_URL"); u != "" {
		secret, err := os.ReadFile(os.Getenv("NULLFIELD_SIGNAL_WEBHOOK_SECRET_FILE"))
		if err != nil {
			return nil, fmt.Errorf("NULLFIELD_SIGNAL_WEBHOOK_SECRET_FILE: %w", err)
		}
		w, err := NewWebhook(u, bytes.TrimSpace(secret))
		if err != nil {
			return nil, err
		}
		sinks = append(sinks, NewSink("webhook", types, w.Deliver, logger))
		logger.Info("signalling by webhook", "types", types)
	}
	return sinks, nil
}
