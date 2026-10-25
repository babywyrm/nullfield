package audit

import (
	"context"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestASpanCarriesTheRunAndProvenance(t *testing.T) {
	spans := tracetest.NewSpanRecorder()
	prev := tracer
	tracer = sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(spans)).Tracer("test")
	t.Cleanup(func() { tracer = prev })

	NewOTLPEmitter().Emit(context.Background(), Event{
		Type: EventCircuitTripped, RunID: "run-1", Action: "repos.delete",
		WorkloadPrincipal: "spiffe://cluster.local/ns/a/sa/b", Attester: "istio",
		Assurance: "MEDIUM", Transport: "B", Counterfactual: "enforced",
	})

	ended := spans.Ended()
	if len(ended) != 1 {
		t.Fatalf("%d spans, want 1", len(ended))
	}
	got := map[string]string{}
	for _, kv := range ended[0].Attributes() {
		got[string(kv.Key)] = kv.Value.Emit()
	}
	for k, want := range map[string]string{
		"nullfield.run_id":             "run-1",
		"nullfield.action":             "repos.delete",
		"nullfield.workload_principal": "spiffe://cluster.local/ns/a/sa/b",
		"nullfield.attester":           "istio",
		"nullfield.assurance":          "MEDIUM",
		"nullfield.transport":          "B",
		"nullfield.counterfactual":     "enforced",
	} {
		if got[k] != want {
			t.Errorf("%s = %q, want %q", k, got[k], want)
		}
	}
}
