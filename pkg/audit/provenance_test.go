package audit

import (
	"encoding/json"
	"testing"
)

func TestProvenanceFieldsSerialize(t *testing.T) {
	e := Event{
		Type:              EventArbiterDecision,
		WorkloadPrincipal: "spiffe://cluster.local/ns/agents/sa/job-runner",
		Attester:          "mesh-spiffe",
		Assurance:         "ATTESTED",
		Transport:         "A",
		Counterfactual:    "DENY",
	}

	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	for key, want := range map[string]string{
		"workload_principal": "spiffe://cluster.local/ns/agents/sa/job-runner",
		"attester":           "mesh-spiffe",
		"assurance":          "ATTESTED",
		"transport":          "A",
		"counterfactual":     "DENY",
	} {
		if back[key] != want {
			t.Errorf("%s = %v, want %q", key, back[key], want)
		}
	}
}

func TestProvenanceFieldsAreOmittedWhenEmpty(t *testing.T) {
	// Proxy-mode events carry no mesh principal. Emitting empty strings would
	// give every existing audit consumer five new always-present keys.
	raw, err := json.Marshal(Event{Type: EventArbiterDecision})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var back map[string]any
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	for _, key := range []string{
		"workload_principal", "attester", "assurance", "transport", "counterfactual",
	} {
		if _, present := back[key]; present {
			t.Errorf("%s is present on an event that never set it", key)
		}
	}
}
