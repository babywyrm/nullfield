package extauthz

import (
	"context"
	"testing"

	"github.com/babywyrm/nullfield/pkg/policy"
)

func TestAnUnparseablePrincipalIsStillRecorded(t *testing.T) {
	// "assurance: NONE" with an empty principal field is ambiguous between no
	// principal arriving, one arriving in a shape we do not parse, and a caller
	// genuinely outside the mesh. Recording the raw value separates them.
	const odd = "some-principal-shape-we-do-not-parse"
	s, _, rec := newServer(ModeObserve, policy.Decision{Allowed: true})

	if _, err := s.Check(context.Background(),
		checkRequest(odd, toolsCallBody, map[string]string{})); err != nil {
		t.Fatalf("Check: %v", err)
	}

	e := rec.events[0]
	if e.WorkloadPrincipal != odd {
		t.Errorf("principal = %q, want the raw value %q recorded", e.WorkloadPrincipal, odd)
	}
	if e.Attester != "none" {
		t.Errorf("attester = %q, want none for something we could not parse", e.Attester)
	}
	if e.Assurance != AssuranceNone {
		t.Errorf("assurance = %q, want %q", e.Assurance, AssuranceNone)
	}
}

func TestAnAttestedPrincipalKeepsBothTheValueAndTheAttester(t *testing.T) {
	s, _, rec := newServer(ModeObserve, policy.Decision{Allowed: true})

	if _, err := s.Check(context.Background(),
		checkRequest(spiffeRunner, toolsCallBody, map[string]string{})); err != nil {
		t.Fatalf("Check: %v", err)
	}

	e := rec.events[0]
	if e.WorkloadPrincipal != spiffeRunner {
		t.Errorf("principal = %q, want %q", e.WorkloadPrincipal, spiffeRunner)
	}
	if e.Attester != "mesh-spiffe" {
		t.Errorf("attester = %q, want mesh-spiffe", e.Attester)
	}
	if e.Assurance != AssuranceAttested {
		t.Errorf("assurance = %q, want %q", e.Assurance, AssuranceAttested)
	}
}
