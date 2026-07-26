package extauthz

import (
	"context"
	"testing"

	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/policy"
)

const spiffeDefault = "spiffe://cluster.local/ns/zerotrust/sa/default"

func TestTheWaypointHeaderIsUsedWhenNoPeerCertificateReachesTheFilter(t *testing.T) {
	// The measured ambient case: source.principal empty because HBONE was
	// terminated upstream, identity republished as a header by the waypoint.
	got, err := Translate(checkRequest("", toolsCallBody, map[string]string{
		identity.PeerPrincipalHeader: spiffeDefault,
	}))
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if got.Attestation == nil {
		t.Fatal("attestation is nil; the waypoint header should have been used")
	}
	if got.Attestation.Attester != identity.AttesterMeshHeader {
		t.Errorf("attester = %q, want %q", got.Attestation.Attester, identity.AttesterMeshHeader)
	}
	if got.Attestation.Namespace != "zerotrust" || got.Attestation.ServiceAccount != "default" {
		t.Errorf("attestation = %+v, want zerotrust/default", got.Attestation)
	}
	if got.RawPrincipal != spiffeDefault {
		t.Errorf("raw principal = %q, want %q", got.RawPrincipal, spiffeDefault)
	}
}

func TestThePeerCertificateOutranksTheHeader(t *testing.T) {
	// Where both exist the certificate is the stronger binding, and the
	// provenance record must say so rather than reporting whichever was checked
	// last.
	const fromCert = "spiffe://cluster.local/ns/agents/sa/job-runner"
	got, err := Translate(checkRequest(fromCert, toolsCallBody, map[string]string{
		identity.PeerPrincipalHeader: spiffeDefault,
	}))
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if got.Attestation.Attester != identity.AttesterMeshSPIFFE {
		t.Errorf("attester = %q, want %q", got.Attestation.Attester, identity.AttesterMeshSPIFFE)
	}
	if got.Attestation.ServiceAccount != "job-runner" {
		t.Errorf("service account = %q, want the certificate's", got.Attestation.ServiceAccount)
	}
}

func TestATruncatedRequestIsStillAttributedToItsCaller(t *testing.T) {
	// Attribution matters most for exactly the requests that look like an
	// attempt to place arguments past the buffer boundary. Refusing to decide
	// must not also mean refusing to say who asked.
	req := checkRequest("", "{}", map[string]string{
		identity.PeerPrincipalHeader: spiffeDefault,
	})
	req.Attributes.Request.Http.Size = 20109

	s, eng, rec := newServer(ModeObserve, policy.Decision{Allowed: true})
	if _, err := s.Check(context.Background(), req); err != nil {
		t.Fatalf("Check: %v", err)
	}
	if eng.calls != 0 {
		t.Errorf("engine consulted %d times on a body we cannot read; want 0", eng.calls)
	}

	e := rec.events[0]
	if e.ReasonClass != "body_truncated" {
		t.Fatalf("reason_class = %q, want body_truncated", e.ReasonClass)
	}
	if e.WorkloadPrincipal != spiffeDefault {
		t.Errorf("principal = %q, want the caller recorded", e.WorkloadPrincipal)
	}
	if e.Attester != identity.AttesterMeshHeader {
		t.Errorf("attester = %q, want %q", e.Attester, identity.AttesterMeshHeader)
	}
	if e.Assurance != AssuranceAttested {
		t.Errorf("assurance = %q, want %q", e.Assurance, AssuranceAttested)
	}
}

func TestAGarbageHeaderDoesNotProduceAnAttestation(t *testing.T) {
	got, err := Translate(checkRequest("", toolsCallBody, map[string]string{
		identity.PeerPrincipalHeader: "not-a-spiffe-id",
	}))
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if got.Attestation != nil {
		t.Errorf("attestation = %+v, want nil for an unparseable header", got.Attestation)
	}
	if got.RawPrincipal != "not-a-spiffe-id" {
		t.Errorf("raw principal = %q, want the value recorded for diagnosis", got.RawPrincipal)
	}
}

func TestAHeaderAttestedCallReachesAttestedAssurance(t *testing.T) {
	s, _, rec := newServer(ModeObserve, policy.Decision{Allowed: false, Reason: "no rule"})

	if _, err := s.Check(context.Background(), checkRequest("", toolsCallBody, map[string]string{
		identity.PeerPrincipalHeader: spiffeDefault,
	})); err != nil {
		t.Fatalf("Check: %v", err)
	}

	e := rec.events[0]
	if e.WorkloadPrincipal != spiffeDefault {
		t.Errorf("principal = %q, want %q", e.WorkloadPrincipal, spiffeDefault)
	}
	if e.Attester != identity.AttesterMeshHeader {
		t.Errorf("attester = %q, want %q", e.Attester, identity.AttesterMeshHeader)
	}
	if e.Assurance != AssuranceAttested {
		t.Errorf("assurance = %q, want %q", e.Assurance, AssuranceAttested)
	}
	if e.Counterfactual != "DENY" {
		t.Errorf("counterfactual = %q, want DENY", e.Counterfactual)
	}
}
