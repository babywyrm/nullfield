package identity

import "testing"

func TestMeshAttesterParsesAFullSpiffeURI(t *testing.T) {
	att, ok := MeshAttester{}.Attest("spiffe://cluster.local/ns/agents/sa/job-runner")
	if !ok {
		t.Fatal("expected attestation to succeed")
	}
	if att.TrustDomain != "cluster.local" {
		t.Errorf("trust domain = %q, want cluster.local", att.TrustDomain)
	}
	if att.Namespace != "agents" {
		t.Errorf("namespace = %q, want agents", att.Namespace)
	}
	if att.ServiceAccount != "job-runner" {
		t.Errorf("service account = %q, want job-runner", att.ServiceAccount)
	}
	if att.Attester != AttesterMeshSPIFFE {
		t.Errorf("attester = %q, want %q", att.Attester, AttesterMeshSPIFFE)
	}
}

func TestMeshAttesterAcceptsAPrincipalWithoutTheScheme(t *testing.T) {
	// Istio strips spiffe:// on some paths. Accepting only one spelling would
	// mean identity failing based on how Envoy happened to fill the field.
	att, ok := MeshAttester{}.Attest("cluster.local/ns/agents/sa/job-runner")
	if !ok {
		t.Fatal("expected attestation to succeed without the scheme")
	}
	if att.Namespace != "agents" || att.ServiceAccount != "job-runner" {
		t.Errorf("got ns=%q sa=%q, want agents/job-runner", att.Namespace, att.ServiceAccount)
	}
}

func TestMeshAttesterPreservesThePrincipalVerbatim(t *testing.T) {
	const p = "spiffe://cluster.local/ns/agents/sa/job-runner"
	att, _ := MeshAttester{}.Attest(p)
	if att.Principal != p {
		t.Errorf("principal = %q, want it preserved as %q", att.Principal, p)
	}
}

func TestMeshAttesterFailsClosedOnUnusableInput(t *testing.T) {
	// A malformed principal must not yield a zero-valued Attestation that reads
	// downstream as a successfully identified workload.
	for _, in := range []string{
		"",
		"not-a-principal",
		"spiffe://cluster.local/ns/agents",
		"cluster.local/sa/job-runner",
		"spiffe://cluster.local/ns//sa/job-runner",
		"spiffe://cluster.local/ns/agents/sa/",
		"spiffe://cluster.local/xx/agents/sa/job-runner",
	} {
		if att, ok := (MeshAttester{}).Attest(in); ok {
			t.Errorf("Attest(%q) succeeded with %+v, want failure", in, att)
		}
	}
}

func TestMeshAttesterSatisfiesTheWorkloadAttesterInterface(t *testing.T) {
	// Pins the interface, so adding an IRSA attester later is an addition
	// rather than a redesign of every call site.
	var a WorkloadAttester = MeshAttester{}
	if a.Name() != AttesterMeshSPIFFE {
		t.Errorf("Name() = %q, want %q", a.Name(), AttesterMeshSPIFFE)
	}
}

func TestMeshHeaderAttesterSatisfiesTheWorkloadAttesterInterface(t *testing.T) {
	// Without this the type satisfies WorkloadAttester only by coincidence:
	// nothing in the codebase assigns it to the interface, so a signature drift
	// would compile cleanly and only surface when a second attester was wired
	// in — the exact case the interface exists to make easy.
	var a WorkloadAttester = MeshHeaderAttester{}
	if a.Name() != AttesterMeshHeader {
		t.Errorf("Name() = %q, want %q", a.Name(), AttesterMeshHeader)
	}
}

func TestMeshHeaderAttesterReportsADifferentSourceForTheSameIdentity(t *testing.T) {
	// The identity is identical; the binding is not. Reading a certificate
	// depends on TLS, reading a header depends on the mesh stripping a
	// client-supplied value first. An audit trail that cannot tell the two apart
	// cannot say how much the attribution is worth.
	const principal = "spiffe://cluster.local/ns/agents/sa/job-runner"

	fromCert, ok := (MeshAttester{}).Attest(principal)
	if !ok {
		t.Fatal("MeshAttester rejected a valid principal")
	}
	fromHeader, ok := (MeshHeaderAttester{}).Attest(principal)
	if !ok {
		t.Fatal("MeshHeaderAttester rejected a valid principal")
	}

	if fromHeader.Attester != AttesterMeshHeader {
		t.Errorf("attester = %q, want %q", fromHeader.Attester, AttesterMeshHeader)
	}
	if fromCert.Attester == fromHeader.Attester {
		t.Error("both attesters report the same source; the provenance record cannot distinguish them")
	}

	// Everything except the source must agree, or the two paths are not
	// describing the same workload.
	if fromHeader.Namespace != fromCert.Namespace ||
		fromHeader.ServiceAccount != fromCert.ServiceAccount ||
		fromHeader.TrustDomain != fromCert.TrustDomain ||
		fromHeader.Principal != fromCert.Principal {
		t.Errorf("header attestation %+v disagrees with certificate attestation %+v", fromHeader, fromCert)
	}
}

func TestMeshHeaderAttesterFailsClosedOnUnusableInput(t *testing.T) {
	// A header is attacker-reachable in a way a certificate is not: if the
	// stripping filter is ever missing, this is the code that sees whatever a
	// workload chose to send. It must not manufacture an identity from it.
	for _, in := range []string{
		"",
		"not-a-spiffe-id",
		"spiffe://cluster.local/ns/agents",
		"spiffe://cluster.local/ns//sa/job-runner",
		"spiffe://cluster.local/namespace/agents/sa/job-runner",
	} {
		if att, ok := (MeshHeaderAttester{}).Attest(in); ok {
			t.Errorf("Attest(%q) succeeded with %+v, want failure", in, att)
		}
	}
}

func TestThePeerPrincipalHeaderNameIsPinned(t *testing.T) {
	// The Lua filter in deploy/manifests/peer-principal-envoyfilter.yaml writes
	// this exact name, and nothing links the two at build time. Renaming the
	// constant alone would leave every mesh caller silently unattested.
	if PeerPrincipalHeader != "x-nullfield-peer-principal" {
		t.Errorf("PeerPrincipalHeader = %q; the EnvoyFilter writes x-nullfield-peer-principal", PeerPrincipalHeader)
	}
}
