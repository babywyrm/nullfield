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
