package identity

import "strings"

// Attester names. The provenance record carries whichever one answered, because
// "we know who this workload is" means something materially different per
// source, and a decision trail that cannot tell them apart is not auditable.
const (
	AttesterMeshSPIFFE = "mesh-spiffe"
	AttesterMeshHeader = "mesh-header"
	AttesterNone       = "none"
)

// PeerPrincipalHeader is where a waypoint republishes the caller's identity.
//
// An ambient waypoint terminates HBONE upstream of the listener that runs
// ext_authz, so the inner stream carries no peer certificate and
// source.principal arrives empty. Istio puts the terminated connection's
// identity into Envoy filter state, and a Lua filter ordered before ext_authz
// copies it here. See deploy/manifests/peer-principal-envoyfilter.yaml.
const PeerPrincipalHeader = "x-nullfield-peer-principal"

// Attestation is a workload identity established by transport evidence rather
// than asserted by the caller.
//
// This is deliberately not an Identity. An Identity answers "whose authority is
// being exercised" and is derived from a token the workload presents; an
// Attestation answers "what is running" and is derived from something the
// workload cannot choose. Collapsing the two is how a confused deputy happens.
type Attestation struct {
	Principal      string `json:"principal"`
	TrustDomain    string `json:"trust_domain,omitempty"`
	Namespace      string `json:"namespace,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
	Attester       string `json:"attester"`
}

// WorkloadAttester establishes workload identity from transport evidence.
//
// This is an interface from the first commit rather than a later refactor
// because EKS brings IRSA and Pod Identity as independent attesters, and every
// decision path and provenance record depends on the shape. Where two attesters
// are available and agree, the corroboration is worth more than either alone.
type WorkloadAttester interface {
	Attest(principal string) (*Attestation, bool)
	Name() string
}

// MeshAttester derives identity from a service mesh peer principal, which Envoy
// populates from the peer certificate's URI SAN under mTLS. The workload cannot
// forge it, which is the entire reason to prefer it over a JWT claim.
type MeshAttester struct{}

// Name identifies this attester in the provenance record.
func (MeshAttester) Name() string { return AttesterMeshSPIFFE }

// Attest parses a SPIFFE principal of the form
// `spiffe://<trust-domain>/ns/<namespace>/sa/<service-account>`.
//
// The scheme is optional because Istio omits it on some paths, and accepting
// only one spelling would mean identity silently failing depending on how Envoy
// happened to populate the field.
//
// Returns false rather than a partially-filled Attestation: a zero value that
// reads as a successfully identified workload is worse than no answer at all.
func (MeshAttester) Attest(principal string) (*Attestation, bool) {
	if principal == "" {
		return nil, false
	}
	parts := strings.Split(strings.TrimPrefix(principal, "spiffe://"), "/")
	if len(parts) != 5 || parts[1] != "ns" || parts[3] != "sa" {
		return nil, false
	}
	if parts[0] == "" || parts[2] == "" || parts[4] == "" {
		return nil, false
	}
	return &Attestation{
		Principal:      principal,
		TrustDomain:    parts[0],
		Namespace:      parts[2],
		ServiceAccount: parts[4],
		Attester:       AttesterMeshSPIFFE,
	}, true
}

// MeshHeaderAttester derives identity from a principal a waypoint republished
// as a request header, for topologies where the peer certificate is not
// readable at the filter.
//
// It is a separate attester rather than a fallback inside MeshAttester because
// the trust chain genuinely differs. Reading a certificate depends on TLS.
// Reading a header depends on the mesh stripping any client-supplied value of
// the same name before writing its own — a property of the deployed filter, not
// of cryptography. Same identity, weaker binding, and the provenance record has
// to be able to say which one answered.
type MeshHeaderAttester struct{}

// Name identifies this attester in the provenance record.
func (MeshHeaderAttester) Name() string { return AttesterMeshHeader }

// Attest parses the same SPIFFE shape, and reports the different source.
func (MeshHeaderAttester) Attest(principal string) (*Attestation, bool) {
	att, ok := (MeshAttester{}).Attest(principal)
	if !ok {
		return nil, false
	}
	att.Attester = AttesterMeshHeader
	return att, true
}
