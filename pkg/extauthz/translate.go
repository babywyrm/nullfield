// Package extauthz adapts Envoy's external authorization protocol onto
// nullfield's existing decision core. It makes the same calls the HTTP proxy
// makes; only the transport differs.
package extauthz

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/babywyrm/nullfield/pkg/identity"
	"github.com/babywyrm/nullfield/pkg/mcp"
	"github.com/babywyrm/nullfield/pkg/policy"
)

// Translated is everything the decision core needs, extracted from one
// CheckRequest.
type Translated struct {
	Policy      policy.Request
	Attestation *identity.Attestation
	Headers     identity.MapHeaders

	// RawPrincipal is whatever the mesh put in source.principal, recorded even
	// when it could not be attested.
	//
	// Without it, "assurance: NONE" is indistinguishable between three very
	// different situations: no principal arrived at all, one arrived in a shape
	// we do not parse, or the caller is genuinely outside the mesh. That is the
	// first question anyone debugging a rollout asks, and it should not require
	// attaching a debugger to answer.
	RawPrincipal string
}

// PartialBodyHeader is Envoy's own statement about whether it delivered the
// whole body. Observed on live waypoint traffic; it is the authoritative signal.
const PartialBodyHeader = "x-envoy-auth-partial-body"

// BodyTruncated reports whether Envoy delivered less body than the request
// actually carried.
//
// `includeRequestBodyInCheck` buffers up to maxRequestBytes, and with
// allowPartialMessage: true Envoy forwards whatever fit and lets the check
// proceed. Authorizing on a body the arbiter cannot fully see is a bypass
// primitive: put the dangerous arguments past the boundary and the gate approves
// what it never read. Callers must fail closed when this returns true.
//
// Three signals, in descending order of authority:
//
//  1. x-envoy-auth-partial-body, which is Envoy telling us directly.
//  2. The size attribute, when set. It is -1 when unknown and 0 when simply
//     unpopulated, so only a positive value means anything.
//  3. content-length.
//
// No signal at all is not treated as truncation: chunked requests carry no
// length, and denying every streamed request would be its own outage.
func BodyTruncated(declaredSize int64, headers map[string]string, body string) bool {
	if partial, ok := headers[PartialBodyHeader]; ok {
		return partial == "true"
	}
	if declaredSize > 0 {
		return declaredSize > int64(len(body))
	}
	raw, ok := headers["content-length"]
	if !ok {
		return false
	}
	declared, err := strconv.Atoi(raw)
	if err != nil {
		return false
	}
	return declared > len(body)
}

// bodyOf returns the request body from whichever field Envoy populated.
//
// Envoy writes RawBody instead of Body when the filter sets pack_as_bytes.
// Reading only Body would make every request under that configuration look
// bodiless, so MCP detection would silently stop working and every tools/call
// would be classified as ordinary wire traffic — a quiet, total loss of
// coverage rather than a visible failure.
func bodyOf(attrs *authv3.AttributeContext_HttpRequest) string {
	if b := attrs.GetBody(); b != "" {
		return b
	}
	return string(attrs.GetRawBody())
}

// Translate converts an Envoy CheckRequest into a policy request.
//
// A truncated body is an error rather than a partial result, because the caller
// must fail closed: past the buffer boundary is exactly where something worth
// denying would be placed.
func Translate(req *authv3.CheckRequest) (*Translated, error) {
	attrs := req.GetAttributes().GetRequest().GetHttp()
	if attrs == nil {
		return nil, fmt.Errorf("check request carries no HTTP attributes")
	}

	out := &Translated{
		Headers: identity.MapHeaders(attrs.GetHeaders()),
		Policy: policy.Request{
			Target:    attrs.GetHost(),
			Operation: strings.TrimSpace(attrs.GetMethod() + " " + attrs.GetPath()),
			Transport: policy.TransportWireAPI,
		},
	}

	// Prefer the peer certificate. Sidecar topologies terminate TLS on the
	// listener that runs this filter, so it is available and is the stronger
	// binding.
	out.RawPrincipal = req.GetAttributes().GetSource().GetPrincipal()
	if out.RawPrincipal != "" {
		if att, ok := (identity.MeshAttester{}).Attest(out.RawPrincipal); ok {
			out.Attestation = att
		}
	}

	// Fall back to the header a waypoint republished. An ambient waypoint
	// terminates HBONE upstream of this listener, so source.principal is empty
	// there however healthy the mesh is.
	if out.Attestation == nil {
		if injected := out.Headers.Get(identity.PeerPrincipalHeader); injected != "" {
			out.RawPrincipal = injected
			if att, ok := (identity.MeshHeaderAttester{}).Attest(injected); ok {
				out.Attestation = att
			}
		}
	}

	// Truncation is checked after attestation, deliberately. Identity does not
	// come from the body, and bailing first would leave the audit trail unable
	// to say who sent an oversized request — attribution matters most for
	// exactly the requests that look like an attempt to get past the buffer.
	// The Translated is returned alongside the error so the caller can record
	// provenance for something it is refusing to decide.
	body := bodyOf(attrs)
	if BodyTruncated(attrs.GetSize(), attrs.GetHeaders(), body) {
		return out, fmt.Errorf(
			"request body truncated by the ext_authz buffer (declared %d bytes, received %d); refusing to decide on partial data",
			attrs.GetSize(), len(body))
	}

	// MCP rides on JSON-RPC and is not distinguishable by URL, so detection is
	// by parse rather than by path.
	if tc, method, ok := parseMCPToolsCall(body); ok {
		out.Policy.Transport = policy.TransportMCP
		out.Policy.Method = method
		out.Policy.ToolName = tc.Name
		out.Policy.Arguments = tc.Arguments
	}

	return out, nil
}

// parseMCPToolsCall reports whether the body is an MCP tools/call and returns
// its parameters. A body that is not JSON-RPC is not an error here — it is other
// traffic the arbiter also covers.
func parseMCPToolsCall(body string) (*mcp.ToolsCallParams, string, bool) {
	if body == "" {
		return nil, "", false
	}
	var envelope mcp.JSONRPCRequest
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return nil, "", false
	}
	if envelope.Method != mcp.MethodToolsCall {
		return nil, envelope.Method, false
	}
	tc, err := mcp.ParseToolsCall(&envelope)
	if err != nil {
		return nil, envelope.Method, false
	}
	return tc, envelope.Method, true
}
