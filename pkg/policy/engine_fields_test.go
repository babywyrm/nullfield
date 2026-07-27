package policy

import "testing"

// The fields below were added for the mesh arbiter. They are additive, and the
// guarantee that makes that safe is not obvious from reading the struct: every
// pre-existing construction site sets none of them, so if any of them defaulted
// to something a rule could act on, code nobody edited would change behaviour.
// These tests pin the guarantee rather than the syntax.

func TestARequestBuiltTheOldWayCarriesNoTransportTargetOrOperation(t *testing.T) {
	req := Request{Method: "tools/call", ToolName: "echo"}

	if req.Transport != "" {
		t.Errorf("Transport = %q, want empty; a default would silently reclassify existing traffic", req.Transport)
	}
	if req.Target != "" {
		t.Errorf("Target = %q, want empty", req.Target)
	}
	if req.Operation != "" {
		t.Errorf("Operation = %q, want empty", req.Operation)
	}
}

func TestAnAppliedDecisionCarriesNoCounterfactual(t *testing.T) {
	// A counterfactual means "this is what would have happened". Present on a
	// decision that was actually applied, it would read as though enforcement
	// had been shadowed when it had not.
	d := Decision{Allowed: true, Reason: "matched rule"}

	if d.Counterfactual != "" {
		t.Errorf("Counterfactual = %q, want empty on an applied decision", d.Counterfactual)
	}
}

func TestTransportConstantsMatchTheDocumentedTaxonomy(t *testing.T) {
	// These letters appear in audit events, in policy labels, and in the spec.
	// Renumbering them would silently reclassify historical evidence, so the
	// mapping is pinned here rather than left to whoever edits the block next.
	for _, tc := range []struct {
		got  string
		want string
		name string
	}{
		{TransportMCP, "A", "MCP"},
		{TransportWireAPI, "B", "wire API"},
		{TransportInProcessSDK, "C", "in-process SDK"},
		{TransportSubprocess, "D", "subprocess"},
		{TransportModelFunctions, "E", "model functions"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s transport = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

func TestTransportConstantsAreDistinct(t *testing.T) {
	seen := map[string]string{}
	for name, value := range map[string]string{
		"MCP":            TransportMCP,
		"WireAPI":        TransportWireAPI,
		"InProcessSDK":   TransportInProcessSDK,
		"Subprocess":     TransportSubprocess,
		"ModelFunctions": TransportModelFunctions,
	} {
		if prior, dup := seen[value]; dup {
			t.Errorf("%s and %s share transport %q; decisions would be indistinguishable", prior, name, value)
		}
		seen[value] = name
	}
}
