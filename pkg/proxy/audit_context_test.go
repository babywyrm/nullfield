package proxy

import "testing"

func TestHoldReasonClassDistinguishesTimeout(t *testing.T) {
	if got := holdReasonClass("timeout"); got != "hold_timeout" {
		t.Fatalf("holdReasonClass(timeout) = %q, want hold_timeout", got)
	}
	if got := holdReasonClass("ops-alice"); got != "hold_denied" {
		t.Fatalf("holdReasonClass(ops-alice) = %q, want hold_denied", got)
	}
}
