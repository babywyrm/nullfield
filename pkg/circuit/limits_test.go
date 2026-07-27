package circuit

import (
	"testing"
	"time"
)

func TestResolveLimits(t *testing.T) {
	const envCalls = 100
	envDuration := 5 * time.Minute

	tests := []struct {
		name           string
		policyCalls    int
		policyDur      time.Duration
		wantCalls      int
		wantDur        time.Duration
		wantFromPolicy bool
	}{
		{
			// The whole point of the change. Policies have carried a
			// circuitBreaker block since the beginning and nothing read it.
			name:        "a policy that declares limits wins over the environment",
			policyCalls: 20, policyDur: time.Minute,
			wantCalls: 20, wantDur: time.Minute,
			wantFromPolicy: true,
		},
		{
			// The regression that matters: every existing deployment sets the
			// env vars and most policies say nothing, so silence must not be
			// read as "zero calls allowed".
			name:        "a policy that says nothing leaves the environment alone",
			policyCalls: 0, policyDur: 0,
			wantCalls: envCalls, wantDur: envDuration,
			wantFromPolicy: false,
		},
		{
			name:        "the two fields are independent",
			policyCalls: 20, policyDur: 0,
			wantCalls: 20, wantDur: envDuration,
			wantFromPolicy: true,
		},
		{
			name:        "and independent the other way",
			policyCalls: 0, policyDur: time.Minute,
			wantCalls: envCalls, wantDur: time.Minute,
			wantFromPolicy: true,
		},
		{
			// A negative is a typo, not an instruction to disable the breaker.
			// Falling back is safer than trusting it.
			name:        "a negative limit is ignored rather than obeyed",
			policyCalls: -1, policyDur: -time.Second,
			wantCalls: envCalls, wantDur: envDuration,
			wantFromPolicy: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls, dur, fromPolicy := ResolveLimits(tc.policyCalls, tc.policyDur, envCalls, envDuration)
			if calls != tc.wantCalls {
				t.Errorf("calls = %d, want %d", calls, tc.wantCalls)
			}
			if dur != tc.wantDur {
				t.Errorf("duration = %v, want %v", dur, tc.wantDur)
			}
			if fromPolicy != tc.wantFromPolicy {
				t.Errorf("fromPolicy = %v, want %v", fromPolicy, tc.wantFromPolicy)
			}
		})
	}
}
