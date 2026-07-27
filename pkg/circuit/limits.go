package circuit

import "time"

// ResolveLimits decides the effective breaker limits from a policy's
// circuitBreaker block and the environment defaults.
//
// A policy that declares a limit wins; a policy that says nothing leaves the
// environment in place. Silence has to mean "unspecified" rather than "zero",
// because most policies omit the block entirely and every deployed
// configuration sets the environment variables.
//
// Non-positive values are treated as unspecified. A negative limit is a typo
// rather than an instruction to disable the breaker, and falling back to the
// environment is the safer reading of one.
//
// The third return value reports whether the policy contributed anything, so
// the caller can log which source won. Operators otherwise have no way to tell
// why a limit is what it is.
func ResolveLimits(policyCalls int, policyDuration time.Duration, envCalls int, envDuration time.Duration) (int, time.Duration, bool) {
	calls, duration := envCalls, envDuration
	fromPolicy := false

	if policyCalls > 0 {
		calls = policyCalls
		fromPolicy = true
	}
	if policyDuration > 0 {
		duration = policyDuration
		fromPolicy = true
	}

	return calls, duration, fromPolicy
}
