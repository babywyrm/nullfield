# Demo 03 — Anomaly Detection

Policy answers "may you." These three answer something else: is this the same
caller, is this the same token, and is this a normal rate. They catch a caller
misbehaving rather than a caller asking for something it was never granted.

```bash
demos/03-anomaly-detection/test.sh
```

Tier 1, Docker Compose plus openssl and python3. Gated in CI. The demo mints
its own throwaway keypair and tokens; it does not borrow demo 02's.

## Session binding

The first identity to use a session id owns it. A second one is refused —
`-32001`, an identity failure rather than a policy denial.

Worth being precise about what is being caught. Mallory's token in this demo is
completely valid: correctly signed, unexpired, right issuer, right audience. It
is refused for being the wrong principal on someone else's session. That is a
stolen-session-id defence, not a bad-token defence, and demo 02 covers the
other one.

## Replay detection

Keyed on the `jti` claim. A token whose `jti` has been seen is refused.

**This makes tokens single-use.** With `detectReplay: true`, a client cannot
reuse one token across calls — it needs a fresh one per request, and the demo's
token generator mints them that way. That is the feature working as designed,
and also why it is not on by default. Turning it on against a client that
caches its token will refuse every call after the first.

### The blind spot

`ReplayDetector.Check` returns nil when `jti` is empty:

```go
// Empty JTIs are allowed (not all tokens have them).
if jti == "" {
    return nil
}
```

So a token with no `jti` is never checked, and nothing warns. An IdP that does
not mint `jti` claims silently disables the whole feature — you would have
`detectReplay: true` in your policy, no errors anywhere, and no replay
detection. The test asserts this gap explicitly, and is written to fail if it
is ever closed.

## Velocity

A sliding one-minute window per subject. Over the threshold, the tracker
alerts; with `alertAction: DENY` the call is refused with `-32004`.

```yaml
anomaly:
  enabled: true
  velocity:
    threshold: 8
    alertAction: DENY
```

The test pins the exact call that trips — the 9th, against a threshold of 8 —
so a silently changed threshold fails here rather than passing vaguely.

Two things in this demo exist only to make that assertion mean something. The
registry sets `maxCallsPerMinute: 600` and the circuit breaker allows 100 calls
per session, both far above the burst, so neither can be what refuses it. Each
call in the burst also uses a fresh token and its own session id, so replay
detection and session binding cannot either. What is left is the velocity
tracker.

Note that it keys on the **subject**, not the session. Spreading a burst across
sessions does not evade it; using a different identity does.

## The three are independent

| Detection | Config | Refusal | Keyed on |
|---|---|---|---|
| Session binding | `integrity.bindToSession` | `-32001` | session id → subject |
| Replay | `integrity.detectReplay` | `-32001` | `jti` |
| Velocity | `anomaly.velocity` | `-32004` | subject |

Each is opt-in on its own. The audit trail separates them: velocity alerts
carry `"gate":"anomaly"` and a `velocity_limit` reason class, integrity
failures are logged as integrity failures.

## What the test asserts

```
a session belongs to whoever opened it:
  ok:  the first caller on a session id is accepted
  ok:  a valid token for a different subject is refused on that session
  ok:  and the same caller is fine on a session of its own

a token is good once:
  ok:  reusing a token that has already been seen is refused
  ok:  a fresh token for the same subject still works
  note: detectReplay makes tokens single-use, so callers must mint one per request

what replay detection does not catch:
  gap: a token with no jti claim is never replay-checked, and nothing warns

an unusual rate is caught even when every call is permitted:
  ok:  a subject over the velocity threshold is refused with -32004
  ok:  on the call after the threshold, not sooner or later

the audit trail distinguishes the three:
  ok:  velocity alerts are recorded against the anomaly gate
  ok:  with a reason class of their own
  ok:  and integrity failures are logged separately
```

## Related

- Demo 02 covers token verification itself, which all of this sits on top of.
- Demo 01 covers the registry and circuit breaker gates held out of the way here.
