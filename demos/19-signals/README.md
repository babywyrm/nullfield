# Demo 19 — Signals

nullfield refuses a run that goes past its circuit breaker. The controller
that owns the run has to hear about it, once, from something it can trust.
This demo trips a run's breaker through a real waypoint and shows the signal
arriving as a Kubernetes Event and as a signed webhook.

See [Signals](../../docs/signals.md) for the reference.

## Prerequisites

- Demo 16's environment: Istio ambient, its extension provider registered
  (`APPLY_MESH_CONFIG=true demos/16-mesh-arbiter/test.sh` once)
- `kubectl`, `python3`, `openssl` on the machine running the script
- `nginx:alpine` and `python:3.13-alpine` pullable or cached

## Run

```bash
BUILD_IMAGES=true ./demos/19-signals/test.sh   # builds and imports on k3s
./demos/19-signals/test.sh                     # images already current
```

It shares demo 16's namespace and demo 17's stand-in controller
(`demos/17-run-tokens/run-controller.sh`), which signs run tokens with a key
that lives in a temp dir.

It changes four things in the namespace:

- the policy;
- a Role letting the arbiter create Events there;
- the arbiter deployment, which gains the signal env vars and the secret;
- a `signal-receiver` deployment, off the waypoint.

Demos 16, 17 and 18 restore their policy on their next run. The extra env
vars stay, because `kubectl apply` keeps fields it did not set. They are
harmless while the `signal-webhook` Secret exists.

The webhook's signing secret is generated fresh per run, written to the temp
dir, and loaded into a Secret from that file.

## The policy

```yaml
runToken: {jwksUri: http://run-controller/.well-known/jwks.json, audience: cluster.local}
circuitBreaker:
  maxToolCallsPerSession: 2
```

Each run gets two calls. The third trips that run's breaker.

## The receiver

[`receiver.py`](receiver.py) is a twenty-line Python receiver, also used by
demo 20, that does what a run
controller's endpoint must do:

- recompute the HMAC over timestamp, `.`, body;
- compare it in constant time;
- reject a timestamp more than five minutes off.

## What it proves

| # | Check | Result |
|---|---|---|
| 1 | Run A, calls 1 and 2 | 200 |
| 2 | Run A, calls 3 and 4 | 403 at `gate: circuit` |
| 3 | Run B on the same pod | 200 |
| 4 | `circuit.tripped` in the audit log | exactly one for run A |
| 5 | Kubernetes Event | one `CircuitTripped` on `ServiceAccount/mesh-demo-client`, annotated `nullfield.io/run-id` |
| 6 | Webhook | one post for run A, signature verified |
| 7 | Unsigned post to the receiver | 401 |
