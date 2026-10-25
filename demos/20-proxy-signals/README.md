# Demo 20 — Signals from the Proxy

The proxy refuses a session that goes past its circuit breaker. This demo
trips one through the compose stack and shows the signal arriving, once,
signed, at a webhook receiver.

See [Signals](../../docs/signals.md) for the reference, and demo 19 for the
same on the mesh.

## Run

```bash
docker compose -f docker-compose.yaml build   # after code changes
./demos/20-proxy-signals/test.sh
```

Needs Docker, `openssl` and `curl`. The webhook's signing secret is generated
fresh per run in a temp dir and bind-mounted into the proxy and the receiver.

## The setup

- `policy.yaml`: `circuitBreaker.maxToolCallsPerSession: 2`; `echo` allowed.
- `compose.override.yaml`: the proxy gets `NULLFIELD_SIGNAL_WEBHOOK_URL` and
  `NULLFIELD_SIGNAL_WEBHOOK_SECRET_FILE`, and a `signal-receiver` service runs
  [`../19-signals/receiver.py`](../19-signals/receiver.py).

## What it proves

| # | Check | Result |
|---|---|---|
| 1 | Session 1, calls 1 and 2 | allowed |
| 2 | Session 1, calls 3 to 5 | `-32002` at the circuit gate |
| 3 | Session 2 | allowed |
| 4 | Audit log for session 1 | one `circuit.tripped`, two `tool.denied` with `gate: circuit` |
| 5 | Webhook | one post for session 1, signature verified |
| 6 | Unsigned post to the receiver | 401 |
