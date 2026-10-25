# Demo 17 — Run Tokens on the Mesh

One pod, one service account, many runs. Attestation says which pod is calling;
a run token says which run, for whom, and within what. This demo signs one per
run, sends it through a real waypoint, and shows nullfield binding it to the
pod and letting it narrow what policy allows.

See [Run Tokens](../../docs/identity-policy.md#run-tokens-ext_authz) for the
reference.

## Prerequisites

- Demo 16's environment: Istio ambient, its extension provider registered
  (`APPLY_MESH_CONFIG=true demos/16-mesh-arbiter/test.sh` once)
- `kubectl`, `python3`, `openssl` on the machine running the script
- `nginx:alpine` pullable or cached, for the key endpoint

## Run

```bash
BUILD_IMAGES=true ./demos/17-run-tokens/test.sh   # builds and imports on k3s
./demos/17-run-tokens/test.sh                     # images already current
```

It shares demo 16's namespace. Demo 16 restores its own policy on its next run,
so the two can be run in either order.

## The stand-in controller

There is no controller binary. The script generates an RSA key in a temp dir,
publishes the public half as a JWKS from an `nginx:alpine` pod, and mints
tokens with `openssl dgst -sign`. That is all a real controller has to do:
sign a JWT with a key whose JWKS nullfield can fetch. The key never leaves the
temp dir and is deleted on exit.

Each token carries `typ: txntoken+jwt`, `aud: cluster.local`, a ten-minute
`exp`, `txn` (the run), `sub: team-sre`, `req_wl` (the pod it is for), and
`tctx.repos`.

## The policy

```yaml
runToken:
  jwksUri: http://run-controller/.well-known/jwks.json
  audience: cluster.local
  maxLifetime: 15m
rules:
  - action: ALLOW
    toolNames: [echo]
    celExpression: request.arguments.repo in request.run.context.repos
  - action: DENY
    toolNames: ["*"]
```

## What it asserts

| # | Call | Result | Recorded |
|---|---|---|---|
| 1 | no token | 403 | `gate: run_token`, `run_token_missing`, the caller's SPIFFE ID |
| 2 | token for this pod, repo in `tctx` | 200 | `run_id: run-a`, `identity: team-sre`, `assurance: MEDIUM` |
| 3 | same token, repo not in `tctx` | 403 | `run_id: run-a`, `policy_denied` |
| 4 | token minted for another service account | 403 | `run_token_unbound` |
| 5 | same claims, `typ: at+jwt` | 403 | `run_token_invalid` |
| 6 | token for this pod | 200 | the echo server logs `txn_token: false` |

Row 3 is the narrowing: policy allows `echo`, the token allows only
`acme/widgets`, and the call needs both. Row 4 is the binding: the token is
genuine and signed by the right key, and it still fails from the wrong pod.
Row 6 is the strip: the client sent `Txn-Token`, and the upstream never saw it.

## Two things the first run found

**A rebuilt `:latest` image is not running until its pod restarts.** The first
run built a new echo server and asserted against the old one. The script now
restarts both deployments it depends on.

**`kubectl logs deploy/x` picks an arbitrary pod during a rollout.** With the old
pod still terminating, a log assertion can read the previous binary's output.
The script waits for one pod per deployment before reading anything.
