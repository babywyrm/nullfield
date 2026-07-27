# Demo 16 — Mesh-Native Arbiter

nullfield as a waypoint's external authorization service, deciding on real mesh
traffic with a cryptographically attested caller.

Nothing here sits in the request path. The waypoint calls the decision service
and acts on the answer, which is why the same binary and the same deployment run
in no-op, observe, or enforce without changing shape.

## Prerequisites

- Istio in ambient mode with the Kubernetes Gateway API CRDs
- `kubectl` and `python3`
- `ghcr.io/babywyrm/nullfield-extauthz:latest` and
  `ghcr.io/babywyrm/nullfield-echo:latest` available to the cluster

## Run

```bash
# Namespace-scoped resources only; fails with instructions if the extension
# provider is not registered.
./demos/16-mesh-arbiter/test.sh

# Also register the provider, which edits mesh-wide config and restarts istiod.
APPLY_MESH_CONFIG=true ./demos/16-mesh-arbiter/test.sh
```

The provider registration is opt-in because it is the only step that touches
anything outside the demo's namespace. It takes a backup first and is
idempotent.

## What it asserts

**1. The caller is identified, not self-declared.** The audit event carries
`spiffe://cluster.local/ns/nullfield-mesh-demo/sa/mesh-demo-client` — the
client's own service account, established from the mesh rather than from a claim
the client sent.

**2. MCP is recognised by parsing the body.** `transport: A` and
`tool_name: dangerous_tool` come out of a JSON-RPC envelope on an ordinary POST.
There is no MCP-shaped URL to match on.

**3. Observe mode records what enforcement would have done, without doing it.**
A call the policy denies still returns HTTP 200, and the event carries
`counterfactual: DENY`.

**4. A body too large to read is refused, not authorized on the part that fit.**
A 20 KB request against an 8 KB buffer yields `reason_class: body_truncated` —
still attributed to the caller, still not blocking in observe mode.

Then the mode is flipped to `enforce` and the same denied call returns 403 while
the allowed one still returns 200.

## Why this namespace runs no other provider

Sharing a waypoint with an enforcing provider makes claim 3 untestable. Every
request returns 403 regardless of what nullfield decided, so "observe mode does
not block" cannot be distinguished from "observe mode blocks, and something else
got there first."

## Two settings that fail silently

**`allowPartialMessage` must match the mode.** With `false`, Envoy answers an
oversized body with 413 *before* calling the check: nullfield never sees the
request and cannot observe it, yet the traffic is already broken. A rollout
declared read-only starts failing large requests. Observe needs `true`; enforce
should use `false` so the proxy fails closed, with nullfield's own truncation
guard as defence in depth.

**A CUSTOM `AuthorizationPolicy` needs `targetRefs`.** Without it the policy
binds to ztunnel, which is L4 only and cannot run an HTTP filter, so the provider
is never consulted and nothing reports that it was skipped.

And if istiod logs `available providers are []`, it cannot parse
`extensionProviders` at all — at which point every CUSTOM policy in the mesh
quietly becomes a deny, including ones unrelated to this demo.

## The EnvoyFilter

Without it the check arrives anonymous. A waypoint terminates HBONE upstream of
the listener running `ext_authz`, so there is no peer certificate to read there;
Istio publishes the identity into Envoy filter state instead, and a Lua filter
ordered before `ext_authz` copies it into a request header.

nullfield does not trust that header. The filter strips any inbound value of the
same name before writing its own, so a workload cannot assert its own identity
by sending it — which is also why a deployment without this filter must not treat
the header as meaningful. Header-derived identity is reported as the
`mesh-header` attester rather than `mesh-spiffe`, because the binding differs
even though the identity is the same.

See `docs/specs/2026-07-26-mesh-native-arbiter.md` for the measurements behind
all of this.
