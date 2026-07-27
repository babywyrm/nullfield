# Demo 15 — Proxy Baseline

The original data path, running in a namespace with no mesh at all.

This demo proves nothing new. That is the point: it is the control. nullfield now
has two deployment shapes — an in-path proxy and an out-of-path decision service
called by a waypoint — and when the mesh one misbehaves, the first question is
whether the decision core is broken or the mesh integration is. Answering that
should cost one command, not an afternoon.

Run this before and after any change to the policy engine, the MCP envelope, or
the audit trail.

## Prerequisites

- A Kubernetes cluster and `kubectl`
- Images available to the cluster:
  - `ghcr.io/babywyrm/nullfield:latest`
  - `ghcr.io/babywyrm/nullfield-echo:latest`

On a single-node k3s cluster, `BUILD_IMAGES=true` builds and imports both.

## Run

```bash
./demos/15-proxy-baseline/test.sh
# or, building images first:
BUILD_IMAGES=true ./demos/15-proxy-baseline/test.sh
```

## What it asserts

| Call | Expected |
|---|---|
| `echo` | reaches the upstream and returns its result |
| `dangerous_tool` | refused by policy, JSON-RPC `-32000` |
| `not_registered` | refused by the registry, JSON-RPC `-32003` |

The distinction between the last two matters. Both are refusals, and collapsing
them would hide a registry that had stopped loading: every tool would look
"denied by policy" while the policy was doing none of the work.

## Why it refuses to run in a meshed namespace

The script checks for `istio.io/dataplane-mode` and exits if it is set. A
waypoint in front of this traffic would change what is being measured while
every assertion below still passed, which is the worst kind of green.

For the mesh path, see [demo 16](../16-mesh-arbiter/).
