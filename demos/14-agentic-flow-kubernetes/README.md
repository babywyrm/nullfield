# Demo 14 — AgenticFlow Kubernetes Reconciliation

This demo shows `AgenticFlow` as a Kubernetes CRD. The nullfield controller watches the CRD, compiles the flow, and writes a managed ConfigMap.

It also deploys a tiny echo MCP server with a nullfield sidecar that mounts the generated ConfigMap, then sends real MCP calls through the sidecar.

## Prerequisites

- A Kubernetes cluster
- `kubectl`
- `nullfield-controller` running with:
  - `NULLFIELD_CRD_WATCH=true`
  - RBAC allowing reads on `agenticflows.nullfield.io`
  - RBAC allowing ConfigMap create/update
- Images available to the cluster:
  - `ghcr.io/babywyrm/nullfield:latest`
  - `ghcr.io/babywyrm/nullfield-echo:latest`

## What This Demonstrates

```text
AgenticFlow CRD
  -> controller watcher
  -> nullfield-flow-<name> ConfigMap
     -> compiled.yaml
     -> policy.yaml
     -> tools.yaml
```

The demo does not require Istio, Cilium, Linkerd, Vault, OAuth, or a private SaaS.

## Run

From the repo root:

```bash
bash demos/14-agentic-flow-kubernetes/test.sh <namespace>
```

If no namespace is provided, the script uses `nullfield-demo`.

For single-node k3s clusters where you want to build/import local images first:

```bash
BUILD_IMAGES=true bash demos/14-agentic-flow-kubernetes/test.sh <namespace>
```

For an existing nullfield controller namespace:

```bash
bash demos/14-agentic-flow-kubernetes/test.sh camazotz
```

## Expected Result

The script verifies:

- `agenticflows.nullfield.io` CRD is installed
- `AgenticFlow/echo-known-path` is accepted
- `ConfigMap/nullfield-flow-echo-known-path` is generated
- `policy.yaml` contains ALLOW, explicit DENY, and default-deny rules
- `tools.yaml` contains the declared tool registry
- `Deployment/agentic-flow-runtime` starts
- `echo` is allowed through nullfield and reaches the echo MCP server
- `dangerous_tool` is denied by policy
- `unknown_tool` is rejected before upstream
