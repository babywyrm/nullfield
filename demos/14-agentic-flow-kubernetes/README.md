# Demo 14 — AgenticFlow Kubernetes Reconciliation

This demo shows `AgenticFlow` as a Kubernetes CRD. The nullfield controller watches the CRD, compiles the flow, and writes a managed ConfigMap.

## Prerequisites

- A Kubernetes cluster
- `kubectl`
- `nullfield-controller` running with:
  - `NULLFIELD_CRD_WATCH=true`
  - RBAC allowing reads on `agenticflows.nullfield.io`
  - RBAC allowing ConfigMap create/update

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

For an existing nullfield controller namespace:

```bash
bash demos/14-agentic-flow-kubernetes/test.sh camazotz
```

## Expected Result

The script verifies:

- `agenticflows.nullfield.io` CRD is installed
- `AgenticFlow/echo-known-path` is accepted
- `ConfigMap/nullfield-flow-echo-known-path` is generated
- `policy.yaml` contains ALLOW, HOLD, DENY, and default-deny rules
- `tools.yaml` contains the declared tool registry
