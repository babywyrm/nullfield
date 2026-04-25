# Demo 10 — CRD Policy Management

Apply nullfield policies as native Kubernetes Custom Resources instead of
ConfigMap-mounted files. GitOps-friendly — `kubectl apply` your policies.

## Prerequisites

- K8s cluster with nullfield deployed
- nullfield-controller with `NULLFIELD_CRD_WATCH=true`

## Step 1: Install CRDs

```bash
kubectl apply -f deploy/crds/
```

Verify:

```bash
kubectl get crd | grep nullfield
# nullfieldpolicies.nullfield.io
# toolregistries.nullfield.io
```

## Step 2: Apply a Policy

```yaml
# policy.yaml
apiVersion: nullfield.io/v1alpha1
kind: NullfieldPolicy
metadata:
  name: demo-policy
  namespace: camazotz
spec:
  selector:
    matchLabels:
      app: brain-gateway
  rules:
    - action: ALLOW
      mcpMethod: tools/call
      toolNames: ["cost.check_usage", "audit.list_actions"]
    - action: HOLD
      mcpMethod: tools/call
      toolNames: ["delegation.invoke_agent"]
      hold:
        timeout: "5m"
        onTimeout: DENY
    - action: DENY
      mcpMethod: tools/call
      toolNames: ["*"]
      reason: "default deny"
```

```bash
kubectl apply -f policy.yaml
```

## Step 3: Verify Sync

The controller creates a ConfigMap from the CRD:

```bash
kubectl -n camazotz get configmap nullfield-policy-demo-policy
# Should exist with policy.yaml key
```

The sidecar's hot-reload picks up the ConfigMap change automatically.

## Step 4: Test Enforcement

```bash
# This should be ALLOWED
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cost.check_usage","arguments":{}}}'

# This should be DENIED
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"secrets.leak_config","arguments":{}}}'
```

## Step 5: Update Policy (GitOps)

Edit the YAML, re-apply, the sidecar hot-reloads:

```bash
# Add a new ALLOW rule, re-apply
kubectl apply -f policy.yaml
# Sidecar picks up the change within 30 seconds (default poll interval)
```
