# Demo 11 — Hot Policy Reload

Change nullfield policy on a running sidecar without restarting. The sidecar
polls its policy file every 30 seconds and swaps the rule engine atomically
when the file changes.

## Prerequisites

- Docker Compose or K8s with nullfield running

## Docker Compose

### Step 1: Start with a permissive policy

```bash
# examples/policy.yaml allows several tools
docker compose up -d
curl -sf http://localhost:9091/healthz  # ok
```

### Step 2: Call a tool that's currently allowed

```bash
curl -s -X POST http://localhost:9090 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github_create_pr","arguments":{"repo":"test","title":"test"}}}'
# Returns: tool result (allowed)
```

### Step 3: Update the policy to deny that tool

Edit `examples/policy.yaml` — change the ALLOW rule to DENY for `github_create_pr`.

Or replace the file entirely:

```bash
cat > examples/policy.yaml << 'EOF'
apiVersion: nullfield.io/v1alpha1
kind: NullfieldPolicy
metadata:
  name: strict
spec:
  selector:
    matchLabels: {}
  rules:
    - action: DENY
      mcpMethod: tools/call
      toolNames: ["*"]
      reason: "lockdown mode"
EOF
```

### Step 4: Wait for reload (or watch logs)

```bash
docker compose logs -f nullfield | grep "hot-reload"
# Within 30 seconds: "policy hot-reloaded path=/etc/nullfield/policy.yaml rules=1"
```

### Step 5: Call the same tool again

```bash
curl -s -X POST http://localhost:9090 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"github_create_pr","arguments":{"repo":"test","title":"test"}}}'
# Returns: -32000 "denied by policy: lockdown mode"
```

No restart needed. The policy change took effect in-flight.

## Kubernetes

Same concept — update the ConfigMap, the sidecar detects the change:

```bash
# Update policy ConfigMap
kubectl -n camazotz create configmap nullfield-config \
  --from-file=policy.yaml=new-policy.yaml \
  --dry-run=client -o yaml | kubectl apply -f -

# Watch sidecar logs for reload
kubectl -n camazotz logs -l app=brain-gateway -c nullfield -f | grep "hot-reload"
```
