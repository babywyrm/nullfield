# nullfield — Cluster Implementation Guide

How to add nullfield to your workloads. Covers manual sidecar injection, Helm integration, policy configuration, and operational runbook.

---

## Prerequisites

- A running Kubernetes cluster (K8s, K3s, EKS, GKE, AKS — any conformant distribution)
- `kubectl` configured with cluster access
- nullfield container image available to the cluster (GHCR, ECR, local import — your choice)

---

## 1. Understand the Traffic Flow

nullfield is an explicit reverse proxy sidecar. Your MCP client talks to nullfield; nullfield talks to your MCP server. Both containers live in the same pod and communicate over localhost.

```text
                        ┌───────────────────────────────────────────┐
                        │  Pod                                      │
                        │                                           │
  MCP Client ─────────────► :9090 nullfield ──► :8080 your-app      │
  (external or          │       │                                   │
   in-cluster)          │       ├── identity check                  │
                        │       ├── registry check                  │
                        │       ├── policy evaluation               │
                        │       ├── circuit breaker                 │
                        │       └── audit log                       │
                        │                                           │
                        │   :9091 admin (/healthz, /readyz)         │
                        └───────────────────────────────────────────┘
```

**Key point**: The Service or Ingress that currently points at your app's port (e.g. 8080) should be updated to point at nullfield's port (9090). Your app container no longer needs to be directly reachable from outside the pod.

---

## 2. Add nullfield to an Existing Deployment

### Option A: Raw manifest (no Helm)

Take your existing Deployment and add three things:

**1) The nullfield container alongside your app:**

```yaml
spec:
  template:
    spec:
      containers:
        # Your existing application container
        - name: my-mcp-server
          image: my-app:latest
          ports:
            - name: app
              containerPort: 8080

        # Add the nullfield sidecar
        - name: nullfield
          image: ghcr.io/babywyrm/nullfield:latest
          ports:
            - name: proxy
              containerPort: 9090
              protocol: TCP
            - name: admin
              containerPort: 9091
              protocol: TCP
          envFrom:
            - configMapRef:
                name: my-app-nullfield-config
          volumeMounts:
            - name: nullfield-tools
              mountPath: /etc/nullfield
              readOnly: true
          livenessProbe:
            httpGet:
              path: /healthz
              port: admin
            initialDelaySeconds: 3
            periodSeconds: 10
          readinessProbe:
            httpGet:
              path: /readyz
              port: admin
            initialDelaySeconds: 2
            periodSeconds: 5
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 200m
              memory: 128Mi
          securityContext:
            runAsNonRoot: true
            runAsUser: 65534
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
            capabilities:
              drop: ["ALL"]

      volumes:
        - name: nullfield-tools
          configMap:
            name: my-app-nullfield-tools
```

**2) A ConfigMap for nullfield environment config:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-app-nullfield-config
  namespace: my-namespace
data:
  NULLFIELD_LISTEN_ADDR: ":9090"
  NULLFIELD_UPSTREAM_ADDR: "localhost:8080"      # your app's port
  NULLFIELD_ADMIN_ADDR: ":9091"
  NULLFIELD_POLICY_PATH: "/etc/nullfield/policy.yaml"
  NULLFIELD_REGISTRY_PATH: "/etc/nullfield/tools.yaml"
  NULLFIELD_CIRCUIT_MAX_CALLS: "100"
  NULLFIELD_CIRCUIT_MAX_DURATION: "5m"
  NULLFIELD_AUDIT_LOG_LEVEL: "FULL"
  # NULLFIELD_JWKS_URL: "https://your-idp.example.com/.well-known/jwks.json"
```

**3) A ConfigMap for your tool registry:**

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: my-app-nullfield-tools
  namespace: my-namespace
data:
  tools.yaml: |
    apiVersion: nullfield.io/v1alpha1
    kind: ToolRegistry
    metadata:
      name: my-app-tools
    tools:
      - name: my_read_tool
        description: Read-only tool
        maxCallsPerMinute: 60
      - name: my_write_tool
        description: Write tool (slower rate)
        maxCallsPerMinute: 10
```

**4) Update your Service to point at nullfield:**

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-mcp-server
spec:
  selector:
    app: my-mcp-server
  ports:
    - name: mcp
      port: 9090           # <-- was 8080, now points at nullfield
      targetPort: proxy
    - name: admin
      port: 9091
      targetPort: admin
```

### Option B: Helm chart

If your app uses Helm, include the nullfield chart as a dependency and use the sidecar template helper:

```yaml
# In your Chart.yaml
dependencies:
  - name: nullfield
    version: "0.1.0"
    repository: "file://../../deploy/helm/nullfield"
```

Then in your deployment template:

```yaml
containers:
  - name: my-mcp-server
    image: {{ .Values.image.repository }}:{{ .Values.image.tag }}
    ports:
      - containerPort: 8080
  {{- include "nullfield.sidecar" .Subcharts.nullfield | nindent 2 }}
```

---

## 3. Define Your Tool Registry

The tool registry is the allowlist. Any tool not in the registry is rejected before policy evaluation even runs.

**Rule**: Start with only the tools your app actually exposes. If your MCP server has 5 tools, register exactly those 5.

```yaml
tools:
  # Read tools — higher rate limits
  - name: get_customer
    description: Fetch customer record by ID
    allowedScopes: ["customer:read"]
    maxCallsPerMinute: 60

  # Write tools — lower rate limits, tighter scopes
  - name: update_customer
    description: Update customer record
    allowedScopes: ["customer:write"]
    maxCallsPerMinute: 10

  # Dangerous tools — register but deny in policy
  - name: delete_customer
    description: Delete customer record (admin only)
    allowedScopes: ["customer:admin"]
    maxCallsPerMinute: 5
```

**How to get the list**: Call `tools/list` on your MCP server directly (before adding nullfield) and register every tool it returns.

---

## 4. Define Your Policy

Policy rules are evaluated top-to-bottom, first match wins. Always end with a deny-all rule.

### Starter policy (recommended)

```yaml
apiVersion: nullfield.io/v1alpha1
kind: NullfieldPolicy
metadata:
  name: my-app-policy
  namespace: my-namespace
spec:
  selector:
    matchLabels:
      app: my-mcp-server
  rules:
    # 1. Allow read-only tools
    - action: ALLOW
      mcpMethod: tools/call
      toolNames:
        - get_customer
      requireIdentity: true
      maxCallsPerMinute: 60

    # 2. Allow write tools with lower rate
    - action: ALLOW
      mcpMethod: tools/call
      toolNames:
        - update_customer
      requireIdentity: true
      maxCallsPerMinute: 10

    # 3. Deny everything else
    - action: DENY
      mcpMethod: tools/call
      toolNames: ["*"]

  circuitBreaker:
    maxToolCallsPerSession: 50
    maxSessionDuration: 120s
    onTrip: KILL_POD

  audit:
    logLevel: FULL
```

### Policy design principles

| Principle | Implementation |
|---|---|
| Default deny | Last rule is always `DENY *` |
| Least privilege | Only ALLOW the specific tools each workload needs |
| Identity required | Set `requireIdentity: true` on every ALLOW rule |
| Rate limits per tool | Write tools get lower limits than read tools |
| Circuit breaker per session | Prevent runaway agent loops |

---

## 5. Update Existing Services and Ingress

This is the step people forget. After adding nullfield, external traffic must route through port 9090 (nullfield), not 8080 (your app).

### Service

```yaml
ports:
  - name: mcp
    port: 9090           # nullfield proxy
    targetPort: proxy    # matches the named port on the nullfield container
```

### Ingress / HTTPRoute

If you have an Ingress or Gateway API HTTPRoute, update the backend port:

```yaml
# Gateway API
rules:
  - backendRefs:
      - name: my-mcp-server
        port: 9090       # was 8080

# Classic Ingress
backend:
  service:
    name: my-mcp-server
    port:
      number: 9090       # was 8080
```

### NetworkPolicy (if applicable)

If you have NetworkPolicies, allow traffic to port 9090 (proxy) and 9091 (admin for probes). You can restrict port 8080 to only accept traffic from localhost (pod-internal).

---

## 6. Verify the Deployment

Run these checks after deploying:

```bash
NS=my-namespace
APP=my-mcp-server

# 1. Both containers running?
kubectl -n $NS get pods -l app=$APP

# 2. nullfield loaded the tool registry?
kubectl -n $NS logs -l app=$APP -c nullfield | head -5
# expect: "loaded tool registry" with correct tool count

# 3. Health checks passing?
POD_IP=$(kubectl -n $NS get pod -l app=$APP -o jsonpath='{.items[0].status.podIP}')
kubectl run curl-test --rm -i --restart=Never --image=curlimages/curl -- \
  curl -sf http://$POD_IP:9091/healthz

# 4. MCP passthrough works?
kubectl run curl-test --rm -i --restart=Never --image=curlimages/curl -- \
  curl -s -X POST http://$POD_IP:9090 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'

# 5. Tool registry blocks unregistered tools?
kubectl run curl-test --rm -i --restart=Never --image=curlimages/curl -- \
  curl -s -X POST http://$POD_IP:9090 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"nonexistent_tool","arguments":{}}}'
# expect: -32003 "tool not registered"

# 6. Audit trail emitting?
kubectl -n $NS logs -l app=$APP -c nullfield --tail=20
# expect: audit events for each request above
```

---

## 7. Operational Runbook

### Adding a new tool

1. Add the tool to the ToolRegistry ConfigMap
2. Add an ALLOW rule for the tool in the NullfieldPolicy
3. `kubectl apply` the updated ConfigMap
4. Restart the pod (nullfield reads the registry at startup)

```bash
kubectl -n $NS rollout restart deployment/$APP
```

### Investigating a denied tool call

```bash
# Find denial events in the audit log
kubectl -n $NS logs -l app=$APP -c nullfield | grep "tool.denied"
```

Each denial log includes the tool name, identity, and reason — either "tool not registered" (registry) or "denied by policy" (rule engine).

### Circuit breaker tripped

```bash
# Find circuit events
kubectl -n $NS logs -l app=$APP -c nullfield | grep "circuit.tripped"
```

The circuit breaker tracks per-session call counts. When tripped, all subsequent tool calls for that session return `-32002`. The session state is cleared when the pod restarts or the session expires (2x the max duration).

### Emergency bypass

If nullfield is blocking legitimate traffic and you need an emergency bypass:

```bash
# Scale down nullfield by removing the sidecar (update the deployment)
# OR: set the upstream to match the app port and policy to allow-all

# Fastest: just point the service back at the app port directly
kubectl -n $NS patch svc $APP -p '{"spec":{"ports":[{"name":"mcp","port":9090,"targetPort":8080}]}}'
```

This bypasses nullfield at the service layer without changing the pod. Revert when the issue is resolved.

---

## 8. Migration Checklist

For each workload being onboarded to nullfield:

```text
[ ] Inventory all tools via tools/list on the existing MCP server
[ ] Create ToolRegistry ConfigMap with those tools
[ ] Create NullfieldPolicy with explicit ALLOW rules + deny-all default
[ ] Add nullfield sidecar container to the Deployment
[ ] Add nullfield ConfigMap (env vars) to the Deployment
[ ] Mount ToolRegistry ConfigMap as volume
[ ] Update Service targetPort from app port to 9090
[ ] Update Ingress/HTTPRoute backend port if applicable
[ ] Update NetworkPolicy if applicable
[ ] If running a service mesh: apply the appropriate overlay (see docs/mesh-integration.md)
[ ] Verify: kubectl get pods shows 2/2 Running (or 3/3 with mesh sidecar)
[ ] Verify: healthz and readyz return ok
[ ] Verify: initialize and tools/list pass through
[ ] Verify: unregistered tool returns -32003
[ ] Verify: audit logs emitting
[ ] Document the policy in your team's runbook
```

---

## 9. What's Next (Roadmap)

| Phase | Feature | Impact |
|---|---|---|
| ~~v0.1~~ | ~~Policy from file~~ | ~~Done — load NullfieldPolicy from mounted YAML~~ |
| v0.2 | JWKS identity validation | Replace noop verifier with real token validation |
| v0.2 | OPA/Rego policy engine | More expressive policy rules beyond first-match |
| v0.2 | OTLP audit export | Ship audit events to OpenTelemetry Collector |
| v0.3 | Credential injection | Outbound LLM API calls get secrets injected from Vault/ASM |
| v0.4 | Mutating admission webhook | Automatic sidecar injection — add a label, get nullfield |
| v0.5 | CRD controller | Watch NullfieldPolicy and ToolRegistry as native K8s resources |
| v1.0 | Transparent proxy | iptables-based interception, no service port changes needed |

The mutating webhook (v0.4) eliminates most of this manual work — teams will just label their namespace or deployment and nullfield gets injected automatically, similar to Istio sidecar injection.
