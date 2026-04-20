# Sidecar Mode — Kubernetes

Deploy nullfield as a sidecar container in a Kubernetes pod. Traffic enters through nullfield (port 9090), gets filtered by policy, and only allowed calls reach the MCP server (port 8080) on localhost.

## What you'll learn

- **Sidecar injection** — two-container pod pattern with shared localhost networking
- **ConfigMap-based policy** — manage tools.yaml and policy.yaml as Kubernetes-native config
- **Service rewiring** — expose nullfield's port (9090) as the Service endpoint, not the app's port (8080)

## Prerequisites

- `kubectl` configured against a running cluster (minikube, kind, k3s, EKS, GKE — any distro)
- The nullfield image available to your cluster:
  - **Local cluster (kind):** `kind load docker-image ghcr.io/babywyrm/nullfield:latest`
  - **Local cluster (minikube):** `minikube image load ghcr.io/babywyrm/nullfield:latest`
  - **Remote cluster:** image must be pullable from `ghcr.io/babywyrm/nullfield:latest`

## Step 1: Create namespace and ConfigMaps

Apply the following to create the namespace, environment config, and policy/tools ConfigMaps:

```bash
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: nullfield-demo
  labels:
    app.kubernetes.io/name: nullfield-demo
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: nullfield-env
  namespace: nullfield-demo
data:
  NULLFIELD_LISTEN_ADDR: ":9090"
  NULLFIELD_UPSTREAM_ADDR: "localhost:8080"
  NULLFIELD_ADMIN_ADDR: ":9091"
  NULLFIELD_POLICY_PATH: "/etc/nullfield/policy.yaml"
  NULLFIELD_REGISTRY_PATH: "/etc/nullfield/tools.yaml"
  NULLFIELD_CIRCUIT_MAX_CALLS: "100"
  NULLFIELD_CIRCUIT_MAX_DURATION: "5m"
  NULLFIELD_AUDIT_LOG_LEVEL: "FULL"
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: nullfield-policy
  namespace: nullfield-demo
data:
  policy.yaml: |
    apiVersion: nullfield.io/v1alpha1
    kind: NullfieldPolicy
    metadata:
      name: demo-sidecar-policy
    spec:
      selector:
        matchLabels:
          app: echo-mcp
      rules:
        - action: ALLOW
          mcpMethod: tools/call
          toolNames:
            - echo
            - github_create_pr
            - pagerduty_resolve
          maxCallsPerMinute: 30
        - action: DENY
          mcpMethod: tools/call
          toolNames: ["*"]
      circuitBreaker:
        maxToolCallsPerSession: 50
        maxSessionDuration: 120s
        onTrip: KILL_POD
      audit:
        logLevel: FULL
  tools.yaml: |
    apiVersion: nullfield.io/v1alpha1
    kind: ToolRegistry
    metadata:
      name: demo-sidecar-tools
    tools:
      - name: echo
        description: Echoes back the input
        maxCallsPerMinute: 60
      - name: github_create_pr
        description: Create a GitHub PR
        allowedScopes: ["repo:write"]
        maxCallsPerMinute: 10
      - name: pagerduty_resolve
        description: Resolve a PagerDuty incident
        allowedScopes: ["incidents:write"]
        maxCallsPerMinute: 10
EOF
```

## Step 2: Deploy echo MCP server + nullfield sidecar

```bash
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: echo-mcp
  namespace: nullfield-demo
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo-mcp
  namespace: nullfield-demo
  labels:
    app: echo-mcp
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo-mcp
  template:
    metadata:
      labels:
        app: echo-mcp
    spec:
      serviceAccountName: echo-mcp
      containers:
        # The MCP application server
        - name: echo-server
          image: ghcr.io/babywyrm/nullfield-echo:latest
          ports:
            - name: app
              containerPort: 8080
              protocol: TCP
          resources:
            requests:
              cpu: 25m
              memory: 32Mi
            limits:
              cpu: 100m
              memory: 64Mi

        # The nullfield sidecar — all external traffic enters here
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
                name: nullfield-env
          volumeMounts:
            - name: policy
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
        - name: policy
          configMap:
            name: nullfield-policy
EOF
```

## Step 3: Create the Service

The Service targets nullfield's proxy port (9090), not the app's port (8080). Clients connect to the Service and nullfield handles filtering before forwarding to the co-located echo server.

```bash
kubectl apply -f - <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: echo-mcp
  namespace: nullfield-demo
  labels:
    app: echo-mcp
spec:
  selector:
    app: echo-mcp
  ports:
    - name: mcp
      port: 9090
      targetPort: proxy
      protocol: TCP
    - name: admin
      port: 9091
      targetPort: admin
      protocol: TCP
  type: ClusterIP
EOF
```

## Step 4: Verify pods are 2/2 Running

```bash
kubectl -n nullfield-demo get pods -l app=echo-mcp
```

Expected output:

```
NAME                        READY   STATUS    RESTARTS   AGE
echo-mcp-7f8b4c6d9-x2k1p   2/2     Running   0          30s
```

Wait until READY shows `2/2`. If a container is stuck in CrashLoopBackOff, check logs:

```bash
kubectl -n nullfield-demo logs -l app=echo-mcp -c nullfield --tail=20
kubectl -n nullfield-demo logs -l app=echo-mcp -c echo-server --tail=20
```

## Step 5: Test from inside the cluster

### 5a. Initialize

```bash
kubectl -n nullfield-demo run curl-test --rm -i --restart=Never \
  --image=curlimages/curl -- \
  curl -s -X POST http://echo-mcp:9090/mcp \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
```

Expected output:

```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","serverInfo":{"name":"echo-mcp-server","version":"0.1.0"},"capabilities":{"tools":{}}}}
```

### 5b. Call an allowed tool

```bash
kubectl -n nullfield-demo run curl-test --rm -i --restart=Never \
  --image=curlimages/curl -- \
  curl -s -X POST http://echo-mcp:9090/mcp \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello from k8s"}}}'
```

Expected output:

```json
{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"echo-server executed tool=\"echo\" args=map[message:hello from k8s] at 2026-04-19T..."}]}}
```

### 5c. Call an unregistered tool (blocked by registry)

```bash
kubectl -n nullfield-demo run curl-test --rm -i --restart=Never \
  --image=curlimages/curl -- \
  curl -s -X POST http://echo-mcp:9090/mcp \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"admin.drop_tables","arguments":{}}}'
```

Expected output:

```json
{"jsonrpc":"2.0","id":3,"error":{"code":-32003,"message":"tool not registered: admin.drop_tables"}}
```

### 5d. Call a denied tool (blocked by policy)

```bash
kubectl -n nullfield-demo run curl-test --rm -i --restart=Never \
  --image=curlimages/curl -- \
  curl -s -X POST http://echo-mcp:9090/mcp \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"dangerous_tool","arguments":{}}}'
```

Expected output:

```json
{"jsonrpc":"2.0","id":4,"error":{"code":-32000,"message":"denied by policy: tool dangerous_tool matched deny rule"}}
```

### 5e. Check health endpoint

```bash
kubectl -n nullfield-demo run curl-test --rm -i --restart=Never \
  --image=curlimages/curl -- \
  curl -s http://echo-mcp:9091/healthz
```

Expected output:

```json
{"status":"ok"}
```

## Step 6: Check nullfield logs

```bash
kubectl -n nullfield-demo logs -l app=echo-mcp -c nullfield --tail=30
```

Expected output (structured JSON, one line per event):

```
{"level":"info","msg":"audit","event":"tool.allowed","tool":"echo","method":"tools/call","reason":"matched allow rule"}
{"level":"info","msg":"audit","event":"tool.denied","tool":"dangerous_tool","method":"tools/call","reason":"matched deny rule: wildcard"}
{"level":"info","msg":"audit","event":"tool.rejected","tool":"admin.drop_tables","method":"tools/call","reason":"tool not registered"}
```

## Step 7: Using Helm instead

For production deployments, use the Helm chart which handles ConfigMaps, RBAC, ServiceMonitor, and sidecar injection automatically:

```bash
helm install nullfield-demo deploy/helm/nullfield \
  --namespace nullfield-demo \
  --create-namespace \
  --set sidecar.upstream="localhost:8080" \
  --set sidecar.image.tag="latest"
```

The chart supports:
- Custom `policy.yaml` and `tools.yaml` via `--set-file`
- Prometheus ServiceMonitor creation
- Grafana dashboard ConfigMap
- Controller deployment for dynamic policy updates

See [`deploy/helm/nullfield/README.md`](../../deploy/helm/nullfield/README.md) for full values reference.

## Cleanup

```bash
kubectl delete namespace nullfield-demo
```

## Next steps

- **Controller demo** — dynamic policy updates without pod restarts (see `deploy/helm/nullfield/templates/controller-deployment.yaml`)
- **Mesh integration** — Istio/Linkerd/Cilium overlays in `meshes/`
