# nullfield Helm Chart

Arbiter for MCP and agentic traffic. Deploys a sidecar proxy that intercepts every MCP tool call and enforces policy. Optionally adds a controller pod for centralized holds, shared budgets, and webhook alerting.

---

## Which mode should I use?

**Start with sidecar-only.** It covers 90% of use cases with zero extra infrastructure.

| I need... | Mode | What to set |
|---|---|---|
| Policy enforcement on one MCP server | Sidecar-only | `controller.enabled=false` (default) |
| Multiple MCP servers, each with own policy | Sidecar-only + targets | `controller.enabled=false`, add `targets[]` |
| Shared budgets across replicas | Full | `controller.enabled=true` |
| Centralized hold approvals (one admin API) | Full | `controller.enabled=true` |
| Webhook/Slack alerting | Full | `controller.enabled=true` + `controller.alerting.webhook` |
| Just evaluating nullfield | Sidecar-only, no Helm | Run the binary directly (see below) |

---

## Quick Install

### Sidecar-only (recommended starting point)

No controller, no extra pods. Just a sidecar next to your MCP server.

```bash
helm install nullfield deploy/helm/nullfield/ \
  --set 'targets[0].name=my-service' \
  --set 'targets[0].namespace=default' \
  --set 'targets[0].upstreamPort=8080' \
  --set 'targets[0].policyFile=files/examples/policy-minimal.yaml' \
  --set 'targets[0].registryFile=files/examples/tools-minimal.yaml'
```

This creates two ConfigMaps (`my-service-nullfield-config` and `my-service-nullfield-tools`) in the `default` namespace. Then add the sidecar to your Deployment:

```yaml
containers:
  - name: my-mcp-server
    image: my-app:latest
    ports:
      - containerPort: 8080
  - name: nullfield
    image: ghcr.io/babywyrm/nullfield:latest
    ports:
      - name: proxy
        containerPort: 9090
      - name: admin
        containerPort: 9091
    envFrom:
      - configMapRef:
          name: my-service-nullfield-config
    volumeMounts:
      - name: nullfield-tools
        mountPath: /etc/nullfield
        readOnly: true
    securityContext:
      runAsNonRoot: true
      runAsUser: 65534
      readOnlyRootFilesystem: true
volumes:
  - name: nullfield-tools
    configMap:
      name: my-service-nullfield-tools
```

Update your Service to point at port 9090 (nullfield) instead of 8080 (your app).

### Without Helm (bare binary)

```bash
export NULLFIELD_UPSTREAM_ADDR=localhost:8080
export NULLFIELD_POLICY_PATH=policy.yaml
export NULLFIELD_REGISTRY_PATH=tools.yaml
./nullfield
```

### Docker Compose

```bash
docker compose up -d
bash tests/smoke.sh
```

### Full mode (controller + sidecar)

For teams that need centralized holds, shared budgets across replicas, or webhook alerting:

```bash
helm install nullfield deploy/helm/nullfield/ \
  --set controller.enabled=true \
  --set 'targets[0].name=brain-gateway' \
  --set 'targets[0].namespace=camazotz' \
  --set 'targets[0].upstreamPort=8080' \
  --set 'targets[0].policyFile=files/camazotz/policy.yaml' \
  --set 'targets[0].registryFile=files/camazotz/tools.yaml' \
  --set monitoring.serviceMonitor.enabled=true \
  --set monitoring.alertRules.enabled=true
```

---

## Deployment Modes

| Mode | `controller.enabled` | `targets` | What gets deployed |
|---|---|---|---|
| Sidecar-only (default) | `false` | 1+ entries | Per-target ConfigMaps only |
| Full | `true` | 1+ entries | Controller Deployment + Service + RBAC + per-target ConfigMaps |
| Controller-only | `true` | `[]` | Controller Deployment + Service + RBAC (sidecars managed externally) |

---

## Values Reference

### Controller

| Key | Default | Description |
|---|---|---|
| `controller.enabled` | `false` | Deploy the controller pod |
| `controller.replicas` | `1` | Controller replica count |
| `controller.image.repository` | `ghcr.io/babywyrm/nullfield-controller` | Controller image |
| `controller.image.tag` | `latest` | Controller image tag |
| `controller.grpcPort` | `9092` | gRPC port (sidecar-to-controller) |
| `controller.adminPort` | `9093` | Admin REST API port |
| `controller.healthPort` | `9091` | Health/metrics port |
| `controller.resources` | 100m/128Mi req, 500m/256Mi lim | CPU/memory |
| `controller.alerting.webhook` | `""` | Webhook URL for alerts |
| `controller.alerting.slack.channel` | `""` | Slack channel |
| `controller.alerting.slack.token` | `""` | Slack bot token |

### Sidecar

| Key | Default | Description |
|---|---|---|
| `sidecar.image.repository` | `ghcr.io/babywyrm/nullfield` | Sidecar image |
| `sidecar.image.tag` | `latest` | Sidecar image tag |
| `sidecar.listenPort` | `9090` | Proxy listen port |
| `sidecar.adminPort` | `9091` | Admin/health port |
| `sidecar.resources` | 50m/64Mi req, 200m/128Mi lim | CPU/memory |

### Targets

Each entry in `targets[]` generates a ConfigMap pair (env config + policy/tools) for one workload:

| Key | Required | Description |
|---|---|---|
| `name` | yes | Target name (used in ConfigMap naming) |
| `namespace` | no | Target namespace (defaults to release namespace) |
| `upstreamPort` | no | Your app's port (default `8080`) |
| `policyFile` | no | Policy YAML path in chart `files/` directory |
| `registryFile` | no | Tool registry YAML path in chart `files/` directory |
| `identity.header` | no | Override identity extraction header |
| `identity.jwksURL` | no | Override JWKS endpoint |
| `circuit.maxCalls` | no | Override circuit breaker call limit |
| `circuit.maxDuration` | no | Override circuit breaker duration |
| `audit.logLevel` | no | Override audit log level |
| `audit.otelEndpoint` | no | Override OTLP collector endpoint |

### Global Defaults

Applied to all targets unless overridden per-target:

| Key | Default | Description |
|---|---|---|
| `identity.header` | `Authorization` | Header to extract Bearer token from |
| `identity.jwksURL` | `""` | JWKS endpoint (empty = noop verifier) |
| `circuit.maxCalls` | `100` | Max tool calls per session |
| `circuit.maxDuration` | `5m` | Max session duration |
| `audit.logLevel` | `FULL` | Audit verbosity: `FULL`, `SUMMARY`, `NONE` |
| `audit.otelEndpoint` | `""` | OTLP gRPC endpoint (empty = disabled) |

### Monitoring

| Key | Default | Description |
|---|---|---|
| `monitoring.serviceMonitor.enabled` | `false` | Create Prometheus ServiceMonitor |
| `monitoring.serviceMonitor.interval` | `15s` | Scrape interval |
| `monitoring.alertRules.enabled` | `false` | Create PrometheusRule (5 alert rules) |
| `monitoring.grafanaDashboard.enabled` | `false` | Create Grafana dashboard ConfigMap |

### Other

| Key | Default | Description |
|---|---|---|
| `mesh.provider` | `none` | Service mesh: `none`, `istio`, `linkerd`, `cilium` |
| `serviceAccount.create` | `true` | Create ServiceAccount |
| `serviceAccount.name` | `""` | Override SA name |
| `serviceAccount.annotations` | `{}` | SA annotations (e.g. IRSA, Workload Identity) |

---

## Target Configuration Examples

### Single target, sidecar-only

```yaml
controller:
  enabled: false

targets:
  - name: my-api
    namespace: default
    upstreamPort: 3000
    policyFile: files/examples/policy-minimal.yaml
    registryFile: files/examples/tools-minimal.yaml
```

### Multiple targets with controller

```yaml
controller:
  enabled: true
  alerting:
    webhook: "https://hooks.slack.com/services/T.../B.../xxx"

targets:
  - name: brain-gateway
    namespace: camazotz
    upstreamPort: 8080
    policyFile: files/camazotz/policy.yaml
    registryFile: files/camazotz/tools.yaml
    identity:
      jwksURL: "https://zitadel.camazotz.svc:8080/.well-known/jwks.json"
    circuit:
      maxCalls: 50

  - name: mcp-server
    namespace: artifice
    upstreamPort: 3000
    policyFile: files/examples/policy-minimal.yaml
    registryFile: files/examples/tools-minimal.yaml

monitoring:
  serviceMonitor:
    enabled: true
  alertRules:
    enabled: true
  grafanaDashboard:
    enabled: true
```

---

## Using the Sidecar Snippet (Helm subchart)

If your app uses Helm, add nullfield as a dependency and use the template helper:

```yaml
# Chart.yaml
dependencies:
  - name: nullfield
    version: "0.6.0"
    repository: "file://path/to/nullfield/deploy/helm/nullfield"
```

```yaml
# In your deployment template
containers:
  - name: my-app
    image: my-app:latest
  {{- include "nullfield.sidecar" .Subcharts.nullfield | nindent 2 }}
```

## Bundled Policy Files

The chart includes ready-to-use policy and registry files:

| Path | Description |
|---|---|
| `files/camazotz/policy.yaml` | 139-tool tiered policy (ALLOW safe, ALLOW write, DENY dangerous, DENY *) |
| `files/camazotz/tools.yaml` | 139-tool registry for the camazotz MCP server |
| `files/examples/policy-minimal.yaml` | 3-rule starter policy |
| `files/examples/tools-minimal.yaml` | 3-tool starter registry |

Add your own policy files under `files/your-app/` and reference them in `targets[].policyFile`.
