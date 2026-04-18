# nullfield — Service Mesh Integration Guide

nullfield is a sidecar that operates at the MCP/agentic application layer. Service meshes operate at the network transport layer. They are complementary:

```text
Mesh (Envoy / Linkerd / Cilium)  =  mTLS, traffic routing, network policy, retries
nullfield                         =  MCP tool registry, policy engine, identity, audit
```

This guide covers how to deploy nullfield in clusters running Istio, Linkerd, Cilium, or no mesh at all.

---

## Deployment Profiles

| Profile | Sidecars per pod | mTLS provider | MCP enforcement | Deploy command |
|---------|-----------------|---------------|-----------------|----------------|
| Bare | 1 (nullfield) | None | nullfield | `kubectl apply -f deploy/manifests/` |
| Istio | 2 (Envoy + nullfield) | Istio | nullfield | `kubectl apply -k deploy/overlays/istio/` |
| Linkerd | 2 (linkerd-proxy + nullfield) | Linkerd | nullfield | `kubectl apply -k deploy/overlays/linkerd/` |
| Cilium | 1 (nullfield) | Cilium eBPF | nullfield | `kubectl apply -k deploy/overlays/cilium/` |

---

## Bare (No Mesh)

This is the default. The existing manifests in `deploy/manifests/` work without any mesh.

```text
Client ──► :9090 nullfield ──► :8080 App
                 │
            :9091 admin
```

What you get:
- MCP tool registry enforcement
- Policy engine (ALLOW/DENY per tool)
- Circuit breaker
- Structured audit logging
- Identity via Bearer token header

What you do not get:
- mTLS between services
- Network-level access control
- Automatic retries or traffic shifting

This is appropriate for development, testing, single-node clusters, and environments where network-level security is handled elsewhere (e.g. VPN, firewall rules).

---

## Istio

### Traffic flow

```text
Client ──► Envoy (mTLS termination) ──► :9090 nullfield ──► :8080 App
                                              │
                                         :9091 admin (bypasses Envoy)
```

Istio's Envoy sidecar handles mTLS, network policy, and observability. nullfield handles MCP-layer enforcement. Both run as sidecars in the same pod.

### Pod annotations

```yaml
metadata:
  annotations:
    # Let kubelet health probes reach nullfield directly (bypass Envoy)
    traffic.sidecar.istio.io/excludeInboundPorts: "9091"
    # Tell Istio that port 9090 speaks HTTP (for proper L7 routing)
    sidecar.istio.io/interceptionMode: REDIRECT
```

### Mesh CRDs

**PeerAuthentication** — enforce STRICT mTLS on the namespace:

```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: nullfield-mtls
  namespace: nullfield
spec:
  mtls:
    mode: STRICT
```

**AuthorizationPolicy** — restrict which services can reach nullfield:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: nullfield-authz
  namespace: nullfield
spec:
  selector:
    matchLabels:
      app: nullfield-demo
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/*/sa/*"]
      to:
        - operation:
            ports: ["9090"]
            methods: ["POST"]
    - to:
        - operation:
            ports: ["9091"]
```

### What each layer handles

| Concern | Istio (Envoy) | nullfield |
|---------|--------------|-----------|
| mTLS | Yes | No |
| Network access control | AuthorizationPolicy | No |
| MCP tool enforcement | No | Yes |
| Tool registry allowlist | No | Yes |
| Per-tool rate limiting | No | Yes |
| Circuit breaker (agent loops) | No | Yes |
| Structured MCP audit trail | No | Yes |
| Traffic metrics (RPS, latency) | Yes | No |
| Retries, timeouts | Yes | No |

### Gotchas

- Envoy rewrites health probes by default. Use `excludeInboundPorts` to let kubelet reach `:9091` directly, otherwise liveness probes may fail during Envoy startup.
- Istio injects its sidecar via mutating webhook. nullfield is added manually (or via its own Helm template). The two injection mechanisms are independent and do not conflict.
- If your MCP traffic uses Streamable HTTP (SSE), make sure Istio is not buffering the response. Set `sidecar.istio.io/interceptionMode: REDIRECT` (the default) rather than `TPROXY`.

### Deploy

```bash
kubectl apply -k deploy/overlays/istio/
```

---

## Linkerd

### Traffic flow

```text
Client ──► linkerd-proxy (mTLS) ──► :9090 nullfield ──► :8080 App
                                          │
                                     :9091 admin
```

### Pod annotations

```yaml
metadata:
  annotations:
    linkerd.io/inject: enabled
    # If MCP traffic is not standard HTTP/1.1 (e.g. SSE streaming),
    # mark port 9090 as opaque so Linkerd doesn't try to parse it
    config.linkerd.io/opaque-ports: "9090"
    # Skip proxy for admin port (health probes)
    config.linkerd.io/skip-inbound-ports: "9091"
```

### Mesh CRDs

**Server** — define the nullfield proxy port as a named server:

```yaml
apiVersion: policy.linkerd.io/v1beta3
kind: Server
metadata:
  name: nullfield-proxy
  namespace: nullfield
spec:
  podSelector:
    matchLabels:
      app: nullfield-demo
  port: 9090
  proxyProtocol: HTTP/1
```

**ServerAuthorization** — restrict access to the proxy port:

```yaml
apiVersion: policy.linkerd.io/v1beta1
kind: ServerAuthorization
metadata:
  name: nullfield-proxy-authz
  namespace: nullfield
spec:
  server:
    name: nullfield-proxy
  client:
    meshTLS:
      identities:
        - "*.nullfield.serviceaccount.identity.linkerd.cluster.local"
```

### What each layer handles

| Concern | Linkerd | nullfield |
|---------|---------|-----------|
| mTLS | Yes | No |
| Service-to-service authz | ServerAuthorization | No |
| MCP tool enforcement | No | Yes |
| Tool registry allowlist | No | Yes |
| Per-tool rate limiting | No | Yes |
| Circuit breaker (agent loops) | No | Yes |
| Structured MCP audit trail | No | Yes |
| Golden metrics (RPS, latency, success) | Yes | No |

### Gotchas

- Linkerd's opaque port annotation is important if your MCP server uses anything other than plain HTTP/1.1 (e.g. SSE, WebSocket upgrade). Without it, Linkerd may try to parse the stream and break it.
- Linkerd does not inject into Jobs by default. If nullfield sidecars an ephemeral Job (like a KosmosJobAgent), add `linkerd.io/inject: enabled` to the Job's pod template.
- `skip-inbound-ports` ensures kubelet probes on `:9091` are not proxied. Without this, probes may fail during linkerd-proxy startup.

### Deploy

```bash
kubectl apply -k deploy/overlays/linkerd/
```

---

## Cilium

### Traffic flow

```text
Client ──► Cilium eBPF (mTLS, L3/L4/L7 policy) ──► :9090 nullfield ──► :8080 App
                                                          │
                                                     :9091 admin
```

Cilium is different from Istio and Linkerd: there is no sidecar proxy. Cilium operates at the kernel level via eBPF. This means nullfield is the only sidecar in the pod.

### Pod annotations

No Cilium-specific pod annotations are needed. Cilium applies policy based on labels and CiliumNetworkPolicy resources.

### Mesh CRDs

**CiliumNetworkPolicy** — restrict L7 access to nullfield ports:

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: nullfield-policy
  namespace: nullfield
spec:
  endpointSelector:
    matchLabels:
      app: nullfield-demo
  ingress:
    - fromEndpoints:
        - {}
      toPorts:
        - ports:
            - port: "9090"
              protocol: TCP
          rules:
            http:
              - method: POST
        - ports:
            - port: "9091"
              protocol: TCP
          rules:
            http:
              - method: GET
                path: "/healthz"
              - method: GET
                path: "/readyz"
```

### What each layer handles

| Concern | Cilium | nullfield |
|---------|--------|-----------|
| mTLS (WireGuard or SPIFFE) | Yes | No |
| L3/L4 network policy | CiliumNetworkPolicy | No |
| L7 HTTP path filtering | CiliumNetworkPolicy | No |
| MCP tool enforcement | No | Yes |
| Tool registry allowlist | No | Yes |
| Per-tool rate limiting | No | Yes |
| Circuit breaker (agent loops) | No | Yes |
| Structured MCP audit trail | No | Yes |
| Hubble observability | Yes | No |

### Gotchas

- Cilium's L7 HTTP rules can restrict paths and methods at the network level, but they cannot inspect JSON-RPC payloads. nullfield is still needed for tool-level enforcement.
- If Cilium mutual authentication is enabled (SPIFFE-based), nullfield's identity verification is a second layer on top. The two do not conflict.
- Cilium is the lightest-weight option for mesh integration because there is no additional sidecar — just nullfield + the app.

### Deploy

```bash
kubectl apply -k deploy/overlays/cilium/
```

---

## Choosing a Profile

| If your cluster runs... | Use profile... | Sidecars | Notes |
|------------------------|---------------|----------|-------|
| No mesh | Bare | 1 | Simplest. MCP enforcement only. |
| Istio | Istio | 2 | Full mesh + MCP enforcement. Most common in enterprise. |
| Linkerd | Linkerd | 2 | Lighter mesh + MCP enforcement. |
| Cilium | Cilium | 1 | eBPF mesh + MCP enforcement. No extra sidecar. |
| Multiple meshes | Pick the one your namespace uses | Varies | nullfield is mesh-agnostic. |

---

## Future: ext_authz and WASM

Two additional integration patterns are on the roadmap but not yet implemented:

**Pattern B — ext_authz filter backend**: nullfield runs as a cluster service (not a sidecar) and Envoy calls it via the `ext_authz` gRPC filter on every request. One sidecar (Envoy), one central nullfield deployment. Reduces per-pod overhead but adds network hop latency.

**Pattern C — WASM filter**: nullfield's core MCP parsing and policy logic compiled to WASM and loaded into Envoy as an in-process filter. Zero additional sidecars or services. Lowest latency but requires a significant rewrite and has WASM sandbox limitations (no filesystem, no Vault calls).

These will be documented here when available.
