# nullfield — Service Mesh Integration Guide

nullfield decides whether an agentic action is permitted. A service mesh moves and secures the bytes. The division of labour is the same in every profile below:

```text
Mesh (Envoy / Linkerd / Cilium)  =  mTLS, traffic routing, network policy, retries
nullfield                         =  MCP tool registry, policy engine, identity, audit
```

What differs is **where nullfield sits**, and there are two answers:

**In path, as a proxy.** nullfield is a sidecar; traffic flows through it; it forwards or refuses. This is the original shape and the subject of most of this guide.

**Out of path, as a decision service.** nullfield is a cluster service the mesh *asks*. Envoy calls it over the `ext_authz` gRPC API for each request and acts on the answer. Nothing flows through nullfield.

The second shape is not merely a deployment preference. It changes what nullfield can know and what it can promise:

| | Proxy | Decision service |
|---|---|---|
| Caller identity | a token the caller presents | the mesh's mTLS peer identity, which the caller cannot choose |
| Coverage | whatever is routed through the sidecar | every request the waypoint sees, including non-MCP traffic |
| Can it read responses? | yes | no — `ext_authz` sees the request only |
| Failure mode | in the blast radius; if it dies, traffic stops | out of it; Envoy's `failOpen` decides |
| Can it run read-only? | not meaningfully | yes — observe mode records what enforcement would have done |

Neither supersedes the other. A proxy can rewrite arguments and inspect responses, which `ext_authz` structurally cannot. A decision service gets attested identity and total coverage of a namespace, which a sidecar structurally cannot.

This guide covers deploying nullfield in clusters running Istio (sidecar or ambient), Linkerd, Cilium, or no mesh at all.

---

## Deployment Profiles

| Profile | Sidecars per pod | mTLS provider | MCP enforcement | Deploy command |
|---------|-----------------|---------------|-----------------|----------------|
| Bare | 1 (nullfield) | None | nullfield | `kubectl apply -f deploy/manifests/` |
| Istio | 2 (Envoy + nullfield) | Istio | nullfield | `kubectl apply -k meshes/istio/` |
| Linkerd | 2 (linkerd-proxy + nullfield) | Linkerd | nullfield | `kubectl apply -k meshes/linkerd/` |
| Cilium | 1 (nullfield) | Cilium eBPF | nullfield | `kubectl apply -k meshes/cilium/` |
| Istio ambient (`ext_authz`) | 0 | Istio (ztunnel) | nullfield, via the waypoint | `deploy/manifests/extauthz.yaml` + provider registration |

The last row is the decision-service shape: no sidecar is added to any application pod, and nullfield runs once per namespace as an ordinary service.

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
kubectl apply -k meshes/istio/
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
- Linkerd does not inject into Jobs by default. If nullfield sidecars an ephemeral Job (like a JobAgent), add `linkerd.io/inject: enabled` to the Job's pod template.
- `skip-inbound-ports` ensures kubelet probes on `:9091` are not proxied. Without this, probes may fail during linkerd-proxy startup.

### Deploy

```bash
kubectl apply -k meshes/linkerd/
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
kubectl apply -k meshes/cilium/
```

---

## K8s sidecar mode (camazotz reference)

The camazotz repo ships a reference deployment that runs nullfield as a sidecar in front of `brain-gateway` and exposes both the unenforced and enforced paths side-by-side, so you can A/B the same MCP traffic against the policy.

### Services

The manifest [`kube/brain-gateway-policed.yaml`](https://github.com/babywyrm/camazotz/blob/main/kube/brain-gateway-policed.yaml) layers a second `Service` over the existing `brain-gateway` pods:

| Endpoint | NodePort | Pod port | What it hits | Policy enforcement |
|----------|----------|----------|--------------|--------------------|
| `:30080` (default `brain-gateway`) | 30080 | 8080 (`brain-gateway` container) | upstream directly | **bypass** — no nullfield in the path |
| `:30090` (`brain-gateway-policed`) | 30090 | 9090 (nullfield sidecar) | nullfield → `brain-gateway` `:8080` | **enforced** — full policy + identity + audit |
| `:31591` (`brain-gateway-policed`) | 31591 | 9091 (nullfield admin) | nullfield admin API | n/a — `/healthz`, `/readyz`, `/metrics`, `/admin/holds` |

```text
Client ──┬──► :30080 ──► brain-gateway :8080                    (bypass; no policy)
         │
         └──► :30090 ──► nullfield :9090 ──► brain-gateway :8080 (policed)
                              │
                          :31591 ──► nullfield :9091 admin
```

### Why a separate Service?

The default `brain-gateway` `Service` targets pod port `8080` directly so existing existing camazotz tooling and the Streamlit operator UI keep working unmodified. The policed `Service` reuses the same pod selector but targets pod port `9090` — the nullfield sidecar's listen address. Both flow into the same pod; only the path through the pod differs.

This pattern lets you:

- Run smoke tests against `:30080` to confirm the application still works
- Run the same smoke tests against `:30090` to confirm the policy is firing
- Hit `:31591/admin/holds` while a request is parked, without exposing admin to the application path

### Verifying enforcement

The canonical verification target is `make smoke-k8s-policed` in the camazotz repo, which runs `scripts/smoke_test.py --target k8s --require-policed`. It probes both endpoints and asserts the enforcement asymmetry.

Live behavior on a single-node K3s NUC (with no client token):

```text
$ curl -s -X POST http://192.168.1.85:30080/mcp -d '{"jsonrpc":"2.0",...}'
HTTP/1.1 200 OK
{...result...}

$ curl -s -X POST http://192.168.1.85:30090/mcp -d '{"jsonrpc":"2.0",...}'
{"jsonrpc":"2.0","error":{"code":-32001,"message":"identity verification failed"},...}
```

Code `-32001` is nullfield's identity check; the bypass returns the upstream response unchanged. That's the contract `make smoke-k8s-policed` enforces.

### When to use this profile

- Validating new policy bundles against a real MCP attack surface (camazotz exposes 52 lab modules / 139 tools today)
- CI / lab smoke gates: `make smoke-k8s-policed` is the canonical "did the sidecar actually engage" probe
- Demos where a side-by-side bypass-vs-policed comparison is more illustrative than a single enforced path

This profile is independent of the mesh choice above. You can layer Istio, Linkerd, or Cilium on top — the policed `Service` keeps targeting nullfield regardless.

---

## Choosing a Profile

| If your cluster runs... | Use profile... | Sidecars | Notes |
|------------------------|---------------|----------|-------|
| No mesh | Bare | 1 | Simplest. MCP enforcement only. |
| Istio (sidecar) | Istio | 2 | Full mesh + MCP enforcement. Most common in enterprise. |
| Istio (ambient) | `ext_authz` | 0 | Attested identity, whole-namespace coverage, requests only. |
| Linkerd | Linkerd | 2 | Lighter mesh + MCP enforcement. |
| Cilium | Cilium | 1 | eBPF mesh + MCP enforcement. No extra sidecar. |
| Multiple meshes | Pick the one your namespace uses | Varies | nullfield is mesh-agnostic. |

Where Istio ambient is available, prefer the `ext_authz` profile for anything you want *observed*, and the proxy profile for anything you need *modified*. They are not mutually exclusive: the decision service can cover a whole namespace while a proxy sidecar sits in front of the one workload whose responses need redacting.

---

## Istio ambient — nullfield as an `ext_authz` decision service

Verified on k3s with Istio 1.30 ambient. Run `demos/16-mesh-arbiter/test.sh` for a working deployment that asserts everything described here.

### Traffic flow

```text
Client ──► ztunnel ──HBONE──► waypoint ──► App
                                 │
                                 └─gRPC─► nullfield-extauthz  (decides; not in path)
```

The waypoint pauses the request, calls nullfield with the method, path, headers and body, and applies the answer. nullfield never sees the response and never forwards anything.

### Deploy

```bash
kubectl apply -f deploy/manifests/extauthz.yaml
```

That manifest is a reference deployment, not a template: it names a namespace and a waypoint, and both must be changed for your cluster. The `AuthorizationPolicy` in particular carries a `targetRefs` entry naming the waypoint it binds to, and pointing it at one that does not exist fails quietly — see below. `demos/16-mesh-arbiter/arbiter.yaml` is a self-contained copy if you would rather start from a working example.

Then register it as an extension provider in the `istio` ConfigMap under `data.mesh`, and restart istiod:

```yaml
extensionProviders:
- name: nullfield-ext-authz
  envoyExtAuthzGrpc:
    service: nullfield-extauthz.<namespace>.svc.cluster.local
    port: 9191
    includeRequestBodyInCheck:
      maxRequestBytes: 8192
      allowPartialMessage: true   # observe; see below
```

Edit that config by parsing and re-emitting it, not by splicing text. A malformed `extensionProviders` list does not fail the patch — istiod logs `available providers are []` and **every** `CUSTOM` AuthorizationPolicy in the mesh quietly becomes a deny, including ones unrelated to nullfield. `demos/16-mesh-arbiter/register-provider.sh` does this safely.

### Modes

`NULLFIELD_EXTAUTHZ_MODE` takes `no-op`, `observe`, or `enforce`. Observe is the reason this shape exists: it renders a real decision, records what enforcement *would* have done as a `counterfactual` on the audit event, and returns OK. You can run it against production traffic and read the results before granting it authority over anything.

### Four things that fail silently

**`allowPartialMessage` must match the mode.** With `false`, Envoy answers any body over `maxRequestBytes` with a 413 *before* calling the check. nullfield never sees the request and cannot observe it, yet the traffic is already broken — so a rollout you declared read-only starts failing large requests. Use `true` for observe and no-op. Use `false` for enforce, where failing closed at the proxy is stronger than denying after the fact; nullfield's own truncation guard stays as defence in depth.

**A `CUSTOM` AuthorizationPolicy needs `targetRefs`.** Bound by selector instead, it attaches to ztunnel, which is L4 only and cannot run an HTTP filter. The provider is never consulted and nothing reports that it was skipped.

```yaml
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: Gateway
      name: <your>-waypoint
  action: CUSTOM
  provider:
    name: nullfield-ext-authz
```

**A second `CUSTOM` provider on the same workload needs a feature flag.** Without `PILOT_ENABLE_MULTIPLE_CUSTOM_AUTHZ_PROVIDERS=true` on istiod, Istio drops one of them and the incumbent decides alone. Relevant when adding nullfield beside an existing OPA deployment.

**The check arrives anonymous without an EnvoyFilter.** A waypoint terminates HBONE upstream of the listener running `ext_authz`, so there is no peer certificate to read there and `source.principal` is empty however healthy the mesh is. Istio publishes the identity into Envoy filter state instead. Apply `deploy/manifests/peer-principal-envoyfilter.yaml`, which copies it into a request header the check does receive.

nullfield does not trust that header — the filter strips any inbound value of the same name before writing its own, so a workload cannot assert its own identity by sending it. **A deployment without this filter must not treat the header as meaningful.** Header-derived identity is reported as the `mesh-header` attester rather than `mesh-spiffe`, because the binding differs even where the identity is the same. See [Identity-Aware Policy](identity-policy.md#workload-attestation) for what that distinction buys you.

### What each layer handles

| Concern | Handled by |
|---------|-----------|
| mTLS between workloads | ztunnel |
| Workload identity (SPIFFE) | Istio, read by nullfield via the waypoint |
| L7 routing | waypoint |
| MCP tool policy | nullfield |
| Audit trail with provenance | nullfield |
| Response inspection | **nobody** — `ext_authz` cannot see responses |

That last row is the real trade. If you need response redaction or argument rewriting, run the proxy profile, either instead of this one or alongside it.

### Limits

- **Requests only.** `SCOPE` and response inspection need `ext_proc`, which is not yet implemented.
- **Bodies are capped** at `maxRequestBytes`. nullfield refuses to decide on a truncated body rather than authorizing the part that fit; see above for why the mode must match.
- **Long-lived connections are authorized once.** A `kubectl exec` stream is one request at setup and invisible afterwards.

---

## Future: WASM

**Pattern C — WASM filter**: nullfield's core MCP parsing and policy logic compiled to WASM and loaded into Envoy as an in-process filter. Zero additional sidecars or services. Lowest latency but requires a significant rewrite and has WASM sandbox limitations (no filesystem, no Vault calls).

This will be documented here when available.
