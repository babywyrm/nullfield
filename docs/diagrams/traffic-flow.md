# Traffic Flow Diagrams

How traffic flows through nullfield in each deployment mode.

Companions: [policy-eval.md](policy-eval.md) for what happens once a request is
inside, and [mesh-arbiter.md](mesh-arbiter.md) for the ambient profile in depth.

---

## Local Development (binary or Docker Compose)

```text
MCP Client (Cursor, Claude, curl)
    │
    │  POST http://localhost:9090/mcp
    ▼
┌────────────────────┐
│  nullfield :9090   │
│  (proxy)           │
│                    │
│  ┌─ identity       │
│  ├─ registry       │     :9091 /healthz /readyz /metrics
│  ├─ circuit brk    │
│  ├─ policy eval    │
│  └─ audit emit     │
└─────────┬──────────┘
          │  http://localhost:8080/mcp
          ▼
┌────────────────────┐
│  MCP Server :8080  │
│  (camazotz,        │
│   echo-server,     │
│   your app)        │
└────────────────────┘
```

---

## Kubernetes — Bare (no mesh)

```text
┌─────────────────────────────────────────────────┐
│  Pod                                            │
│                                                 │
│  Service :9090 ──► nullfield ──► App :8080      │
│                       │                         │
│                       ├─ identity               │
│                       ├─ registry               │
│                       ├─ policy                 │
│                       ├─ circuit breaker        │
│                       └─ audit                  │
│                                                 │
│  :9091 admin ◄── kubelet probes                 │
└─────────────────────────────────────────────────┘
```

---

## Kubernetes — Istio

```text
┌─────────────────────────────────────────────────────────────┐
│  Pod                                                        │
│                                                             │
│  Service ──► Envoy ──► nullfield :9090 ──► App :8080        │
│                 │            │                               │
│                 │ mTLS       ├─ identity                     │
│                 │ AuthzPol   ├─ registry                     │
│                 │ metrics    ├─ policy                       │
│                 │            ├─ circuit breaker               │
│                 │            └─ audit                         │
│                 │                                             │
│                 │   :9091 admin ◄── kubelet (bypasses Envoy)  │
└─────────────────────────────────────────────────────────────┘

Envoy handles:  mTLS, AuthorizationPolicy, traffic metrics, retries
nullfield handles: MCP tool enforcement, policy, registry, audit
```

---

## Kubernetes — Linkerd

```text
┌─────────────────────────────────────────────────────────────────┐
│  Pod                                                            │
│                                                                 │
│  Service ──► linkerd-proxy ──► nullfield :9090 ──► App :8080    │
│                    │                 │                           │
│                    │ mTLS            ├─ identity                 │
│                    │ Server/AuthZ    ├─ registry                 │
│                    │ golden metrics  ├─ policy                   │
│                    │                 └─ audit                    │
│                    │                                             │
│                    │   :9091 admin ◄── kubelet (skip-inbound)    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Kubernetes — Cilium

```text
┌─────────────────────────────────────────────────┐
│  Pod                                            │
│                                                 │
│  Service :9090 ──► nullfield ──► App :8080      │
│                       │                         │
│                       ├─ identity               │
│                       ├─ registry               │
│                       ├─ policy                 │
│                       └─ audit                  │
│                                                 │
│  :9091 admin ◄── kubelet probes                 │
└─────────────────────────────────────────────────┘

Cilium eBPF (kernel level, no sidecar):
  mTLS (WireGuard/SPIFFE), CiliumNetworkPolicy L7 rules, Hubble observability
```

---

## Kubernetes — Istio ambient (`ext_authz` decision service)

The only profile where nullfield is neither inside the pod nor in the request
path. The waypoint pauses each request, asks nullfield, and acts on the answer.

```text
┌──────────────┐                          ┌──────────────┐
│ Client Pod   │                          │ App Pod      │
│              │                          │              │
│  (no sidecar)│                          │ (no sidecar) │
└──────┬───────┘                          └──────▲───────┘
       │                                         │
       │ HBONE (mTLS, ztunnel)                   │ plain HTTP
       ▼                                         │
┌──────────────────────────────────────────────────────────┐
│  Waypoint (Envoy, one per namespace)                     │
│                                                          │
│    terminate HBONE ──► ext_authz filter ──► route ───────┼──►
│                              │                           │
└──────────────────────────────┼───────────────────────────┘
                               │ gRPC CheckRequest
                               │ (method, path, headers, body)
                               ▼
                    ┌──────────────────────┐
                    │ nullfield-extauthz   │
                    │ :9191                │
                    │                      │
                    │  ├─ translate        │
                    │  ├─ attest workload  │
                    │  ├─ truncation guard │
                    │  ├─ policy           │
                    │  └─ audit            │
                    └──────────────────────┘
                               │ OK / Denied
                               └──────────► back to the filter

The response never passes through nullfield. Nothing does.
```

What each layer handles:

```text
ztunnel           mTLS, L4 identity, HBONE transport
waypoint          L7 routing, calls the decision service
nullfield         MCP tool policy, attested provenance, audit
nobody            response inspection - ext_authz sees requests only
```

Deployment count: **one nullfield per namespace**, not one per pod. No
application pod is modified, which is the operational argument for this profile
and the reason it can be added to a running namespace.

See [mesh-arbiter.md](mesh-arbiter.md) for how identity reaches the decision
service, how the three modes differ, and where the buffer boundary sits.
