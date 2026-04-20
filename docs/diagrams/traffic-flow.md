# Traffic Flow Diagrams

How traffic flows through nullfield in each deployment mode.

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
