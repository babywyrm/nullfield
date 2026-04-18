# Traffic Flow Diagrams

How traffic flows through nullfield in each deployment mode.

---

## Local Development (binary or Docker Compose)

```text
MCP Client (Cursor, Claude, curl)
    │
    │  POST http://localhost:9090/mcp
    ▼
┌──────────────────┐
│  nullfield:9090  │
│  (proxy)         │
│                  │
│  ┌─ identity     │
│  ├─ registry     │     :9091 /healthz /readyz
│  ├─ circuit brk  │
│  ├─ policy eval  │
│  └─ audit emit   │
└────────┬─────────┘
         │  http://localhost:8080/mcp (or echo-server:8080 in compose)
         ▼
┌──────────────────┐
│  MCP Server:8080 │
│  (camazotz,      │
│   echo-server,   │
│   your app)      │
└──────────────────┘
```

---

## Kubernetes — Bare (no mesh)

```text
                    ┌─────────────────────────────────────────┐
                    │  Pod                                    │
                    │                                        │
 Service:9090 ─────────► :9090 nullfield ──► :8080 App      │
                    │       │                                │
                    │       ├─ identity                      │
                    │       ├─ registry                      │
                    │       ├─ policy                        │
                    │       ├─ circuit breaker               │
                    │       └─ audit                         │
                    │                                        │
                    │  :9091 admin ◄── kubelet probes        │
                    └─────────────────────────────────────────┘
```

---

## Kubernetes — Istio

```text
                    ┌─────────────────────────────────────────────────────┐
                    │  Pod                                                │
                    │                                                     │
 Service:9090 ──► Envoy ──► :9090 nullfield ──► :8080 App               │
                    │  │          │                                       │
                    │  │ mTLS     ├─ identity                            │
                    │  │ AuthzPol ├─ registry                            │
                    │  │ metrics  ├─ policy                              │
                    │  │          ├─ circuit breaker                     │
                    │  │          └─ audit                               │
                    │  │                                                  │
                    │  │     :9091 admin ◄── kubelet (bypasses Envoy)    │
                    └─────────────────────────────────────────────────────┘

Envoy handles:  mTLS, AuthorizationPolicy, traffic metrics, retries
nullfield handles: MCP tool enforcement, policy, registry, audit
```

---

## Kubernetes — Linkerd

```text
                    ┌───────────────────────────────────────────────────────────┐
                    │  Pod                                                      │
                    │                                                           │
 Service:9090 ──► linkerd-proxy ──► :9090 nullfield ──► :8080 App             │
                    │  │                  │                                     │
                    │  │ mTLS             ├─ identity                          │
                    │  │ Server/AuthZ     ├─ registry                          │
                    │  │ golden metrics   ├─ policy                            │
                    │  │                  └─ audit                             │
                    │  │                                                        │
                    │  │     :9091 admin ◄── kubelet (skip-inbound-ports)      │
                    └───────────────────────────────────────────────────────────┘
```

---

## Kubernetes — Cilium

```text
                    ┌─────────────────────────────────────────┐
                    │  Pod                                    │
                    │                                        │
 Service:9090 ─────────► :9090 nullfield ──► :8080 App      │
                    │       │                                │
                    │       ├─ identity                      │
                    │       ├─ registry                      │
                    │       ├─ policy                        │
                    │       └─ audit                         │
                    │                                        │
                    │  :9091 admin ◄── kubelet probes        │
                    └─────────────────────────────────────────┘

Cilium eBPF (kernel level, no sidecar):
  mTLS (WireGuard/SPIFFE), CiliumNetworkPolicy L7 rules, Hubble observability
```
