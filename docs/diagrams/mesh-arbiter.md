# Mesh Arbiter Diagrams

How nullfield behaves as an `ext_authz` decision service: where the caller's
identity comes from, how the three modes differ, and where the request body
stops being readable.

For the traffic shape, see [traffic-flow.md](traffic-flow.md#kubernetes--istio-ambient-ext_authz-decision-service).
For the gates themselves, see [policy-eval.md](policy-eval.md).

---

## Where the Caller's Identity Comes From

The obvious answer is wrong, and the wrong answer fails silently — the decision
service works perfectly and simply reports every caller as anonymous.

### What does not work

```text
Client ──HBONE/mTLS──► Waypoint ──► ext_authz filter ──► nullfield
        (identity is                       │
         right here)                       │  CheckRequest.source.principal = ""
                                           │  x-forwarded-client-cert          absent
                                           ▼  downstreamSslConnection()        nil
                                        nothing
```

ztunnel knows exactly who the caller is and logs it correctly. The waypoint
terminates HBONE on an *upstream* listener, so by the time the request reaches
the listener running `ext_authz`, the inner stream carries no TLS of its own.
There is no certificate to read, and `source.principal` arrives empty however
healthy the mesh is.

This is not specific to nullfield. Any `ext_authz` provider on an ambient
waypoint sees the same empty source.

### Where it actually lives

Probing every source reachable from that filter chain, against live traffic:

```text
downstreamSslConnection()                        nil      no TLS object at all
downstreamSslConnection():uriSanPeerCertificate()  --     unreachable
dynamicMetadata():get("istio_authn")             nil
connection():ssl()                               nil
filterState():get("io.istio.peer_principal")     FOUND ◄── the SPIFFE ID
```

Istio publishes the terminated connection's peer identity into Envoy **filter
state**. That is how `AuthorizationPolicy` principals keep working at waypoints.
`ext_authz` does not read filter state, which is the whole problem.

### The bridge

```text
                    Waypoint (Envoy)
┌──────────────────────────────────────────────────────────────┐
│                                                              │
│   filter state                                               │
│   io.istio.peer_principal = spiffe://.../ns/agents/sa/runner │
│              │                                               │
│              │ read                                          │
│              ▼                                               │
│   ┌─────────────────────────────┐                            │
│   │ Lua filter                  │  INSERT_BEFORE ext_authz   │
│   │                             │                            │
│   │ 1. strip any inbound        │  ◄── this is the security  │
│   │    x-nullfield-peer-        │      property, not the     │
│   │    principal header         │      copy below            │
│   │                             │                            │
│   │ 2. write it from            │                            │
│   │    filter state             │                            │
│   └──────────────┬──────────────┘                            │
│                  │                                           │
│                  ▼                                           │
│   ┌─────────────────────────────┐                            │
│   │ ext_authz filter            │ ──gRPC──► nullfield        │
│   └─────────────────────────────┘                            │
└──────────────────────────────────────────────────────────────┘
```

Step 1 is what makes step 2 trustworthy. The header is only meaningful because
a workload cannot set it on itself — the filter overwrites any value it sent.
**A deployment without this filter must not treat the header as meaningful.**

### What nullfield records

```text
source.principal present?
   │
   ├─ yes ──► MeshAttester       ──► attester: mesh-spiffe   (read from a cert)
   │                                 assurance: ATTESTED
   │
   └─ no ───► header present?
                 │
                 ├─ yes ──► MeshHeaderAttester ──► attester: mesh-header
                 │          (parses, or fails)     assurance: ATTESTED
                 │
                 └─ no ───► attester: none
                            assurance: NONE
                            principal recorded verbatim anyway, so that
                            "nothing arrived" and "arrived unparseable"
                            stay distinguishable
```

The certificate wins where both are present. The two attesters are named
separately because the binding differs: a certificate depends on TLS, a header
depends on a deployed filter. Same identity, different worth.

---

## The Three Modes

The mode changes only what nullfield *returns*. The decision, the audit event,
and the provenance are identical in all three — which is what makes observe
mode evidence rather than a guess.

```text
                          policy says DENY
                                 │
        ┌────────────────────────┼────────────────────────┐
        │                        │                        │
     no-op                    observe                  enforce
        │                        │                        │
   return OK               return OK              return DENIED
        │                        │                        │
   audit: minimal          audit: full             audit: full
                           counterfactual: DENY    counterfactual: (none)
        │                        │                        │
        ▼                        ▼                        ▼
   traffic passes          traffic passes          traffic blocked
                           and you now know
                           what would have
                           been blocked
```

A `counterfactual` on an *applied* decision would be a bug: it would read as
though enforcement had been shadowed when it had not.

```text
Rollout order:
  no-op ──► observe ──► read the counterfactuals ──► enforce
            │
            └─ this is the step that answers
               "what will enforcement break?"
               before it breaks anything
```

---

## The Buffer Boundary

`ext_authz` buffers up to `maxRequestBytes` of the request body. Past that
boundary is exactly where someone would place arguments they want the arbiter
not to read, so what happens there matters more than its obscurity suggests.

**The behaviour is set by mesh config, not by nullfield config.** This is the
trap: the mode is a nullfield setting, `allowPartialMessage` is an Istio one,
and they must agree.

```text
                     request body > maxRequestBytes
                                  │
             ┌────────────────────┴────────────────────┐
             │                                         │
   allowPartialMessage: false            allowPartialMessage: true
             │                                         │
             ▼                                         ▼
   Envoy returns 413                       Envoy forwards the first 8k
   BEFORE calling the check                + x-envoy-auth-partial-body: true
             │                                         │
             │                                         ▼
   nullfield never sees it                 nullfield sees it is partial
   and cannot observe it                             │
             │                                         ▼
             ▼                              refuses to decide
   traffic broken                           reason_class: body_truncated
   while observing nothing                  counterfactual: DENY
                                            caller still attributed
             │                                         │
             ▼                                         ▼
   correct for ENFORCE                      correct for OBSERVE
   (fails closed at the proxy,              (records the attempt without
    stronger than deciding late)             touching the response)
```

Setting `false` while in observe mode is the failure worth naming: a rollout
declared read-only starts rejecting large requests, and nullfield's log stays
silent because it was never asked.

The in-process guard remains in both cases, as defence in depth for anyone
running `true` while enforcing — which is what a reference OPA deployment in the
test mesh does. Measured there: a decision rendered on 8192 bytes of a
20109-byte request.
