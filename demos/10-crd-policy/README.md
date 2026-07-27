# Demo 10 — CRD Policy Management

Make `kubectl apply` the control plane for a running sidecar. A
`NullfieldPolicy` custom resource is reconciled into the ConfigMap a workload
mounts, so granting a tool is a pull request rather than an exec into a pod.

The payoff is step 5: edit the CRD, re-apply, and watch a sidecar that was
denying a tool start allowing it, with no restart.

```bash
demos/10-crd-policy/test.sh                        # against the current cluster
BUILD_IMAGES=true demos/10-crd-policy/test.sh      # build and import for k3s first
KEEP=true demos/10-crd-policy/test.sh              # leave the namespace up to poke at
```

Tier 2, so it is not gated in CI. Verified on k3s v1.35.

## The one setting that makes this work

The controller has two ways of reconciling a `NullfieldPolicy`, and only one of
them reaches a sidecar:

| | What it writes | Who reads it |
|---|---|---|
| Default | A ConfigMap per policy, named `nullfield-policy-<name>` | Nothing, unless you wire it up yourself |
| Active-target bridge | One ConfigMap you nominate, holding the policy you nominate | The sidecar that mounts it |

The bridge is off unless `NULLFIELD_ACTIVE_TARGET_CM` **and**
`NULLFIELD_ACTIVE_TARGET_LABEL` are both set. Miss either and `kubectl apply`
appears to succeed, a ConfigMap does appear, and nothing about the running
sidecar changes — the least helpful kind of failure. `controller.yaml` sets:

```yaml
- name: NULLFIELD_ACTIVE_TARGET_CM
  value: "crd-demo-active-policy"      # the ConfigMap the workload mounts
- name: NULLFIELD_ACTIVE_TARGET_KEY
  value: "policy.yaml"                 # the key inside it
- name: NULLFIELD_ACTIVE_TARGET_LABEL
  value: "crd-demo"                    # selects which policy wins
```

The label is the selector, so the policy has to opt in:

```yaml
metadata:
  name: crd-demo
  labels:
    nullfield.io/active-for: crd-demo
```

The first policy carrying a matching label wins. There is no merging and no
ordering guarantee, so keep it to one policy per label.

## What the demo deploys

```text
  kubectl apply -f policy.yaml
           │
           ▼
   NullfieldPolicy CRD ────► controller (polls every 10s)
                                 │
                                 ▼
                     ConfigMap crd-demo-active-policy
                                 │  (kubelet refreshes the volume)
                                 ▼
                  ┌──────────────────────────────┐
                  │  crd-demo-runtime pod        │
                  │                              │
                  │  nullfield ──► echo-server   │
                  │  :9090         :8080         │
                  │   ▲  polls policy.yaml /10s  │
                  └───┼──────────────────────────┘
                      │
                 tool calls
```

- `controller.yaml` — a namespace-scoped controller with the bridge on, plus
  the RBAC it needs. It has to `create` and `update` ConfigMaps, not just read
  them.
- `tools.yaml` — the tool registry, as a plain ConfigMap. Only the policy is
  CRD-driven here, which keeps the demo to one moving part.
- `policy.yaml` — the `NullfieldPolicy`. Grants `cost.check_usage` and denies
  everything else.
- `workload.yaml` — echo-server with a nullfield sidecar.

## How long propagation actually takes

Roughly **80 seconds**, measured. Three legs, and only the first is yours to
tune:

| Leg | Default | Tunable |
|---|---|---|
| CRD → ConfigMap | 30s poll | Yes, `NULLFIELD_CRD_WATCH_INTERVAL`. This demo sets 10s |
| ConfigMap → the file in the pod | up to ~60s | Only by kubelet's sync period, cluster-wide |
| File → sidecar's policy engine | 10s poll | No, it is hardcoded |

Older versions of this page claimed 30 seconds, which was the first leg
mistaken for the whole trip. If you need this to be fast, the kubelet leg is
the one that dominates, and no nullfield setting touches it.

## Two things that will bite you

**Do not mount the policy with `subPath`.** kubelet copies a `subPath` mount
once at container start and never refreshes it, so the sidecar stays pinned to
whatever the policy said when the pod started, forever, silently.
`workload.yaml` uses a projected volume to combine the policy and registry
ConfigMaps into one directory, and projected sources refresh normally.

**The registry does not hot-reload.** `pkg/registry` is safe to reload but
nothing reloads it, so a `ToolRegistry` change needs a pod restart even though
a `NullfieldPolicy` change does not. Adding a tool is a rollout; granting an
already-registered tool is an apply.

## What the test asserts

```
the crd reaches a sidecar:
  ok:  the controller renders the labelled CRD into the sidecar's ConfigMap
  ok:  the ConfigMap records which CRD it came from

the policy in the crd is the policy being enforced:
  ok:  a tool the CRD grants is allowed
  ok:  a registered tool the CRD does not grant is refused by policy
  ok:  audit.list_actions starts out denied

editing the crd changes the running sidecar's mind:
  ok:  kubectl apply on the CRD flipped a live deny into an allow, with no restart
       (took 80s to propagate)
  ok:  no container restarted while that happened
  ok:  the rest of the policy is unchanged
```

The restart check matters: without it a pod that happened to cycle would make
the demo pass for the wrong reason and prove nothing about hot-reload.

`secrets.read_config` is registered in `tools.yaml` on purpose so its refusal
comes from policy (`-32000`) rather than from the registry (`-32003`). A demo
where every "no" comes from the registry cannot tell the two gates apart.

## Related

- Demo 14 reconciles an `AgenticFlow` instead, which compiles to a policy *and*
  a registry.
- Demo 09 covers the controller's other job, aggregating decisions from every
  sidecar.
