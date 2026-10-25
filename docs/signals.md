# Signals

A signal is a decision event delivered to whoever acts on it, typically the
controller that launched a run's pod. nullfield refuses the call; the
controller decides what happens to the run, such as ending its pod.
nullfield never deletes pods itself, so it never holds that permission.

Supported by `nullfield-extauthz`. Delivery is asynchronous and never delays a
decision.

## What is signalled

By default only `circuit.tripped`: a run that went past its
[circuit breaker](identity-policy.md#run-tokens-ext_authz). It is emitted
**once per run**, on the first refused call, however many calls the run
makes after that. Every refused call is still an `arbiter.decision` in the
audit stream.

`NULLFIELD_SIGNAL_EVENTS` selects other types, comma-separated, from those
this service emits: `circuit.tripped`, `arbiter.decision` (every decision;
high volume), `anomaly.velocity`. Any other value refuses to start.

## Channels

Each channel is optional and independent; enable any combination.

| Variable | Meaning |
|---|---|
| `NULLFIELD_SIGNAL_EVENTS` | Event types to deliver. Default `circuit.tripped` |
| `NULLFIELD_SIGNAL_KUBE_EVENTS` | `true` records Kubernetes Events |
| `NULLFIELD_SIGNAL_WEBHOOK_URL` | POSTs each event here |
| `NULLFIELD_SIGNAL_WEBHOOK_SECRET_FILE` | Signing secret, required with the URL. A file, so it can come from a Secret (External Secrets Operator included) and never sits in the environment |
| `NULLFIELD_AUDIT_ENDPOINT` | OTLP gRPC endpoint: every audit event as a span, signals included |

A channel that is asked for and cannot be built refuses to start: an
unreadable secret file, a URL with no scheme, Kubernetes Events off-cluster.

### Kubernetes Events

An `events.k8s.io/v1` Event in the workload's namespace:

| Field | Value |
|---|---|
| `regarding` | the caller's ServiceAccount, from its attested SPIFFE ID |
| `reason` | the event type in CamelCase: `CircuitTripped` |
| `type` | `Warning` |
| `note` | `run <id>: <reason>` |
| `reportingController` | `nullfield.io/extauthz` |
| annotations | `nullfield.io/run-id`, `nullfield.io/workload`, `nullfield.io/reason-class`, and `nullfield.io/target` and `nullfield.io/action` when set |

A controller that already watches the API server can watch these:

```bash
kubectl get events.events.k8s.io -n agents --field-selector reason=CircuitTripped
```

An event about a caller that was not attested names no ServiceAccount and is
not recorded.

The API server is verified against the service account CA, and the token is
re-read on each delivery because projected tokens rotate.

RBAC: `create` on `events.k8s.io` `events` in every namespace whose workloads
it decides for. Use a Role per namespace, or a ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: nullfield-extauthz-signals
rules:
  - apiGroups: ["events.k8s.io"]
    resources: ["events"]
    verbs: ["create"]
```

### Webhook

The audit event as JSON, signed:

| Header | Value |
|---|---|
| `X-Nullfield-Timestamp` | Unix seconds |
| `X-Nullfield-Signature` | `sha256=` + hex HMAC-SHA256 over timestamp, `.`, body |

The receiver must check the signature with a constant-time compare and reject
stale timestamps, or anyone who can reach it can end runs, or replay an old
signal. [Demo 19](../demos/19-signals/) has a receiver that does both in
twenty lines of Python.

A non-2xx response or a network error is retried four times with backoff
(1s, 2s, 4s, 8s), then logged as `signal not delivered`.

On a mesh, keep the receiver off the waypoint nullfield authorizes, or
nullfield will be asked to authorize its own signal.

## Limits

Each channel queues up to 256 events. A full queue drops the event and logs
`signal dropped: queue full` rather than delaying a decision, and events
still queued when the process exits are lost. A controller that must not miss
a trip should also reconcile from the audit stream (OTLP or logs), where every
refusal is recorded.

## `onTrip`

`circuitBreaker.onTrip` stays `DENY` (or empty, or `REJECT`): a tripped
breaker refuses calls. Values that would act on the workload, such as
`KILL_POD`, refuse to load. Ending the workload is the controller's job, on
this signal.
