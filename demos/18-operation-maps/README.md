# Demo 18 — Operation Maps on the Mesh

Rules that match raw paths repeat each API's routes in every policy and miss
other spellings of the same path. An operation map names each call once, as
data. This demo maps a stand-in REST API, sends real traffic through a
waypoint, and shows policy deciding on names and parameters.

See [Operation Maps](../../docs/operation-maps.md) for the reference.

## Prerequisites

- Demo 16's environment: Istio ambient, its extension provider registered
  (`APPLY_MESH_CONFIG=true demos/16-mesh-arbiter/test.sh` once)
- `kubectl`, `python3` on the machine running the script

## Run

```bash
BUILD_IMAGES=true ./demos/18-operation-maps/test.sh   # builds and imports on k3s
./demos/18-operation-maps/test.sh                     # images already current
```

It shares demo 16's namespace and changes three things there:

- the policy;
- the AuthorizationPolicy, which now sends every method to the arbiter, not
  only POST;
- the arbiter deployment, which gains `NULLFIELD_OPERATIONS_DIR` and a volume
  for the map.

Demos 16 and 17 restore their policy and AuthorizationPolicy on their next
run. The env var and volume stay, because `kubectl apply` keeps fields it did
not set. They are harmless while the `nullfield-extauthz-operations`
ConfigMap exists.

## The map

`mcp-echo` stands in for a REST API: it answers any path.

```yaml
target: mcp-echo
operations:
  - {name: repos.get,     method: GET,    path: "/repos/{owner}/{repo}"}
  - {name: repos.delete,  method: DELETE, path: "/repos/{owner}/{repo}"}
  - {name: issues.create, method: POST,   path: "/repos/{owner}/{repo}/issues"}
```

## The policy

```yaml
- action: DENY
  celExpression: has(request.action) && request.action == "repos.delete"
- action: ALLOW
  celExpression: has(request.action) && request.params.owner == "acme"
```

Everything else falls to default deny.

## What it proves

| # | Call | Result |
|---|---|---|
| 1 | `GET /repos/acme/widgets` | 200, `action: repos.get` |
| 2 | `POST /repos/acme/widgets/issues` | 200, `action: issues.create` |
| 3 | `DELETE /repos/acme/widgets` | 403, `policy_denied` |
| 4 | `GET /repos/evil/widgets` | 403, `default_deny`: the owner parameter narrows |
| 5 | `DELETE /repos/acme/widgets/` | 403, `gate: operation`, `operation_ambiguous` |
| 6 | `GET /healthz` | 403, no `action`, `default_deny` |

Check 5 is the point of refusing ambiguous paths. Without it, the trailing
slash leaves the call unnamed: the DENY on `repos.delete` would not fire,
while many APIs route the call to the same repository anyway.
