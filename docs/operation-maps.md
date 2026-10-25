# Operation Maps

An operation map names what a call does to an integration. With a map for
`api.github.com`, `DELETE /repos/acme/widgets` reaches policy as
`request.action == "repos.delete"` with `request.params` `{owner: acme, repo:
widgets}`, so a rule says what it means instead of matching a path.

Maps are data: one YAML file per target. An integration is added by writing a
file, not code.

Supported by `nullfield-extauthz` only, the one entry that sees the target
host and HTTP path.

## Configuration

Point `NULLFIELD_OPERATIONS_DIR` at a directory of `.yaml` or `.yml` files,
typically a mounted ConfigMap. Other files are ignored.

```yaml
target: api.github.com
operations:
  - name: repos.delete
    method: DELETE
    path: /repos/{owner}/{repo}
  - name: issues.create
    method: POST
    path: /repos/{owner}/{repo}/issues
```

| Field | Meaning |
|---|---|
| `target` | Host, lowercase, no port. One file per target. |
| `operations[].name` | The name rules match on. |
| `operations[].method` | HTTP method, case-insensitive. |
| `operations[].path` | Absolute path. `{name}` matches exactly one segment and becomes a parameter. |

The service refuses to start when the directory is unreadable or holds no
maps, or when any map has an unknown field, a missing name, method or target,
a target with a port, a path with an empty or dot segment, or a parameter
named twice.

See [`examples/operations/github.yaml`](../examples/operations/github.yaml).

## Matching

- The host is compared without port, case or trailing dot.
- The query string is ignored.
- Segments are percent-decoded before comparison, because the upstream acts
  on the decoded path.
- The first operation that matches wins, so list specific paths before
  general ones.
- A call on a mapped target that no operation matches has no `action`. A call
  on a target with no map is untouched.

## Ambiguous paths are refused

On a mapped target, a path the map cannot read one way only is refused before
policy runs (`gate: operation`, `reasonClass: operation_ambiguous`):

- a trailing slash or empty segment (`/repos/acme/widgets/`, `/repos//acme`);
- a dot segment, literal or encoded (`/a/./b`, `/a/%2E%2E`);
- an encoded slash (`/repos/acme%2Fwidgets/x`);
- invalid percent-encoding, or a path that is not absolute.

Otherwise a DENY on `repos.delete` could be dodged by a spelling the map
leaves unnamed but the upstream still routes to the same repository.

What the map cannot see is how an upstream treats case in literal segments.
Write rules as an allowlist of names over a default DENY, not as a denylist
over a default ALLOW.

## Rules

`request.action` and `request.params` are absent, not empty, when a call has
no name. Guard with `has()`:

```yaml
rules:
  - action: DENY
    celExpression: >-
      has(request.action) && request.action == "repos.delete"
  - action: ALLOW
    celExpression: >-
      has(request.action) && request.action in ["repos.get", "issues.create"] &&
      request.params.owner == "acme"
  - action: DENY
    toolNames: ["*"]
```

With a [run token](identity-policy.md#run-tokens-ext_authz), a rule can narrow
a name to the run's context:
`request.params.repo in request.run.context.repos`.

## Audit

The decision event carries `action` when the call was named.
