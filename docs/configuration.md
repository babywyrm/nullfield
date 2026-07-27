# Configuration Reference

Everything nullfield reads from the environment. Policy and registry *content*
is specified in [arbiter-model.md](arbiter-model.md); this file is only about
how a process is wired up.

---

## Proxy and gateway (`nullfield`)

| Variable | Default | Description |
|---|---|---|
| `NULLFIELD_LISTEN_ADDR` | `:9090` | Proxy listen address |
| `NULLFIELD_UPSTREAM_ADDR` | `localhost:8080` | Application upstream (sidecar mode) |
| `NULLFIELD_ADMIN_ADDR` | `:9091` | Admin and health endpoint |
| `NULLFIELD_POLICY_PATH` | `/etc/nullfield/policy.yaml` | Path to the `NullfieldPolicy` |
| `NULLFIELD_REGISTRY_PATH` | `/etc/nullfield/tools.yaml` | Path to the `ToolRegistry` |
| `NULLFIELD_ROUTES_PATH` | _(empty)_ | Gateway routes config. Mutually exclusive with `UPSTREAM_ADDR` |

## Identity

| Variable | Default | Description |
|---|---|---|
| `NULLFIELD_IDENTITY_HEADER` | `Authorization` | Header to extract the bearer token from |
| `NULLFIELD_JWKS_URL` | _(empty)_ | JWKS endpoint to validate tokens against. Requires `NULLFIELD_JWKS_ISSUER` |
| `NULLFIELD_JWKS_ISSUER` | _(empty)_ | Expected `iss` claim. Mandatory whenever `NULLFIELD_JWKS_URL` is set |
| `NULLFIELD_JWKS_AUDIENCE` | _(empty)_ | Comma-separated expected `aud` values. Empty means the audience is not checked |
| `NULLFIELD_TRUST_HEADER_IDENTITY` | `false` | Accept any bearer token unverified, taking the token as the subject. **Development only** |

There are three ways to configure identity, and they are not equivalent:

1. **`spec.identity.providers` in the policy.** The fullest option — multiple
   issuers, per-provider audiences, clock skew, algorithm allow-lists. Use this
   when more than one IdP is in play.
2. **The environment variables above.** One issuer, real validation. Enough for
   a single IdP.
3. **Nothing.** The noop verifier, which fabricates `dev-user` for every
   request. Every identity-conditional rule in your policy matches the same
   principal.

**Setting `NULLFIELD_JWKS_URL` without an issuer is now a startup failure.** It
used to select a verifier that never fetched the JWKS and accepted any bearer
token unverified, taking the raw token as the subject — so the variable that
reads like it turns on validation turned on trusting the caller. If you were
relying on that behaviour, ask for it by name with
`NULLFIELD_TRUST_HEADER_IDENTITY=true`, and only in development.

nullfield logs which path it took at startup, so check that before trusting an
identity-conditional policy:

```
identity validation enabled from environment issuer=https://idp.example.com ...
no identity providers configured, using noop verifier (dev mode)
NULLFIELD_TRUST_HEADER_IDENTITY is set: bearer tokens are accepted without ...
```

See [identity-policy.md](identity-policy.md).

## Limits and audit

| Variable | Default | Description |
|---|---|---|
| `NULLFIELD_CIRCUIT_MAX_CALLS` | `100` | Tool calls per session before the circuit opens |
| `NULLFIELD_CIRCUIT_MAX_DURATION` | `5m` | Session duration before the circuit opens |
| `NULLFIELD_AUDIT_LOG_LEVEL` | `FULL` | `FULL`, `SUMMARY`, or `NONE` |
| `NULLFIELD_AUDIT_ENDPOINT` | _(empty)_ | OTLP gRPC endpoint for audit events |

## Controller and credentials

| Variable | Default | Description |
|---|---|---|
| `NULLFIELD_CONTROLLER_ADDR` | _(empty)_ | Controller gRPC address. Empty means standalone |
| `NULLFIELD_CRD_WATCH` | `false` | Watch `NullfieldPolicy`/`ToolRegistry` CRDs (controller only) |
| `NULLFIELD_CRD_WATCH_INTERVAL` | `30s` | CRD poll interval |
| `NULLFIELD_VAULT_ADDR` | _(empty)_ | Vault address for credential injection |
| `NULLFIELD_VAULT_ROLE` | _(empty)_ | Vault role for the Kubernetes auth method |
| `NULLFIELD_VAULT_AUTH_METHOD` | _(auto)_ | `token` or `kubernetes`; auto-detected from `VAULT_TOKEN` |
| `NULLFIELD_CREDENTIAL_CACHE_TTL` | `5m` | TTL for cached credentials |

---

## Decision service (`nullfield-extauthz`)

A separate binary with a much smaller surface, because it decides rather than
forwards.

| Variable | Default | Description |
|---|---|---|
| `NULLFIELD_EXTAUTHZ_LISTEN_ADDR` | `:9191` | gRPC listen address for Envoy's `ext_authz` checks |
| `NULLFIELD_EXTAUTHZ_MODE` | `observe` | `noop`, `observe`, or `enforce` |
| `NULLFIELD_EXTAUTHZ_LOG_PEER` | `false` | Log raw peer attributes and header names. For diagnosing identity that is not arriving |
| `NULLFIELD_POLICY_PATH` | `/etc/nullfield/policy.yaml` | Path to the `NullfieldPolicy` |

Two things that are easy to get wrong here:

An unrecognised or empty mode falls back to `observe`, never to `enforce`. A
typo therefore costs you enforcement rather than costing you an outage.

`NULLFIELD_REGISTRY_PATH` is accepted but **not consumed** by this binary — it
builds a policy engine only, so there is no registry gate and an unregistered
tool reaches the rules. Default-deny comes from a `DENY *` fallthrough rule. See
[policy-eval.md](diagrams/policy-eval.md#two-entries-different-chains).

The mode is a nullfield setting, but truncation behaviour is an Istio one, and
they have to agree — see the
[buffer boundary](diagrams/mesh-arbiter.md#the-buffer-boundary).

---

## Ports

| Port | Process | Purpose |
|---|---|---|
| 9090 | `nullfield` | MCP proxy |
| 9091 | `nullfield` | Admin: `/healthz`, `/readyz`, `/metrics`, `/admin/holds` |
| 9092 | `nullfield-controller` | gRPC from sidecars |
| 9093 | `nullfield-controller` | Admin API |
| 9191 | `nullfield-extauthz` | gRPC `ext_authz` checks and health |

The admin port is deliberately separate from the proxy port so kubelet probes do
not traverse policy — a liveness check must not be deniable.
