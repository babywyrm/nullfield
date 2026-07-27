# Identity-Aware Policy Guide

How to configure identity providers, write when-conditions, and enable integrity checks in nullfield.

---

## Overview

nullfield's identity features are entirely opt-in. There are four levels of configuration, each building on the previous:

| Level | What you configure | What it does |
|-------|-------------------|--------------|
| 0 | Nothing (default) | No identity validation. NoopVerifier in dev mode. Works like v0.1. |
| 1 | `when:` blocks on rules | Different rules for different identity types. No JWT validation. |
| 2 | `identity.enabled: true` + providers | JWT signature validation against JWKS endpoints. |
| 3 | `integrity.enabled: true` | Session binding + token replay detection on top of JWT. |

Each level is independent. You can use Level 1 without Level 2 (identity type from a trusted header instead of JWT), or Level 2 without Level 3 (JWT without replay detection).

All four levels answer one question: **whose authority is being exercised?** When nullfield runs as an `ext_authz` decision service it can also answer a second, independent one — **what is actually running?** — from evidence the workload cannot choose. That is [workload attestation](#workload-attestation), and it is not a fifth level; it is a different axis.

---

## Workload Attestation

Every level above derives identity from something the caller *presents*: a JWT, a header, a bearer token. That is the right answer to "on whose behalf is this happening", and the wrong answer to "what is making this call".

The gap between those two questions is where a confused deputy lives. A legitimate job runner holding a legitimate user token is indistinguishable, at the token layer, from a compromised job runner replaying that same token. Both present valid credentials. Both are, as far as levels 0–3 can tell, the same caller.

Attestation closes that gap by establishing the *workload* from transport evidence rather than from a claim:

| | Identity (levels 0–3) | Attestation |
|---|---|---|
| Answers | whose authority is being exercised | what is running |
| Derived from | a token the workload presents | the mesh's mTLS peer identity |
| Can the workload choose it? | yes, if it holds the token | no |
| Available in | every mode | `ext_authz` mode |

They are deliberately separate types in the code, and collapsing them would defeat the point: a workload that has stolen a token still cannot forge the identity its own certificate carries.

### Attesters

An attester is a named mechanism for establishing workload identity. The name is recorded on every decision, because "we know who this workload is" means materially different things depending on which one answered.

| Attester | Source | Binding |
|----------|--------|---------|
| `mesh-spiffe` | Envoy's `source.principal`, from the peer certificate's URI SAN | mTLS. The workload cannot forge it. |
| `mesh-header` | A principal a waypoint republished into a request header | The mesh stripping any client-supplied value of that name first |
| `none` | No workload identity could be established | — |

`mesh-header` exists because an ambient waypoint terminates HBONE upstream of the listener running `ext_authz`, so no peer certificate is readable there and `source.principal` arrives empty however healthy the mesh is. An EnvoyFilter copies the identity out of Envoy filter state into a header the check does receive.

The identity is the same; the binding is weaker. Reading a certificate depends on TLS. Reading a header depends on a filter that strips inbound values before writing its own — a property of deployed configuration rather than of cryptography. **A deployment without that filter must not treat the header as meaningful**, which is exactly why it is a separate attester name rather than a silent fallback inside `mesh-spiffe`.

Where a certificate and a header are both present, the certificate wins.

### Assurance

`assurance` on a decision reports whether a workload identity was established at all: `ATTESTED` or `NONE`. It is intentionally coarse today. Once grants land, it will distinguish how strongly the workload is bound to the authority it is exercising — corroboration from two independent attesters, for instance, is worth more than either alone, which is the case on EKS where IRSA or Pod Identity can be checked alongside the mesh.

### Reading it

```json
{
  "workload_principal": "spiffe://cluster.local/ns/agents/sa/job-runner",
  "attester": "mesh-header",
  "assurance": "ATTESTED"
}
```

An `attester: none` with an empty principal means the EnvoyFilter is absent or the caller is outside the mesh. See [Observability](observability.md#decision-provenance-ext_authz-mode) for how to tell those apart, and [Mesh Integration](mesh-integration.md#istio-ambient--nullfield-as-an-ext_authz-decision-service) for the deployment.

---

## Level 0: No Identity (Default)

The minimal policy has no identity section. nullfield uses the noop verifier in dev mode (all requests get `dev-user` identity) or the header verifier if JWKS URL is set via environment variable.

```yaml
spec:
  rules:
    - action: ALLOW
      mcpMethod: tools/call
      toolNames: [my_tool]
    - action: DENY
      mcpMethod: tools/call
      toolNames: ["*"]
```

---

## Level 1: When-Conditions (Identity Type Matching)

Add `when:` blocks to rules to match on identity type, provider, or claims. The identity metadata comes from whatever verifier is active (noop, header, or JWKS).

```yaml
spec:
  rules:
    - action: ALLOW
      mcpMethod: tools/call
      toolNames: [github_create_pr]
      when:
        identity: human
      requireIdentity: true

    - action: ALLOW
      mcpMethod: tools/call
      toolNames: [audit.list_actions]
      when:
        identity: agent

    - action: DENY
      mcpMethod: tools/call
      toolNames: ["*"]
      when:
        identity: autonomous
      reason: "autonomous agents are not permitted"

    - action: DENY
      mcpMethod: tools/call
      toolNames: ["*"]
      reason: "default deny"
```

### Identity types

| Type | Meaning | How it's determined |
|------|---------|-------------------|
| `human` | User-initiated request via MCP client | JWT contains `openid` scope or `identity_type: human` claim |
| `agent` | Agent acting on behalf of a human | JWT contains `identity_type: agent` claim |
| `autonomous` | Fully autonomous agent (no human in loop) | JWT contains `identity_type: autonomous` claim |
| `unknown` | Can't determine from token | No matching claim found |
| `any` | Matches all types | Wildcard |

### When-condition fields

All specified fields must match (AND logic). Absent fields match anything.

| Field | Type | Example | Matches when |
|-------|------|---------|-------------|
| `identity` | string | `human` | Identity type matches |
| `provider` | string | `okta` | Token was issued by this provider |
| `claims` | map | `groups: { contains: "admins" }` | Claim value matches |

---

## Level 2: JWT Validation

Enable real JWT signature validation by configuring identity providers in the policy.

```yaml
spec:
  identity:
    enabled: true
    providers:
      - name: okta
        issuer: "https://your-org.okta.com"
        jwksUri: "https://your-org.okta.com/oauth2/v1/keys"
        audiences: ["api://nullfield"]
        clockSkew: "30s"

      - name: zitadel
        issuer: "http://zitadel:8080"
        jwksUri: "http://zitadel:8080/oauth/v2/keys"

    validation:
      requireSignature: true
      allowedAlgorithms: [RS256, ES256]
      requireExpiry: true
      requireAudience: true
```

### How it works

1. nullfield extracts the Bearer token from the configured header
2. It peeks at the `iss` claim to find the matching provider
3. It fetches the provider's JWKS keys (cached for 5 minutes)
4. It validates the signature, expiry, audience, and issuer
5. It extracts claims (subject, groups, scopes) into the Identity struct
6. The Identity is then available to `when:` conditions in rules

### Multiple providers

Configure as many providers as you need. nullfield routes each token to the correct provider by matching the `iss` claim. If no provider matches the issuer, the request is rejected.

### Security defaults

- `alg: none` tokens are always rejected
- Only RS256 and ES256 are allowed by default
- Token must have a valid signature from the provider's JWKS

---

## Level 3: Integrity Checks

Add session binding and replay detection on top of JWT validation.

```yaml
spec:
  integrity:
    enabled: true
    bindToSession: true
    detectReplay: true
```

### Session binding

When `bindToSession: true`, nullfield tracks the identity (subject) associated with each MCP session. If a different identity appears on the same session, the request is rejected.

This detects scenarios where an LLM or intermediate agent swaps out the caller context mid-session.

### Replay detection

When `detectReplay: true`, nullfield tracks the `jti` (JWT ID) claim of each token. If the same JTI appears twice, the second request is rejected.

This detects token replay attacks where a captured token is reused. JTI entries expire automatically (default 10 minutes) to bound memory usage.

---

## Combining Levels

The full configuration with all levels enabled:

```yaml
spec:
  identity:
    enabled: true
    providers:
      - name: okta
        issuer: "https://your-org.okta.com"
        jwksUri: "https://your-org.okta.com/oauth2/v1/keys"
        audiences: ["api://nullfield"]

  integrity:
    enabled: true
    bindToSession: true
    detectReplay: true

  rules:
    - action: ALLOW
      mcpMethod: tools/call
      toolNames: [github_create_pr]
      when:
        identity: human
        provider: okta
        claims:
          groups: { contains: "mcp-writers" }
      requireIdentity: true

    - action: DENY
      mcpMethod: tools/call
      toolNames: ["*"]
      reason: "default deny"
```

To disable any level, remove or set `enabled: false` on that section. Rules without `when:` blocks continue to work unconditionally.
