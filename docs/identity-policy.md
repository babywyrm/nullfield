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
