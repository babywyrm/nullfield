# Demo 02 — JWT Identity Tracking

Two things, and the second only means something because of the first: that
tokens are genuinely verified, and that a verified identity changes what a call
is allowed to do.

```bash
demos/02-jwt-identity-tracking/test.sh
```

Tier 1, no dependencies beyond Docker Compose, openssl, and python3. Gated in
CI. Nothing here is a real key — the keypair is regenerated on every run and
the tokens expire in an hour.

## Verification is real, and provable

The generator mints seven tokens. One of them is the interesting one:

| Token | Why it should be refused |
|---|---|
| `forged-token.txt` | **Correct claims, correct `kid`, signed by a key the JWKS never published** |
| `expired-token.txt` | `exp` in the past |
| `wrong-issuer-token.txt` | `iss` is another IdP |
| `wrong-audience-token.txt` | `aud` names someone else |

The forged one is the assertion that matters. Every other refusal could be
produced by a verifier that reads claims and never checks a signature. Only a
token with perfect claims and a bad signature separates "validating" from
"parsing."

There is also a regression assertion. `NULLFIELD_JWKS_URL` used to select a
verifier that took the raw token string as the subject without parsing it, so
the test checks the audit trail says `alice@example.com` and not a
700-character JWT.

## Identity changes the answer

Same tool, same registry, same upstream. Only the token differs:

| Caller | `cost.check_usage` | `tenant.delete_tenant` |
|---|---|---|
| human in `mcp-writers` | allowed | allowed |
| agent | allowed | **denied** (`-32000`) |
| autonomous | **denied** | **denied** |

Rules select on claims through `when`:

```yaml
- id: agent-read-only
  action: ALLOW
  toolNames: [cost.check_usage, audit.list_actions]
  requireIdentity: true
  when:
    identity: agent
```

Note the two different refusals an agent can get. `tenant.delete_tenant` is
`-32000`, a policy denial, because the tool is registered and the agent's rule
does not name it. That is different from `-32003`, which would mean the
registry had never heard of it. Demo 01 covers that distinction.

## How the JWKS gets served

Identity verification cannot be demonstrated without a JWKS endpoint, so
`compose.override.yaml` starts one:

```yaml
jwks:
  image: busybox:1.36
  command: ["httpd", "-f", "-p", "8888", "-h", "/www"]
  volumes:
    - ./demos/02-jwt-identity-tracking/.generated:/www:ro
```

and the policy points at it by service name:

```yaml
identity:
  enabled: true
  providers:
    - name: test-idp
      issuer: "nullfield-test"
      jwksUri: "http://jwks:8888/jwks.json"
      audiences: ["nullfield"]
      clockSkew: "30s"
```

`generate-test-jwt.sh` needs only openssl and python3 — it reads the modulus
from `openssl rsa -noout -modulus` and checks the exponent rather than pulling
in the `cryptography` package, so it runs in CI.

## Two ways to configure this, and one that used to lie

`spec.identity.providers`, as above, is the fuller path: several issuers, per
provider audiences, clock skew, algorithm allow-lists.

The environment variables are the smaller one — `NULLFIELD_JWKS_URL` plus
`NULLFIELD_JWKS_ISSUER`, and optionally `NULLFIELD_JWKS_AUDIENCE`. Enough for a
single IdP.

Setting `NULLFIELD_JWKS_URL` on its own used to select a verifier that never
fetched the JWKS and accepted any bearer token unverified. It is now a startup
failure: an issuer is mandatory, because the verifier matches on `iss` and a
URL alone cannot validate anything. The unverified path still exists for local
work but has to be asked for by name, with
`NULLFIELD_TRUST_HEADER_IDENTITY=true`. See
[configuration.md](../../docs/configuration.md).

With neither configured, the noop verifier fabricates `dev-user` for every
request and every identity-conditional rule matches the same principal. Check
the startup log before trusting one.

## What the test asserts

```
a valid token is verified, not merely present:
  ok:  a token signed by the published key is accepted
  ok:  the subject comes from the sub claim, not the raw token

every way a token can be wrong is refused:
  ok:  a forged signature is refused, though its claims are perfect
  ok:  an expired token is refused
  ok:  a token from another issuer is refused
  ok:  a token minted for another audience is refused
  ok:  something that is not a token at all is refused
  ok:  a call with no token is refused

identity decides what the call is allowed to do:
  ok:  a human in mcp-writers may call the destructive tool
  ok:  an agent calling the same tool is refused by policy
  ok:  the agent keeps the read-only tools it is granted
  ok:  an autonomous caller is denied even the read-only tools

the audit trail attributes the call:
  ok:  each decision names the verified principal
  ok:  and the identity-conditional rule that matched
```

## Related

- Demo 03 builds on these tokens for session binding and replay detection.
- Demo 01 covers the gates that run before identity is consulted.
