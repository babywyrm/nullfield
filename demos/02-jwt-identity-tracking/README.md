# Demo 02: JWT Identity Tracking

Configure identity providers, generate test JWTs, and observe how nullfield enforces different rules for different identity types.

## Overview

nullfield can validate JWT tokens against JWKS endpoints and use the identity metadata in policy rules. This demo shows:

1. Generating test RSA keypairs and signed JWTs
2. Configuring nullfield to validate tokens against a local JWKS
3. Writing policy rules that differentiate humans from agents
4. Observing allow/deny decisions based on identity type

## Setup

### 1. Generate test keys and tokens

```bash
cd demos/02-jwt-identity-tracking
bash generate-test-jwt.sh
```

This creates:
- `test-key.pem` — RSA private key
- `test-key-pub.pem` — RSA public key
- `jwks.json` — JWKS file with the public key
- `human-token.txt` — JWT with `identity_type: human, groups: [mcp-writers]`
- `agent-token.txt` — JWT with `identity_type: agent`
- `autonomous-token.txt` — JWT with `identity_type: autonomous`

### 2. Serve the JWKS locally

```bash
python3 -m http.server 8888 &
```

This serves `jwks.json` at `http://localhost:8888/jwks.json`.

### 3. Start nullfield with the identity policy

```bash
cd /path/to/nullfield

NULLFIELD_UPSTREAM_ADDR=localhost:8080 \
NULLFIELD_POLICY_PATH=demos/02-jwt-identity-tracking/policy.yaml \
NULLFIELD_REGISTRY_PATH=integrations/camazotz/tools.yaml \
./bin/nullfield
```

## What to observe

### Human token — write tools allowed

```bash
TOKEN=$(cat demos/02-jwt-identity-tracking/human-token.txt)
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"cost.check_usage","arguments":{}}}' | python3 -m json.tool
```

Expected: allowed — human identity with `mcp-writers` group.

### Agent token — read tools allowed, write tools denied

```bash
TOKEN=$(cat demos/02-jwt-identity-tracking/agent-token.txt)

# Read tool — allowed
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"cost.check_usage","arguments":{}}}' | python3 -m json.tool
```

Expected: allowed for read-only tools, denied for write tools.

### Autonomous token — everything denied

```bash
TOKEN=$(cat demos/02-jwt-identity-tracking/autonomous-token.txt)
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"cost.check_usage","arguments":{}}}' | python3 -m json.tool
```

Expected: denied — autonomous agents are not permitted.

### No token — rejected at identity gate

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"cost.check_usage","arguments":{}}}' | python3 -m json.tool
```

Expected: `{"error":{"code":-32001,"message":"identity verification failed"}}`

## How the policy works

```yaml
identity:
  enabled: true
  providers:
    - name: test-idp
      issuer: "nullfield-test"
      jwksUri: "http://localhost:8888/jwks.json"

rules:
  - action: ALLOW             # humans can use all registered tools
    when:
      identity: human

  - action: ALLOW             # agents can only use read tools
    toolNames: [cost.check_usage, audit.list_actions, ...]
    when:
      identity: agent

  - action: DENY              # autonomous callers blocked
    when:
      identity: autonomous
    reason: "autonomous agents are not permitted"

  - action: DENY              # default deny
    reason: "no matching rule"
```

## Key files

- `generate-test-jwt.sh` — generates keys, JWKS, and signed test tokens
- `policy.yaml` — identity-aware policy with when-conditions
- `examples/policy-identity.yaml` — production-style multi-provider example
- `docs/identity-policy.md` — full configuration guide
