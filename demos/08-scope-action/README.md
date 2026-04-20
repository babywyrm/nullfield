# Demo 08: SCOPE Action — Request/Response Modification

SCOPE rules let nullfield **modify tool calls in transit** — strip dangerous arguments before they reach the upstream, inject defaults, or redact sensitive patterns from responses before they reach the caller. The call still goes through, but the data is shaped by policy.

## Policy

```yaml
rules:
  - action: SCOPE                          # strip secret_key, inject read_only
    toolNames: [pagerduty_resolve]
    scope:
      request:
        stripArguments: [secret_key]
        injectArguments:
          read_only: "true"

  - action: SCOPE                          # redact sensitive response patterns
    toolNames: [jira_get_issue]
    scope:
      response:
        redactPatterns: [password, secret, api_key]
        redactReplacement: "[REDACTED]"

  - action: ALLOW                          # pass-through, no modification
    toolNames: [github_create_pr]

  - action: DENY                           # everything else blocked
    toolNames: ["*"]
```

## Setup

Start the stack with this demo's policy:

```bash
docker compose -f docker-compose.yaml up -d \
  -v $(pwd)/demos/08-scope-action/policy.yaml:/etc/nullfield/policy.yaml:ro
```

Verify:

```bash
docker compose ps
```

## Walkthrough

### Step 1 — Request scoping: strip + inject on pagerduty_resolve

Send a `pagerduty_resolve` call with a `secret_key` argument that should be stripped, and observe `read_only` getting injected:

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "pagerduty_resolve",
      "arguments": {
        "incident_id": "PD-1234",
        "secret_key": "sk-super-secret-value",
        "note": "resolved via automation"
      }
    }
  }' | python3 -m json.tool
```

Expected — the echo server shows what it actually received. Notice `secret_key` is gone and `read_only` is present:

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "content": [
            {
                "type": "text",
                "text": "echo-server executed tool=\"pagerduty_resolve\" args=map[incident_id:PD-1234 note:resolved via automation read_only:true] at 2026-04-19T..."
            }
        ]
    }
}
```

The `secret_key` never reached the upstream server. The `read_only: "true"` was injected by policy.

### Step 2 — Response scoping: redact sensitive patterns from jira_get_issue

The echo server reflects arguments back in its response text. Send arguments containing sensitive-looking values to trigger redaction:

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "jira_get_issue",
      "arguments": {
        "key": "PROJ-42",
        "password": "hunter2",
        "api_key": "ak-12345",
        "description": "normal field"
      }
    }
  }' | python3 -m json.tool
```

Expected — patterns matching `password`, `secret`, or `api_key` in the response are redacted:

```json
{
    "jsonrpc": "2.0",
    "id": 2,
    "result": {
        "content": [
            {
                "type": "text",
                "text": "echo-server executed tool=\"jira_get_issue\" args=map[description:normal field [REDACTED] [REDACTED] key:PROJ-42] at 2026-04-19T..."
            }
        ]
    }
}
```

The redaction happens on the response body using regex matching — any occurrence of the patterns followed by key-value syntax is replaced with `[REDACTED]`.

### Step 3 — Unscoped pass-through: github_create_pr

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "github_create_pr",
      "arguments": {
        "repo": "acme/web",
        "title": "feat: add dashboard",
        "secret_key": "this-stays-because-no-scope-rule"
      }
    }
  }' | python3 -m json.tool
```

Expected — everything passes through unmodified (plain ALLOW, no SCOPE):

```json
{
    "jsonrpc": "2.0",
    "id": 3,
    "result": {
        "content": [
            {
                "type": "text",
                "text": "echo-server executed tool=\"github_create_pr\" args=map[repo:acme/web secret_key:this-stays-because-no-scope-rule title:feat: add dashboard] at 2026-04-19T..."
            }
        ]
    }
}
```

Notice `secret_key` is still present — the SCOPE rule only applies to `pagerduty_resolve`.

### Step 4 — Verify a denied tool

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "dangerous_tool",
      "arguments": {}
    }
  }' | python3 -m json.tool
```

Expected:

```json
{
    "jsonrpc": "2.0",
    "id": 4,
    "error": {
        "code": -32000,
        "message": "denied by policy: not permitted by scope-demo policy"
    }
}
```

### Step 5 — Check the audit logs

```bash
docker compose logs nullfield 2>&1 | grep -E 'scope|strip|inject|redact'
```

Expected audit entries showing what was modified:

```
scope.modified  tool=pagerduty_resolve identity=anonymous stripped=[secret_key] injected=[read_only]
scope.modified  tool=jira_get_issue    identity=anonymous response: 2 patterns redacted
tool.allowed    tool=github_create_pr  identity=anonymous
tool.denied     tool=dangerous_tool    identity=anonymous reason="not permitted by scope-demo policy"
```

## How it works

```
Request arrives → policy engine → SCOPE match
    │
    ├── Request scoping (before forwarding):
    │   ├── stripArguments: remove keys from args map
    │   └── injectArguments: add/overwrite keys in args map
    │
    ├── Forward modified request to upstream
    │
    └── Response scoping (before returning to caller):
        └── redactPatterns: regex replace matching patterns with replacement
```

SCOPE rules are treated as ALLOW with modifications — the call still goes through to the upstream server, but the request and/or response are transformed in transit.

## Key files

- `policy.yaml` — SCOPE rules for request stripping/injection and response redaction
- `../../pkg/scope/modifier.go` — request and response modification logic
- `../../pkg/proxy/handler.go` — scope integration in the proxy pipeline
