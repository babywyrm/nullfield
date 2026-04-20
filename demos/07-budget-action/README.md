# Demo 07: BUDGET Action — Call Quotas and Cost Caps

Budget limits attach to ALLOW rules and enforce **per-identity** or **per-session** call quotas. Once the budget is exhausted, subsequent calls are rejected with `-32004` — the tool stays "allowed" in principle but the caller has used up their allocation.

## Policy

```yaml
rules:
  - action: ALLOW                          # budgeted — 3 calls/hour
    toolNames: [github_create_pr]
    budget:
      perIdentity:
        maxCallsPerHour: 3

  - action: ALLOW                          # unlimited read tool
    toolNames: [jira_get_issue]

  - action: DENY                           # everything else blocked
    toolNames: ["*"]
```

## Setup

Start the stack with this demo's policy:

```bash
docker compose -f docker-compose.yaml up -d \
  -v $(pwd)/demos/07-budget-action/policy.yaml:/etc/nullfield/policy.yaml:ro
```

Verify:

```bash
docker compose ps
```

## Walkthrough

### Step 1 — Call github_create_pr (call 1 of 3)

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "github_create_pr",
      "arguments": {"repo": "acme/web", "title": "feat: add login"}
    }
  }' | python3 -m json.tool
```

Expected — success:

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "content": [
            {
                "type": "text",
                "text": "echo-server executed tool=\"github_create_pr\" args=map[repo:acme/web title:feat: add login] at 2026-04-19T..."
            }
        ]
    }
}
```

### Step 2 — Call github_create_pr (calls 2 and 3)

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "github_create_pr",
      "arguments": {"repo": "acme/web", "title": "fix: null check"}
    }
  }' | python3 -m json.tool
```

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "github_create_pr",
      "arguments": {"repo": "acme/api", "title": "chore: update deps"}
    }
  }' | python3 -m json.tool
```

Both succeed — you've now used 3 of 3 hourly calls.

### Step 3 — Call github_create_pr a 4th time (budget exhausted)

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "github_create_pr",
      "arguments": {"repo": "acme/api", "title": "docs: readme"}
    }
  }' | python3 -m json.tool
```

Expected — budget exhausted:

```json
{
    "jsonrpc": "2.0",
    "id": 4,
    "error": {
        "code": -32004,
        "message": "budget exhausted: identity budget: hourly call limit reached (3/3)"
    }
}
```

### Step 4 — Call jira_get_issue (different rule, no budget)

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 5,
    "method": "tools/call",
    "params": {
      "name": "jira_get_issue",
      "arguments": {"key": "PROJ-42"}
    }
  }' | python3 -m json.tool
```

Expected — still works (this rule has no budget):

```json
{
    "jsonrpc": "2.0",
    "id": 5,
    "result": {
        "content": [
            {
                "type": "text",
                "text": "echo-server executed tool=\"jira_get_issue\" args=map[key:PROJ-42] at 2026-04-19T..."
            }
        ]
    }
}
```

### Step 5 — Check metrics for budget exhaustion

```bash
curl -s http://localhost:9091/metrics | grep nullfield
```

Look for counters like:

```
nullfield_tool_calls_total{tool="github_create_pr",decision="allowed"} 3
nullfield_tool_calls_total{tool="github_create_pr",decision="denied"} 1
nullfield_tool_calls_total{tool="jira_get_issue",decision="allowed"} 1
```

You can also see the budget exhaustion in the container logs:

```bash
docker compose logs nullfield 2>&1 | grep -E 'budget|github_create_pr'
```

Expected log lines:

```
tool.allowed  tool=github_create_pr identity=anonymous   (×3)
tool.denied   tool=github_create_pr identity=anonymous reason="budget exhausted: identity budget: hourly call limit reached (3/3)"
tool.allowed  tool=jira_get_issue   identity=anonymous
```

## How it works

```
Request arrives → policy engine → ALLOW match with budget
    │
    ├── Budget tracker checks identity's hourly/daily counters
    │
    ├── Under limit → record call, forward to upstream
    └── Over limit  → -32004 error, call never reaches upstream
```

Budget counters reset on a rolling window — the hourly limit tracks calls within the last 60 minutes, not a fixed clock hour.

## Key files

- `policy.yaml` — ALLOW rule with perIdentity budget (3 calls/hour)
- `../../pkg/budget/tracker.go` — sliding-window budget enforcement
- `../../pkg/proxy/handler.go` — budget check integration after policy match
