# Demo 06: HOLD Action — Human Approval Gates

A tool call that matches a HOLD rule is **parked** — the HTTP request blocks until a human approves, denies, or the timeout expires. This gives operators a synchronous approval gate over dangerous operations without changing the client.

## Policy

```yaml
rules:
  - action: ALLOW                          # read-only — pass through
    toolNames: [github_create_pr, jira_get_issue]

  - action: HOLD                           # dangerous — wait for human
    toolNames: [pagerduty_resolve]
    hold:
      timeout: 2m
      onTimeout: DENY

  - action: DENY                           # everything else blocked
    toolNames: ["*"]
```

## Setup

Start the stack with this demo's policy mounted over the default:

```bash
docker compose -f docker-compose.yaml up -d \
  -v $(pwd)/demos/06-hold-action/policy.yaml:/etc/nullfield/policy.yaml:ro
```

Verify both containers are healthy:

```bash
docker compose ps
```

## Walkthrough

### Step 1 — Confirm allowed tools work normally

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "github_create_pr",
      "arguments": {"repo": "acme/web", "title": "fix: typo"}
    }
  }' | python3 -m json.tool
```

Expected — immediate success:

```json
{
    "jsonrpc": "2.0",
    "id": 1,
    "result": {
        "content": [
            {
                "type": "text",
                "text": "echo-server executed tool=\"github_create_pr\" args=map[repo:acme/web title:fix: typo] at 2026-04-19T..."
            }
        ]
    }
}
```

### Step 2 — Send a tool call that triggers HOLD (Terminal 1)

This request **blocks** — it will not return until someone approves, denies, or the 2-minute timeout fires.

```bash
# Terminal 1 — this will hang waiting for approval
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "pagerduty_resolve",
      "arguments": {"incident_id": "PD-1234"}
    }
  }' | python3 -m json.tool
```

The curl hangs. Open a second terminal.

### Step 3 — List pending holds (Terminal 2)

```bash
curl -s http://localhost:9091/admin/holds | python3 -m json.tool
```

Expected — one pending hold:

```json
[
    {
        "id": "hold-a1b2c3d4e5f6g7h8",
        "tool": "pagerduty_resolve",
        "arguments": {
            "incident_id": "PD-1234"
        },
        "identity": "anonymous",
        "reason": "pagerduty_resolve requires human approval",
        "status": "pending",
        "createdAt": "2026-04-19T..."
    }
]
```

Copy the `id` value — you'll need it for the next step.

### Step 4 — Approve the hold (Terminal 2)

Replace `HOLD_ID` with the actual ID from Step 3:

```bash
curl -s -X POST http://localhost:9091/admin/holds/HOLD_ID/approve \
  -H "X-Approver: ops-alice" | python3 -m json.tool
```

Expected:

```json
{
    "status": "approved",
    "hold": "hold-a1b2c3d4e5f6g7h8"
}
```

### Step 5 — Terminal 1 unblocks

Back in Terminal 1, the curl returns with the upstream response:

```json
{
    "jsonrpc": "2.0",
    "id": 2,
    "result": {
        "content": [
            {
                "type": "text",
                "text": "echo-server executed tool=\"pagerduty_resolve\" args=map[incident_id:PD-1234] at 2026-04-19T..."
            }
        ]
    }
}
```

The call went through only after human approval.

### Step 6 — Repeat but DENY instead

Terminal 1 — send another held request:

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {
      "name": "pagerduty_resolve",
      "arguments": {"incident_id": "PD-5678"}
    }
  }' | python3 -m json.tool
```

Terminal 2 — list holds, then deny:

```bash
# Get the hold ID
curl -s http://localhost:9091/admin/holds | python3 -m json.tool

# Deny it (replace HOLD_ID)
curl -s -X POST http://localhost:9091/admin/holds/HOLD_ID/deny \
  -H "X-Approver: ops-bob" | python3 -m json.tool
```

Expected deny response:

```json
{
    "status": "denied",
    "hold": "hold-..."
}
```

Terminal 1 unblocks with a JSON-RPC error:

```json
{
    "jsonrpc": "2.0",
    "id": 3,
    "error": {
        "code": -32000,
        "message": "hold denied by ops-bob"
    }
}
```

### Step 7 — Let one timeout

Send another held request and **don't approve or deny it** — just wait 2 minutes:

```bash
curl -s -X POST http://localhost:9090/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 4,
    "method": "tools/call",
    "params": {
      "name": "pagerduty_resolve",
      "arguments": {"incident_id": "PD-9999"}
    }
  }' | python3 -m json.tool
```

After 2 minutes, Terminal 1 returns:

```json
{
    "jsonrpc": "2.0",
    "id": 4,
    "error": {
        "code": -32005,
        "message": "hold timed out without approval"
    }
}
```

The `onTimeout: DENY` in the policy caused the timeout to be treated as a denial.

### Step 8 — Check the audit trail

View hold lifecycle events in the container logs:

```bash
docker compose logs nullfield 2>&1 | grep -E 'hold|pagerduty'
```

You'll see structured log entries for each hold lifecycle event:

```
hold.created   tool=pagerduty_resolve identity=anonymous holdId=hold-... timeout=2m0s
hold.approved  tool=pagerduty_resolve identity=anonymous holdId=hold-... approvedBy=ops-alice
hold.created   tool=pagerduty_resolve identity=anonymous holdId=hold-...
tool.denied    tool=pagerduty_resolve identity=anonymous reason="hold hold-...: denied by ops-bob"
hold.created   tool=pagerduty_resolve identity=anonymous holdId=hold-...
tool.denied    tool=pagerduty_resolve identity=anonymous reason="hold timed out without approval"
```

Check the history of resolved holds via the admin API:

```bash
curl -s http://localhost:9091/admin/holds/history | python3 -m json.tool
```

## How it works

```
Request arrives → policy engine → HOLD match
    │
    ├── Hold created, request blocks
    ├── Admin API exposes hold for approval
    │
    ├── POST /admin/holds/{id}/approve → request forwards to upstream
    ├── POST /admin/holds/{id}/deny    → -32000 error returned
    └── Timeout expires                → -32005 error returned (onTimeout: DENY)
```

## Key files

- `policy.yaml` — HOLD rule with 2m timeout and DENY on expiry
- `../../pkg/hold/manager.go` — hold lifecycle management
- `../../pkg/hold/admin.go` — admin API handlers
- `../../pkg/proxy/handler.go` — proxy integration (blocks on hold channel)
