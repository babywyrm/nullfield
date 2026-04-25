# Demo 12 — Response Inspection

Detect and redact sensitive content in MCP tool responses before they reach
the LLM. Catches credentials, PII, system prompt fragments, and internal
infrastructure details.

## What Response Inspection Detects

| Category | Examples | Severity |
|----------|---------|----------|
| Credentials | Private keys, `password=`, API keys (`sk-...`), bearer tokens | CRITICAL/HIGH |
| PII | SSNs (123-45-6789), email addresses, credit card numbers | HIGH/MEDIUM |
| Prompt leaks | "System prompt: You are an AI...", "never disclose..." | HIGH/MEDIUM |
| Internal paths | `/var/run/secrets/kubernetes`, `svc.cluster.local`, `10.x.x.x:port` | HIGH/MEDIUM |

## How It Works

The inspector analyzes tool response text against pattern rules. When a match
is found, it can:
1. **Flag** — add to the audit log without modifying the response
2. **Redact** — replace the matched content with `[REDACTED]` in-flight

## Example: Credential in Response

A tool returns database connection info:

```json
{
  "content": [{
    "type": "text",
    "text": "{\"host\": \"db.internal\", \"password\": \"Sup3rS3cret!2026\", \"port\": 5432}"
  }]
}
```

The inspector detects `password: "Sup3rS3cret!2026"` and redacts:

```json
{
  "content": [{
    "type": "text",
    "text": "{\"host\": \"db.internal\", \"password\": \"[REDACTED]\", \"port\": 5432}"
  }]
}
```

## Testing with Camazotz

The `response_inspection_lab` in camazotz provides a hands-on exercise:

```bash
# Step 1: Call the leaky tool to see what it exposes
curl -s -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"response_inspection.call_leaky_tool","arguments":{}}}'

# Step 2: Write redaction patterns and submit them
curl -s -X POST http://localhost:8080/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"response_inspection.submit_redaction","arguments":{"patterns":["password","secret","Bearer\\s+\\S+","sk-[a-zA-Z0-9]+"]}}}'
```

The lab scores your patterns on coverage (sensitive keys redacted) and
precision (legitimate fields preserved).

## Custom Patterns

Add custom detection patterns in the nullfield policy:

```yaml
inspection:
  detectCredentials: true
  detectPII: true
  detectPromptLeak: true
  detectInternalPaths: true
  customPatterns:
    - "INTERNAL-\\d{6}"
    - "company-secret-\\w+"
```
