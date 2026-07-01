# Demo 13 — AgenticFlow Local Compile

This demo shows the least-privilege authoring model without requiring Kubernetes, a service mesh, or any private SaaS.

`AgenticFlow` describes a known acceptable path for an agent. The compiler turns it into the existing enforcement artifacts:

- `NullfieldPolicy`
- `ToolRegistry`

## What This Demonstrates

| Tool | Compiled action | Why |
|---|---|---|
| `echo` | `ALLOW` | Safe read-style status check |
| `github_create_pr` | `SCOPE` | Credential is injected only for this declared path |
| `pagerduty_resolve` | `HOLD` | Operational write requires approval |
| `dangerous_tool` | `DENY` | Outside the known acceptable path |
| everything else | `DENY` | Default deny |

## Run

From the repo root:

```bash
bash demos/13-agentic-flow-local/test.sh
```

Or inspect the compiled YAML directly:

```bash
go run ./cmd/nullfield-compile demos/13-agentic-flow-local/agentic-flow.yaml
```

## Key Point

The agent may reason non-deterministically, but the executable path is constrained by explicit YAML. Undeclared tools and undeclared credentials do not become executable authority.
