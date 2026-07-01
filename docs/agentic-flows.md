# Agentic Flows

`AgenticFlow` is a concise YAML intent format for defining the known acceptable path for an agent. It compiles to the enforcement surfaces nullfield already uses: `NullfieldPolicy` and `ToolRegistry`.

The goal is not to replace policy YAML. It is to make common agentic flows easier to author, review, and compile into deterministic PDP/PEP controls.

## Example

```yaml
apiVersion: nullfield.io/v1alpha1
kind: AgenticFlow
metadata:
  name: astra-jira
spec:
  lane: delegated
  transport: A
  selector:
    matchLabels:
      app: astra
  tools:
    - name: mcp-atlassian.read_issue
      action: ALLOW
      allowedScopes: [PRODENG, AIFE, EE]
      auditLabels:
        system: jira
        resource: issue

    - name: mcp-atlassian.search
      action: ALLOW
      credentials:
        - from: vault
          secretRef: jira-read-token
          injectAs: token

    - name: mcp-atlassian.delete_page
      action: DENY
      reason: delete is outside the known acceptable path
```

Compile it:

```bash
go run ./cmd/nullfield-compile examples/agentic-flow.yaml > compiled.yaml
```

The output is a multi-document YAML stream:

- `NullfieldPolicy` with stable rule IDs, `requireIdentity: true`, runtime actions, credential-scoped `SCOPE` rules, audit labels, and a default deny.
- `ToolRegistry` containing every declared tool, including explicitly denied tools, so policy denials are visible as policy decisions instead of disappearing at the registry gate.

## Control Split

Use `AgenticFlow` for runtime MCP intent: which agent path may call which tool, under which identity, with which credential and audit labels.

Network and mesh policy generation should remain profile-based. `NetworkPolicy`, Istio `AuthorizationPolicy`, Cilium policy, and Linkerd policy answer different questions, so they should be generated only when the flow declares enough explicit workload and destination intent.
