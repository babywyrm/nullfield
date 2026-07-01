# Agentic Flows

`AgenticFlow` is a concise YAML intent format for defining the known acceptable path for an agent. It compiles to the enforcement surfaces nullfield already uses: `NullfieldPolicy` and `ToolRegistry`.

The goal is not to replace policy YAML. It is to make common agentic flows easier to author, review, and compile into deterministic PDP/PEP controls.

## Current Status

Implemented today:

- Local compiler: `go run ./cmd/nullfield-compile <flow.yaml>`
- Kubernetes CRD: `AgenticFlow`
- Controller reconciliation to `nullfield-flow-<name>` ConfigMaps
- Runtime policy and registry generation
- Credential-scoped `SCOPE` rules with OAuth audience/scope audit context
- Optional NetworkPolicy, Istio, Cilium, and Linkerd artifact generation
- Runtime demo proving CRD-generated policy can be mounted by a nullfield sidecar and enforce real MCP calls

Next build targets:

- Reconciler apply mode for generated network/mesh artifacts
- Status conditions on `AgenticFlow` for compile failures and generated artifact hashes
- Richer credential demos using Vault/K8s Secret/OAuth-style flows
- More lane-specific examples for human, delegated, machine, chain, and anonymous traffic

## Example

```yaml
apiVersion: nullfield.io/v1alpha1
kind: AgenticFlow
metadata:
  name: demo-jira
spec:
  lane: delegated
  transport: A
  selector:
    matchLabels:
      app: demo-agent
  network:
    egress:
      - name: atlassian
        cidr: 104.192.136.0/21
        ports: [443]
  mesh:
    istio:
      principals:
        - cluster.local/ns/demo/sa/demo-runtime
      ports: [9090]
    cilium:
      ingress:
        - fromEndpoints:
            - app: demo-runtime
          port: 9090
          methods: [POST]
    linkerd:
      servers:
        - name: demo-mcp
          port: 9090
          identities:
            - demo-runtime.demo.serviceaccount.identity.linkerd.cluster.local
  credentials:
    - name: jira-read
      from: vault
      secretRef: jira-read-token
      injectAs: token
      oauth:
        audience: https://api.atlassian.com
        scopes: [read:jira-work]
  tools:
    - name: mcp-atlassian.read_issue
      action: ALLOW
      allowedScopes: [PROJECT-A, PROJECT-B, PROJECT-C]
      auditLabels:
        system: jira
        resource: issue

    - name: mcp-atlassian.search
      action: ALLOW
      credentialRefs: [jira-read]

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
- `NetworkPolicy`, when `spec.network.egress` is declared.
- Istio `AuthorizationPolicy`, when `spec.mesh.istio` is declared.
- Cilium `CiliumNetworkPolicy`, when `spec.mesh.cilium` is declared.
- Linkerd `Server` and `ServerAuthorization`, when `spec.mesh.linkerd` is declared.

Credential declarations are resolved by name. If a tool references an undeclared credential, compilation fails. OAuth metadata is preserved as audit context so operators can see which audience and scopes were intended for the credentialed path.

## Kubernetes Reconciliation

`AgenticFlow` is also available as a namespaced CRD. When the controller runs with `NULLFIELD_CRD_WATCH=true`, the CRD watcher lists `agenticflows.nullfield.io`, compiles each flow, and writes a managed ConfigMap named `nullfield-flow-<name>` containing:

- `compiled.yaml` — all generated artifacts
- `policy.yaml` — compiled `NullfieldPolicy`
- `tools.yaml` — compiled `ToolRegistry`

Apply the CRD and an example:

```bash
kubectl apply -f deploy/crds/agenticflow-crd.yaml
kubectl apply -f examples/crd/agentic-flow-example.yaml
```

## Control Split

Use `AgenticFlow` for runtime MCP intent: which agent path may call which tool, under which identity, with which credential and audit labels.

Network and mesh policy generation is opt-in. `NetworkPolicy`, Istio `AuthorizationPolicy`, Cilium policy, and Linkerd policy answer different questions, so nullfield only emits these artifacts when the flow declares enough explicit workload, destination, principal, port, and method intent to avoid broad allow rules.
