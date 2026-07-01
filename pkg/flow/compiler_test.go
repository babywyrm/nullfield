package flow

import (
	"strings"
	"testing"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
)

func TestCompileFlowEmitsPolicyAndRegistry(t *testing.T) {
	doc := AgenticFlow{
		APIVersion: "nullfield.io/v1alpha1",
		Kind:       "AgenticFlow",
		Metadata: v1alpha1.Metadata{
			Name:      "astra-jira",
			Namespace: "prod",
		},
		Spec: FlowSpec{
			Selector:  v1alpha1.Selector{MatchLabels: map[string]string{"app": "astra"}},
			Lane:      "delegated",
			Transport: "A",
			Tools: []FlowTool{
				{
					Name:          "mcp-atlassian.read_issue",
					Description:   "Read Jira issues",
					Action:        v1alpha1.ActionAllow,
					AllowedScopes: []string{"PRODENG", "AIFE", "EE"},
					AuditLabels:   map[string]string{"system": "jira", "resource": "issue"},
				},
				{
					Name:   "mcp-atlassian.search",
					Action: v1alpha1.ActionAllow,
					Credentials: []v1alpha1.CredentialRef{
						{From: "vault", SecretRef: "jira-read-token", InjectAs: "token"},
					},
					AuditLabels: map[string]string{"system": "jira", "credential": "jira-read-token"},
				},
				{
					Name:   "mcp-atlassian.delete_page",
					Action: v1alpha1.ActionDeny,
					Reason: "delete is outside the known acceptable path",
				},
			},
		},
	}

	artifacts, err := Compile(doc)
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}

	if artifacts.Policy.Kind != "NullfieldPolicy" {
		t.Fatalf("policy kind = %q, want NullfieldPolicy", artifacts.Policy.Kind)
	}
	if artifacts.Registry.Kind != "ToolRegistry" {
		t.Fatalf("registry kind = %q, want ToolRegistry", artifacts.Registry.Kind)
	}
	if artifacts.Policy.Metadata.Labels["nullfield.io/lane"] != "delegated" {
		t.Fatalf("policy lane label = %q, want delegated", artifacts.Policy.Metadata.Labels["nullfield.io/lane"])
	}
	if artifacts.Policy.Metadata.Labels["nullfield.io/transport"] != "A" {
		t.Fatalf("policy transport label = %q, want A", artifacts.Policy.Metadata.Labels["nullfield.io/transport"])
	}
	if got := len(artifacts.Registry.Tools); got != 3 {
		t.Fatalf("registry tools = %d, want 3", got)
	}
	if artifacts.Registry.Tools[0].Name != "mcp-atlassian.read_issue" {
		t.Fatalf("first registry tool = %q", artifacts.Registry.Tools[0].Name)
	}
	if got := len(artifacts.Policy.Spec.Rules); got != 4 {
		t.Fatalf("policy rules = %d, want 4 including default deny", got)
	}

	readRule := artifacts.Policy.Spec.Rules[0]
	if readRule.ID != "mcp-atlassian-read-issue-allow" {
		t.Fatalf("read rule id = %q, want mcp-atlassian-read-issue-allow", readRule.ID)
	}
	if readRule.RequireIdentity != true {
		t.Fatal("expected compiled tool rule to require identity")
	}
	if readRule.AuditLabels["system"] != "jira" {
		t.Fatalf("read rule audit label system = %q, want jira", readRule.AuditLabels["system"])
	}

	searchRule := artifacts.Policy.Spec.Rules[1]
	if searchRule.ID != "mcp-atlassian-search-scope" {
		t.Fatalf("credentialed rule id = %q, want mcp-atlassian-search-scope", searchRule.ID)
	}
	if searchRule.Action != v1alpha1.ActionScope {
		t.Fatalf("credentialed action = %q, want SCOPE", searchRule.Action)
	}
	if searchRule.Scope == nil || searchRule.Scope.Request == nil {
		t.Fatal("expected credentialed rule to compile a request scope")
	}
	if got := searchRule.Scope.Request.InjectCredentials[0].SecretRef; got != "jira-read-token" {
		t.Fatalf("injected credential = %q, want jira-read-token", got)
	}

	denyRule := artifacts.Policy.Spec.Rules[2]
	if denyRule.Action != v1alpha1.ActionDeny {
		t.Fatalf("deny rule action = %q, want DENY", denyRule.Action)
	}
	if denyRule.Reason != "delete is outside the known acceptable path" {
		t.Fatalf("deny reason = %q", denyRule.Reason)
	}

	defaultRule := artifacts.Policy.Spec.Rules[3]
	if defaultRule.ID != "default-deny" || defaultRule.Action != v1alpha1.ActionDeny {
		t.Fatalf("default rule = %+v, want default-deny DENY", defaultRule)
	}
}

func TestLoadYAMLParsesAgenticFlow(t *testing.T) {
	doc, err := LoadYAML([]byte(`
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
      auditLabels:
        system: jira
`))
	if err != nil {
		t.Fatalf("LoadYAML returned error: %v", err)
	}
	if doc.Metadata.Name != "astra-jira" {
		t.Fatalf("metadata.name = %q, want astra-jira", doc.Metadata.Name)
	}
	if doc.Spec.Tools[0].AuditLabels["system"] != "jira" {
		t.Fatalf("audit label system = %q, want jira", doc.Spec.Tools[0].AuditLabels["system"])
	}
}

func TestMarshalArtifactsYAMLEmitsPolicyAndRegistryDocuments(t *testing.T) {
	artifacts, err := Compile(AgenticFlow{
		APIVersion: "nullfield.io/v1alpha1",
		Kind:       "AgenticFlow",
		Metadata:   v1alpha1.Metadata{Name: "astra-jira"},
		Spec: FlowSpec{
			Tools: []FlowTool{{Name: "mcp-atlassian.read_issue", Action: v1alpha1.ActionAllow}},
		},
	})
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}

	out, err := MarshalArtifactsYAML(artifacts)
	if err != nil {
		t.Fatalf("MarshalArtifactsYAML returned error: %v", err)
	}
	text := string(out)
	if !strings.Contains(text, "kind: NullfieldPolicy") {
		t.Fatalf("output missing NullfieldPolicy document:\n%s", text)
	}
	if !strings.Contains(text, "kind: ToolRegistry") {
		t.Fatalf("output missing ToolRegistry document:\n%s", text)
	}
	if !strings.Contains(text, "---\n") {
		t.Fatalf("output missing YAML document separator:\n%s", text)
	}
}
