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
			Name:      "demo-jira",
			Namespace: "prod",
		},
		Spec: FlowSpec{
			Selector:  v1alpha1.Selector{MatchLabels: map[string]string{"app": "demo-agent"}},
			Lane:      "delegated",
			Transport: "A",
			Tools: []FlowTool{
				{
					Name:          "mcp-atlassian.read_issue",
					Description:   "Read Jira issues",
					Action:        v1alpha1.ActionAllow,
					AllowedScopes: []string{"PROJECT-A", "PROJECT-B", "PROJECT-C"},
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
  name: demo-jira
spec:
  lane: delegated
  transport: A
  selector:
    matchLabels:
      app: demo-agent
  tools:
    - name: mcp-atlassian.read_issue
      action: ALLOW
      auditLabels:
        system: jira
`))
	if err != nil {
		t.Fatalf("LoadYAML returned error: %v", err)
	}
	if doc.Metadata.Name != "demo-jira" {
		t.Fatalf("metadata.name = %q, want demo-jira", doc.Metadata.Name)
	}
	if doc.Spec.Tools[0].AuditLabels["system"] != "jira" {
		t.Fatalf("audit label system = %q, want jira", doc.Spec.Tools[0].AuditLabels["system"])
	}
}

func TestMarshalArtifactsYAMLEmitsPolicyAndRegistryDocuments(t *testing.T) {
	artifacts, err := Compile(AgenticFlow{
		APIVersion: "nullfield.io/v1alpha1",
		Kind:       "AgenticFlow",
		Metadata:   v1alpha1.Metadata{Name: "demo-jira"},
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

func TestCompileFlowEmitsOptInNetworkAndIstioPolicies(t *testing.T) {
	artifacts, err := Compile(AgenticFlow{
		APIVersion: "nullfield.io/v1alpha1",
		Kind:       "AgenticFlow",
		Metadata:   v1alpha1.Metadata{Name: "demo-jira", Namespace: "prod"},
		Spec: FlowSpec{
			Selector: v1alpha1.Selector{MatchLabels: map[string]string{"app": "demo-agent"}},
			Network: &NetworkSpec{
				Egress: []EgressDestination{
					{Name: "atlassian", CIDR: "104.192.136.0/21", Ports: []int{443}},
				},
			},
			Mesh: &MeshSpec{
				Istio: &IstioAuthzSpec{
					Principals: []string{"cluster.local/ns/prod/sa/demo-runtime"},
					Ports:      []int{9090},
				},
			},
			Tools: []FlowTool{{Name: "mcp-atlassian.read_issue", Action: v1alpha1.ActionAllow}},
		},
	})
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}

	if len(artifacts.NetworkPolicies) != 1 {
		t.Fatalf("NetworkPolicies = %d, want 1", len(artifacts.NetworkPolicies))
	}
	np := artifacts.NetworkPolicies[0]
	if np.Kind != "NetworkPolicy" {
		t.Fatalf("network kind = %q, want NetworkPolicy", np.Kind)
	}
	if np.Spec.PodSelector.MatchLabels["app"] != "demo-agent" {
		t.Fatalf("network pod selector = %+v", np.Spec.PodSelector.MatchLabels)
	}
	if got := np.Spec.Egress[0].To[0].IPBlock.CIDR; got != "104.192.136.0/21" {
		t.Fatalf("egress CIDR = %q, want Atlassian CIDR", got)
	}

	if len(artifacts.IstioAuthorizationPolicies) != 1 {
		t.Fatalf("IstioAuthorizationPolicies = %d, want 1", len(artifacts.IstioAuthorizationPolicies))
	}
	authz := artifacts.IstioAuthorizationPolicies[0]
	if authz.Kind != "AuthorizationPolicy" {
		t.Fatalf("authz kind = %q, want AuthorizationPolicy", authz.Kind)
	}
	if got := authz.Spec.Rules[0].From[0].Source.Principals[0]; got != "cluster.local/ns/prod/sa/demo-runtime" {
		t.Fatalf("authz principal = %q", got)
	}
}

func TestCompileFlowEnforcesDeclaredCredentialRefs(t *testing.T) {
	artifacts, err := Compile(AgenticFlow{
		APIVersion: "nullfield.io/v1alpha1",
		Kind:       "AgenticFlow",
		Metadata:   v1alpha1.Metadata{Name: "demo-jira"},
		Spec: FlowSpec{
			Credentials: []FlowCredential{
				{
					Name:      "jira-read",
					From:      "vault",
					SecretRef: "jira-read-token",
					InjectAs:  "token",
					OAuth: &OAuthSpec{
						Audience: "https://api.atlassian.com",
						Scopes:   []string{"read:jira-work"},
					},
					AuditLabels: map[string]string{"credential": "jira-read", "provider": "atlassian"},
				},
			},
			Tools: []FlowTool{
				{
					Name:           "mcp-atlassian.search",
					Action:         v1alpha1.ActionAllow,
					CredentialRefs: []string{"jira-read"},
					AuditLabels:    map[string]string{"system": "jira"},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}

	rule := artifacts.Policy.Spec.Rules[0]
	if rule.Action != v1alpha1.ActionScope {
		t.Fatalf("credentialed action = %q, want SCOPE", rule.Action)
	}
	if rule.Scope == nil || rule.Scope.Request == nil {
		t.Fatal("expected compiled credential rule to have request scope")
	}
	gotCred := rule.Scope.Request.InjectCredentials[0]
	if gotCred.SecretRef != "jira-read-token" || gotCred.From != "vault" || gotCred.InjectAs != "token" {
		t.Fatalf("compiled credential = %+v", gotCred)
	}
	if rule.AuditLabels["credential"] != "jira-read" {
		t.Fatalf("credential audit label = %q, want jira-read", rule.AuditLabels["credential"])
	}
	if rule.AuditLabels["oauth_audience"] != "https://api.atlassian.com" {
		t.Fatalf("oauth audience label = %q", rule.AuditLabels["oauth_audience"])
	}
	if rule.AuditLabels["oauth_scopes"] != "read:jira-work" {
		t.Fatalf("oauth scopes label = %q", rule.AuditLabels["oauth_scopes"])
	}
}

func TestCompileFlowRejectsUndeclaredCredentialRefs(t *testing.T) {
	_, err := Compile(AgenticFlow{
		APIVersion: "nullfield.io/v1alpha1",
		Kind:       "AgenticFlow",
		Metadata:   v1alpha1.Metadata{Name: "demo-jira"},
		Spec: FlowSpec{
			Tools: []FlowTool{
				{
					Name:           "mcp-atlassian.search",
					Action:         v1alpha1.ActionAllow,
					CredentialRefs: []string{"missing"},
				},
			},
		},
	})
	if err == nil {
		t.Fatal("expected undeclared credential ref to fail compilation")
	}
}

func TestCompileFlowRejectsBroadNetworkPolicyIntent(t *testing.T) {
	cases := []struct {
		name string
		spec FlowSpec
	}{
		{
			name: "network without selector",
			spec: FlowSpec{
				Network: &NetworkSpec{Egress: []EgressDestination{{CIDR: "104.192.136.0/21", Ports: []int{443}}}},
				Tools:   []FlowTool{{Name: "mcp-atlassian.read_issue", Action: v1alpha1.ActionAllow}},
			},
		},
		{
			name: "network without ports",
			spec: FlowSpec{
				Selector: v1alpha1.Selector{MatchLabels: map[string]string{"app": "demo-agent"}},
				Network:  &NetworkSpec{Egress: []EgressDestination{{CIDR: "104.192.136.0/21"}}},
				Tools:    []FlowTool{{Name: "mcp-atlassian.read_issue", Action: v1alpha1.ActionAllow}},
			},
		},
		{
			name: "istio without principals",
			spec: FlowSpec{
				Selector: v1alpha1.Selector{MatchLabels: map[string]string{"app": "demo-agent"}},
				Mesh:     &MeshSpec{Istio: &IstioAuthzSpec{Ports: []int{9090}}},
				Tools:    []FlowTool{{Name: "mcp-atlassian.read_issue", Action: v1alpha1.ActionAllow}},
			},
		},
		{
			name: "istio without ports",
			spec: FlowSpec{
				Selector: v1alpha1.Selector{MatchLabels: map[string]string{"app": "demo-agent"}},
				Mesh:     &MeshSpec{Istio: &IstioAuthzSpec{Principals: []string{"cluster.local/ns/prod/sa/demo-runtime"}}},
				Tools:    []FlowTool{{Name: "mcp-atlassian.read_issue", Action: v1alpha1.ActionAllow}},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Compile(AgenticFlow{
				APIVersion: "nullfield.io/v1alpha1",
				Kind:       "AgenticFlow",
				Metadata:   v1alpha1.Metadata{Name: "demo-jira"},
				Spec:       c.spec,
			})
			if err == nil {
				t.Fatal("expected Compile to reject broad network/authz intent")
			}
		})
	}
}

func TestMarshalArtifactsYAMLEmitsOptInNetworkDocuments(t *testing.T) {
	artifacts, err := Compile(AgenticFlow{
		APIVersion: "nullfield.io/v1alpha1",
		Kind:       "AgenticFlow",
		Metadata:   v1alpha1.Metadata{Name: "demo-jira", Namespace: "prod"},
		Spec: FlowSpec{
			Selector: v1alpha1.Selector{MatchLabels: map[string]string{"app": "demo-agent"}},
			Network:  &NetworkSpec{Egress: []EgressDestination{{CIDR: "104.192.136.0/21", Ports: []int{443}}}},
			Mesh: &MeshSpec{Istio: &IstioAuthzSpec{
				Principals: []string{"cluster.local/ns/prod/sa/demo-runtime"},
				Ports:      []int{9090},
			}},
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
	for _, want := range []string{
		"kind: NetworkPolicy",
		"name: demo-jira-egress",
		"cidr: 104.192.136.0/21",
		"kind: AuthorizationPolicy",
		"name: demo-jira-authz",
		"principals:",
		"- \"9090\"",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
}

func TestCompileFlowEmitsCiliumAndLinkerdPolicies(t *testing.T) {
	artifacts, err := Compile(AgenticFlow{
		APIVersion: "nullfield.io/v1alpha1",
		Kind:       "AgenticFlow",
		Metadata:   v1alpha1.Metadata{Name: "demo-jira", Namespace: "prod"},
		Spec: FlowSpec{
			Selector: v1alpha1.Selector{MatchLabels: map[string]string{"app": "demo-agent"}},
			Mesh: &MeshSpec{
				Cilium: &CiliumSpec{Ingress: []CiliumIngressRule{{
					FromEndpoints: []map[string]string{{"app": "demo-runtime"}},
					Port:          9090,
					Methods:       []string{"POST"},
				}}},
				Linkerd: &LinkerdSpec{Servers: []LinkerdServerSpec{{
					Name:       "demo-mcp",
					Port:       9090,
					Identities: []string{"demo-runtime.prod.serviceaccount.identity.linkerd.cluster.local"},
				}}},
			},
			Tools: []FlowTool{{Name: "mcp-atlassian.read_issue", Action: v1alpha1.ActionAllow}},
		},
	})
	if err != nil {
		t.Fatalf("Compile returned error: %v", err)
	}

	if len(artifacts.CiliumNetworkPolicies) != 1 {
		t.Fatalf("CiliumNetworkPolicies = %d, want 1", len(artifacts.CiliumNetworkPolicies))
	}
	cilium := artifacts.CiliumNetworkPolicies[0]
	if cilium.Kind != "CiliumNetworkPolicy" {
		t.Fatalf("cilium kind = %q, want CiliumNetworkPolicy", cilium.Kind)
	}
	if got := cilium.Spec.Ingress[0].ToPorts[0].Ports[0].Port; got != "9090" {
		t.Fatalf("cilium port = %q, want 9090", got)
	}
	if got := cilium.Spec.Ingress[0].ToPorts[0].Rules.HTTP[0].Method; got != "POST" {
		t.Fatalf("cilium method = %q, want POST", got)
	}
	if got := cilium.Spec.Ingress[0].FromEndpoints[0]["app"]; got != "demo-runtime" {
		t.Fatalf("cilium source label = %q, want demo-runtime", got)
	}

	if len(artifacts.LinkerdServers) != 1 {
		t.Fatalf("LinkerdServers = %d, want 1", len(artifacts.LinkerdServers))
	}
	server := artifacts.LinkerdServers[0]
	if server.Kind != "Server" || server.Spec.Port != 9090 {
		t.Fatalf("linkerd server = %+v", server)
	}
	if len(artifacts.LinkerdServerAuthorizations) != 1 {
		t.Fatalf("LinkerdServerAuthorizations = %d, want 1", len(artifacts.LinkerdServerAuthorizations))
	}
	authz := artifacts.LinkerdServerAuthorizations[0]
	if got := authz.Spec.Client.MeshTLS.Identities[0]; got != "demo-runtime.prod.serviceaccount.identity.linkerd.cluster.local" {
		t.Fatalf("linkerd identity = %q", got)
	}
}

func TestCompileFlowRejectsBroadCiliumAndLinkerdIntent(t *testing.T) {
	cases := []struct {
		name string
		mesh *MeshSpec
	}{
		{
			name: "cilium without source endpoints",
			mesh: &MeshSpec{Cilium: &CiliumSpec{Ingress: []CiliumIngressRule{{Port: 9090, Methods: []string{"POST"}}}}},
		},
		{
			name: "cilium without HTTP methods",
			mesh: &MeshSpec{Cilium: &CiliumSpec{Ingress: []CiliumIngressRule{{
				FromEndpoints: []map[string]string{{"app": "demo-runtime"}},
				Port:          9090,
				Paths:         []string{"/mcp"},
			}}}},
		},
		{
			name: "cilium without ingress rules",
			mesh: &MeshSpec{Cilium: &CiliumSpec{}},
		},
		{
			name: "linkerd without identity decision",
			mesh: &MeshSpec{Linkerd: &LinkerdSpec{Servers: []LinkerdServerSpec{{Name: "demo-mcp", Port: 9090}}}},
		},
		{
			name: "linkerd without servers",
			mesh: &MeshSpec{Linkerd: &LinkerdSpec{}},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Compile(AgenticFlow{
				APIVersion: "nullfield.io/v1alpha1",
				Kind:       "AgenticFlow",
				Metadata:   v1alpha1.Metadata{Name: "demo-jira"},
				Spec: FlowSpec{
					Selector: v1alpha1.Selector{MatchLabels: map[string]string{"app": "demo-agent"}},
					Mesh:     c.mesh,
					Tools:    []FlowTool{{Name: "mcp-atlassian.read_issue", Action: v1alpha1.ActionAllow}},
				},
			})
			if err == nil {
				t.Fatal("expected Compile to reject broad mesh intent")
			}
		})
	}
}
