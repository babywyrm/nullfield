package policy

import (
	"strings"
	"testing"
)

const header = "apiVersion: nullfield.io/v1alpha1\nkind: NullfieldPolicy\nmetadata:\n  name: t\nspec:\n"

func parse(spec string) error {
	_, err := ParseSpec([]byte(header + spec))
	return err
}

func TestAValidPolicyParses(t *testing.T) {
	err := parse(`  rules:
    - action: ALLOW
      mcpMethod: tools/call
      toolNames: [echo]
      maxCallsPerMinute: 10
`)
	if err != nil {
		t.Fatal(err)
	}
}

// Every field below is accepted by the schema and enforced nowhere. Each one
// reads as a control; the policy that sets it is refused rather than run
// without it.
func TestAPolicyThatSetsAnUnenforcedFieldIsRefused(t *testing.T) {
	for name, spec := range map[string]string{
		"misspelt key": `  rules:
    - action: ALLOW
      requireIdentiy: true
`,
		"celExpression": `  rules:
    - action: ALLOW
      celExpression: "request.target == 'api.github.com'"
`,
		// Ignoring these turns "allow outbound to one host" into "allow
		// everything".
		"direction and destination": `  rules:
    - action: ALLOW
      direction: OUTBOUND
      destination: api.anthropic.com
`,
		"injectCredential": `  rules:
    - action: ALLOW
      injectCredential: {secretRef: k, from: env}
`,
		"paramRules": `  rules:
    - action: ALLOW
      paramRules: [{name: path, pattern: "^/tmp"}]
`,
		"hold notify": `  rules:
    - action: HOLD
      hold: {notify: {webhook: "https://example.invalid/hook"}}
`,
		"integrity chainValidation": `  integrity: {enabled: true, chainValidation: true}
  rules: [{action: ALLOW}]
`,
		"anomaly sequences": `  anomaly:
    enabled: true
    sequences: [{name: s, tools: [a, b], alertAction: DENY}]
  rules: [{action: ALLOW}]
`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := parse(spec); err == nil {
				t.Fatal("parsed; want refusal")
			}
		})
	}
}

// A reaction is accepted only when it names what actually happens.
func TestAReactionNullfieldDoesNotPerformIsRefused(t *testing.T) {
	for spec, want := range map[string]bool{
		"  rules: [{action: ALLOW, budget: {perIdentity: {maxCallsPerHour: 1}, onExhausted: DENY}}]\n": true,
		"  rules: [{action: ALLOW, budget: {perIdentity: {maxCallsPerHour: 1}, onExhausted: LOG}}]\n":  false,
		"  rules: [{action: ALLOW}]\n  circuitBreaker: {onTrip: DENY}\n":                               true,
		"  rules: [{action: ALLOW}]\n  circuitBreaker: {onTrip: REJECT}\n":                             true,
		"  rules: [{action: ALLOW}]\n  circuitBreaker: {onTrip: KILL_POD}\n":                           false,
	} {
		if err := parse(spec); (err == nil) != want {
			t.Errorf("%s: err %v, want accepted=%v", strings.TrimSpace(spec), err, want)
		}
	}
}

func TestRequireAudienceWithAProviderThatListsNoneIsRefused(t *testing.T) {
	// The verifier checks audience only against a configured list, so this
	// would accept a token minted for any service on the same issuer.
	err := parse(`  identity:
    enabled: true
    providers: [{name: okta, issuer: "https://okta.example", jwksUri: "https://okta.example/keys"}]
    validation: {requireAudience: true}
  rules: [{action: ALLOW}]
`)
	if err == nil || !strings.Contains(err.Error(), "okta") {
		t.Fatalf("err %v; want a refusal naming the provider", err)
	}
}

func TestAnUnparseableDurationIsRefused(t *testing.T) {
	for name, spec := range map[string]string{
		"maxLifetime": `  identity:
    enabled: true
    providers: [{name: p, issuer: i, jwksUri: u}]
    validation: {maxLifetime: "an hour"}
  rules: [{action: ALLOW}]
`,
		"clockSkew": `  identity:
    enabled: true
    providers: [{name: p, issuer: i, jwksUri: u, clockSkew: "30"}]
  rules: [{action: ALLOW}]
`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := parse(spec); err == nil {
				t.Fatal("parsed; want refusal")
			}
		})
	}
}
