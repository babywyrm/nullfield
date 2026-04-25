package inspection

import (
	"strings"
	"testing"
)

func TestInspect_Credentials(t *testing.T) {
	insp := New(Config{DetectCredentials: true})

	tests := []struct {
		name    string
		input   string
		wantCat string
	}{
		{"private key", "-----BEGIN PRIVATE KEY-----\ndata\n-----END PRIVATE KEY-----", "credential"},
		{"password assignment", `password: "hunter2secret"`, "credential"},
		{"api key pattern", "Authorization: sk-abcdefghijklmnopqrstuvwx", "credential"},
		{"bearer token", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6Ik", "credential"},
		{"aws secret", "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "credential"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := insp.Inspect(tt.input)
			if len(findings) == 0 {
				t.Fatalf("expected findings for %q", tt.name)
			}
			if findings[0].Category != tt.wantCat {
				t.Fatalf("expected category %q, got %q", tt.wantCat, findings[0].Category)
			}
		})
	}
}

func TestInspect_PII(t *testing.T) {
	insp := New(Config{DetectPII: true})

	findings := insp.Inspect("SSN: 123-45-6789")
	if len(findings) == 0 {
		t.Fatal("expected SSN finding")
	}

	findings = insp.Inspect("contact: user@example.com")
	if len(findings) == 0 {
		t.Fatal("expected email finding")
	}
}

func TestInspect_PromptLeak(t *testing.T) {
	insp := New(Config{DetectPromptLeak: true})

	findings := insp.Inspect("System prompt: You are an AI assistant that helps with coding")
	if len(findings) == 0 {
		t.Fatal("expected prompt leak finding")
	}
}

func TestInspect_InternalPaths(t *testing.T) {
	insp := New(Config{DetectInternalPaths: true})

	findings := insp.Inspect("reading /var/run/secrets/kubernetes/token")
	if len(findings) == 0 {
		t.Fatal("expected k8s path finding")
	}

	findings = insp.Inspect("connecting to auth-service.teleport.svc.cluster.local")
	if len(findings) == 0 {
		t.Fatal("expected k8s DNS finding")
	}
}

func TestInspect_CleanContent(t *testing.T) {
	insp := New(DefaultConfig())

	findings := insp.Inspect("The weather today is sunny with a high of 72F.")
	if len(findings) != 0 {
		t.Fatalf("expected no findings for clean content, got %d", len(findings))
	}
}

func TestRedact(t *testing.T) {
	insp := New(Config{DetectCredentials: true})

	input := `config:
  password: "supersecret123"
  api_key: sk-abcdefghijklmnopqrstuvwxyz`

	redacted, count := insp.Redact(input, "[REDACTED]")
	if count == 0 {
		t.Fatal("expected redactions")
	}
	if strings.Contains(redacted, "supersecret") {
		t.Fatal("credential was not redacted")
	}
	if strings.Contains(redacted, "sk-abcdefgh") {
		t.Fatal("API key was not redacted")
	}
	if !strings.Contains(redacted, "[REDACTED]") {
		t.Fatal("expected [REDACTED] placeholder")
	}
}

func TestHasSensitiveContent(t *testing.T) {
	insp := New(DefaultConfig())

	if !insp.HasSensitiveContent("password: secret123value") {
		t.Fatal("expected sensitive content detected")
	}
	if insp.HasSensitiveContent("Hello world") {
		t.Fatal("expected no sensitive content")
	}
}

func TestCustomPatterns(t *testing.T) {
	insp := New(Config{
		CustomPatterns: []string{`INTERNAL-\d{6}`},
	})

	findings := insp.Inspect("Reference: INTERNAL-123456")
	if len(findings) == 0 {
		t.Fatal("expected custom pattern finding")
	}
	if findings[0].Category != "custom" {
		t.Fatalf("expected category 'custom', got %q", findings[0].Category)
	}
}

func TestSummarize(t *testing.T) {
	s := Summarize(nil)
	if s != "no sensitive content detected" {
		t.Fatalf("unexpected summary for empty: %q", s)
	}

	findings := []Finding{
		{Category: "credential", Severity: "HIGH"},
		{Category: "credential", Severity: "HIGH"},
		{Category: "pii", Severity: "MEDIUM"},
	}
	s = Summarize(findings)
	if !strings.Contains(s, "credential") || !strings.Contains(s, "pii") {
		t.Fatalf("summary missing categories: %q", s)
	}
}
