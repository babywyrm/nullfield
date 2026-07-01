package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunCompilesFlowFromStdin(t *testing.T) {
	input := strings.NewReader(`
apiVersion: nullfield.io/v1alpha1
kind: AgenticFlow
metadata:
  name: demo-jira
spec:
  tools:
    - name: mcp-atlassian.read_issue
      action: ALLOW
`)
	var out bytes.Buffer

	if err := run([]string{"nullfield-compile"}, input, &out); err != nil {
		t.Fatalf("run returned error: %v", err)
	}

	text := out.String()
	if !strings.Contains(text, "kind: NullfieldPolicy") {
		t.Fatalf("output missing NullfieldPolicy:\n%s", text)
	}
	if !strings.Contains(text, "kind: ToolRegistry") {
		t.Fatalf("output missing ToolRegistry:\n%s", text)
	}
}
