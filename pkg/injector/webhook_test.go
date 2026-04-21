package injector

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testConfig() *SidecarConfig {
	return &SidecarConfig{
		Image:            "ghcr.io/babywyrm/nullfield:test",
		ImagePullPolicy:  "IfNotPresent",
		ListenPort:       9090,
		AdminPort:        9091,
		ResourceRequests: ResourceSpec{CPU: "50m", Memory: "64Mi"},
		ResourceLimits:   ResourceSpec{CPU: "200m", Memory: "128Mi"},
	}
}

func buildReview(annotations map[string]string, containers []Container) []byte {
	if containers == nil {
		containers = []Container{{
			Name:  "app",
			Image: "myapp:latest",
			Ports: []ContainerPort{{ContainerPort: 8080}},
		}}
	}

	pod := PodSpec{
		Metadata: PodMeta{
			Name:        "test-pod",
			Annotations: annotations,
		},
		Spec: PodSpecInner{
			Containers: containers,
			Volumes:    []Volume{{Name: "existing"}},
		},
	}

	podBytes, _ := json.Marshal(pod)
	review := map[string]any{
		"apiVersion": "admission.k8s.io/v1",
		"kind":       "AdmissionReview",
		"request": map[string]any{
			"uid":       "test-uid-123",
			"namespace": "default",
			"object":    json.RawMessage(podBytes),
		},
	}
	data, _ := json.Marshal(review)
	return data
}

func doMutate(t *testing.T, cfg *SidecarConfig, body []byte) AdmissionReview {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	wh := NewWebhook(cfg, logger)

	req := httptest.NewRequest(http.MethodPost, "/mutate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp AdmissionReview
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response failed: %v", err)
	}
	return resp
}

func TestWebhook_InjectEnabled(t *testing.T) {
	body := buildReview(map[string]string{
		AnnotationInject: "true",
	}, nil)

	resp := doMutate(t, testConfig(), body)

	if !resp.Response.Allowed {
		t.Fatal("expected allowed")
	}
	if resp.Response.PatchType == nil || *resp.Response.PatchType != "JSONPatch" {
		t.Fatal("expected JSONPatch patch type")
	}
	if resp.Response.Patch == nil {
		t.Fatal("expected patch to be non-nil")
	}

	var patches []PatchOp
	if err := json.Unmarshal(resp.Response.Patch, &patches); err != nil {
		t.Fatalf("unmarshal patch failed: %v", err)
	}
	if len(patches) != 3 {
		t.Fatalf("expected 3 patch ops (container + volume + annotation), got %d", len(patches))
	}

	// First patch should add the sidecar container.
	if patches[0].Path != "/spec/containers/-" {
		t.Fatalf("expected container patch, got path %q", patches[0].Path)
	}
	container := patches[0].Value.(map[string]any)
	if container["name"] != "nullfield" {
		t.Fatalf("expected container name 'nullfield', got %q", container["name"])
	}
	if container["image"] != "ghcr.io/babywyrm/nullfield:test" {
		t.Fatalf("expected test image, got %q", container["image"])
	}

	// Check upstream port auto-detection via re-marshaling the env list.
	upstreamEnv := extractEnvValue(t, container, "NULLFIELD_UPSTREAM_ADDR")
	if upstreamEnv != "localhost:8080" {
		t.Fatalf("expected upstream localhost:8080, got %q", upstreamEnv)
	}
}

func TestWebhook_NoAnnotation(t *testing.T) {
	body := buildReview(map[string]string{}, nil)
	resp := doMutate(t, testConfig(), body)

	if !resp.Response.Allowed {
		t.Fatal("expected allowed")
	}
	if resp.Response.Patch != nil {
		t.Fatal("expected no patch when inject annotation is missing")
	}
}

func TestWebhook_InjectFalse(t *testing.T) {
	body := buildReview(map[string]string{
		AnnotationInject: "false",
	}, nil)
	resp := doMutate(t, testConfig(), body)

	if resp.Response.Patch != nil {
		t.Fatal("expected no patch when inject=false")
	}
}

func TestWebhook_AlreadyInjected(t *testing.T) {
	body := buildReview(map[string]string{
		AnnotationInject: "true",
		AnnotationStatus: "injected",
	}, nil)
	resp := doMutate(t, testConfig(), body)

	if resp.Response.Patch != nil {
		t.Fatal("expected no patch for already-injected pod")
	}
}

func TestWebhook_ExistingSidecar(t *testing.T) {
	body := buildReview(map[string]string{
		AnnotationInject: "true",
	}, []Container{
		{Name: "app", Ports: []ContainerPort{{ContainerPort: 8080}}},
		{Name: "nullfield"},
	})
	resp := doMutate(t, testConfig(), body)

	if resp.Response.Patch != nil {
		t.Fatal("expected no patch when nullfield container already exists")
	}
}

func TestWebhook_CustomPort(t *testing.T) {
	body := buildReview(map[string]string{
		AnnotationInject: "true",
		AnnotationPort:   "3000",
	}, nil)
	resp := doMutate(t, testConfig(), body)

	var patches []PatchOp
	json.Unmarshal(resp.Response.Patch, &patches)

	container := patches[0].Value.(map[string]any)
	val := extractEnvValue(t, container, "NULLFIELD_UPSTREAM_ADDR")
	if val != "localhost:3000" {
		t.Fatalf("expected localhost:3000, got %q", val)
	}
}

// extractEnvValue pulls a named env var from a container patch value.
// Handles JSON round-trip where []map[string]any becomes []any.
func extractEnvValue(t *testing.T, container map[string]any, name string) string {
	t.Helper()
	envRaw, ok := container["env"]
	if !ok {
		t.Fatal("no env in container")
	}
	envBytes, _ := json.Marshal(envRaw)
	var envList []map[string]string
	if err := json.Unmarshal(envBytes, &envList); err != nil {
		t.Fatalf("env unmarshal failed: %v", err)
	}
	for _, e := range envList {
		if e["name"] == name {
			return e["value"]
		}
	}
	t.Fatalf("env var %q not found", name)
	return ""
}

func TestWebhook_CustomConfigMaps(t *testing.T) {
	cfg := testConfig()
	cfg.DefaultPolicyConfigMap = "default-policy"
	cfg.DefaultRegistryConfigMap = "default-registry"

	body := buildReview(map[string]string{
		AnnotationInject:   "true",
		AnnotationPolicy:   "custom-policy",
		AnnotationRegistry: "custom-registry",
	}, nil)
	resp := doMutate(t, cfg, body)

	var patches []PatchOp
	json.Unmarshal(resp.Response.Patch, &patches)

	// Re-marshal/unmarshal the volume patch to normalize types after JSON round-trip.
	volBytes, _ := json.Marshal(patches[1].Value)
	var volumePatch map[string]json.RawMessage
	json.Unmarshal(volBytes, &volumePatch)

	var projected struct {
		Sources []struct {
			ConfigMap struct {
				Name string `json:"name"`
			} `json:"configMap"`
		} `json:"sources"`
	}
	json.Unmarshal(volumePatch["projected"], &projected)

	if len(projected.Sources) != 2 {
		t.Fatalf("expected 2 projected sources, got %d", len(projected.Sources))
	}
	if projected.Sources[0].ConfigMap.Name != "custom-policy" {
		t.Fatalf("expected policy CM 'custom-policy', got %q", projected.Sources[0].ConfigMap.Name)
	}
	if projected.Sources[1].ConfigMap.Name != "custom-registry" {
		t.Fatalf("expected registry CM 'custom-registry', got %q", projected.Sources[1].ConfigMap.Name)
	}
}

func TestWebhook_StatusAnnotation(t *testing.T) {
	body := buildReview(map[string]string{
		AnnotationInject: "true",
	}, nil)
	resp := doMutate(t, testConfig(), body)

	var patches []PatchOp
	json.Unmarshal(resp.Response.Patch, &patches)

	found := false
	for _, p := range patches {
		if p.Path == "/metadata/annotations/nullfield.io~1status" {
			found = true
			if p.Value != "injected" {
				t.Fatalf("expected 'injected' annotation value, got %v", p.Value)
			}
		}
	}
	if !found {
		t.Fatal("expected status annotation patch")
	}
}

func TestWebhook_SecurityContext(t *testing.T) {
	body := buildReview(map[string]string{
		AnnotationInject: "true",
	}, nil)
	resp := doMutate(t, testConfig(), body)

	var patches []PatchOp
	json.Unmarshal(resp.Response.Patch, &patches)

	container := patches[0].Value.(map[string]any)
	scRaw := container["securityContext"]
	scBytes, _ := json.Marshal(scRaw)
	var sc struct {
		RunAsNonRoot             bool `json:"runAsNonRoot"`
		RunAsUser                int  `json:"runAsUser"`
		ReadOnlyRootFilesystem   bool `json:"readOnlyRootFilesystem"`
		AllowPrivilegeEscalation bool `json:"allowPrivilegeEscalation"`
	}
	json.Unmarshal(scBytes, &sc)

	if !sc.RunAsNonRoot {
		t.Fatal("expected runAsNonRoot=true")
	}
	if sc.RunAsUser != 65534 {
		t.Fatalf("expected runAsUser=65534, got %d", sc.RunAsUser)
	}
	if !sc.ReadOnlyRootFilesystem {
		t.Fatal("expected readOnlyRootFilesystem=true")
	}
	if sc.AllowPrivilegeEscalation {
		t.Fatal("expected allowPrivilegeEscalation=false")
	}
}
