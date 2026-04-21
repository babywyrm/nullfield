package injector

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
)

const (
	AnnotationInject    = "nullfield.io/inject"
	AnnotationPolicy    = "nullfield.io/policy"
	AnnotationRegistry  = "nullfield.io/registry"
	AnnotationPort      = "nullfield.io/upstream-port"
	AnnotationStatus    = "nullfield.io/status"
)

// Webhook handles Kubernetes MutatingAdmissionWebhook requests.
type Webhook struct {
	config *SidecarConfig
	logger *slog.Logger
}

func NewWebhook(cfg *SidecarConfig, logger *slog.Logger) *Webhook {
	return &Webhook{config: cfg, logger: logger}
}

func (wh *Webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body failed", http.StatusBadRequest)
		return
	}

	var review AdmissionReview
	if err := json.Unmarshal(body, &review); err != nil {
		http.Error(w, "unmarshal failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	response := wh.mutate(&review)

	reviewResponse := AdmissionReview{
		APIVersion: "admission.k8s.io/v1",
		Kind:       "AdmissionReview",
		Response:   response,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reviewResponse)
}

func (wh *Webhook) mutate(review *AdmissionReview) *AdmissionResponse {
	req := review.Request
	if req == nil {
		return &AdmissionResponse{UID: "", Allowed: true}
	}

	resp := &AdmissionResponse{
		UID:     req.UID,
		Allowed: true,
	}

	var pod PodSpec
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		wh.logger.Error("failed to unmarshal pod", "error", err)
		resp.Allowed = true
		return resp
	}

	annotations := pod.Metadata.Annotations
	if annotations == nil {
		return resp
	}

	inject, ok := annotations[AnnotationInject]
	if !ok || inject != "true" {
		return resp
	}

	// Already injected?
	if annotations[AnnotationStatus] == "injected" {
		wh.logger.Info("pod already injected, skipping", "name", pod.Metadata.Name)
		return resp
	}

	for _, c := range pod.Spec.Containers {
		if c.Name == "nullfield" {
			wh.logger.Info("nullfield container already present, skipping", "name", pod.Metadata.Name)
			return resp
		}
	}

	upstreamPort := wh.config.DefaultUpstreamPort
	if portStr, ok := annotations[AnnotationPort]; ok {
		if p, err := strconv.Atoi(portStr); err == nil {
			upstreamPort = p
		}
	}
	if upstreamPort == 0 && len(pod.Spec.Containers) > 0 && len(pod.Spec.Containers[0].Ports) > 0 {
		upstreamPort = pod.Spec.Containers[0].Ports[0].ContainerPort
	}
	if upstreamPort == 0 {
		upstreamPort = 8080
	}

	policyConfigMap := wh.config.DefaultPolicyConfigMap
	if cm, ok := annotations[AnnotationPolicy]; ok {
		policyConfigMap = cm
	}

	registryConfigMap := wh.config.DefaultRegistryConfigMap
	if cm, ok := annotations[AnnotationRegistry]; ok {
		registryConfigMap = cm
	}

	patch := buildPatch(wh.config, upstreamPort, policyConfigMap, registryConfigMap)

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		wh.logger.Error("failed to marshal patch", "error", err)
		return resp
	}

	patchType := "JSONPatch"
	resp.PatchType = &patchType
	resp.Patch = patchBytes

	wh.logger.Info("injecting nullfield sidecar",
		"pod", pod.Metadata.Name,
		"namespace", req.Namespace,
		"upstream", fmt.Sprintf("localhost:%d", upstreamPort),
		"policy", policyConfigMap)

	return resp
}

func buildPatch(cfg *SidecarConfig, upstreamPort int, policyCM, registryCM string) []PatchOp {
	var patches []PatchOp

	sidecar := map[string]any{
		"name":            "nullfield",
		"image":           cfg.Image,
		"imagePullPolicy": cfg.ImagePullPolicy,
		"ports": []map[string]any{
			{"name": "proxy", "containerPort": cfg.ListenPort, "protocol": "TCP"},
			{"name": "admin", "containerPort": cfg.AdminPort, "protocol": "TCP"},
		},
		"env": []map[string]any{
			{"name": "NULLFIELD_LISTEN_ADDR", "value": fmt.Sprintf(":%d", cfg.ListenPort)},
			{"name": "NULLFIELD_ADMIN_ADDR", "value": fmt.Sprintf(":%d", cfg.AdminPort)},
			{"name": "NULLFIELD_UPSTREAM_ADDR", "value": fmt.Sprintf("localhost:%d", upstreamPort)},
			{"name": "NULLFIELD_POLICY_PATH", "value": "/etc/nullfield/policy.yaml"},
			{"name": "NULLFIELD_REGISTRY_PATH", "value": "/etc/nullfield/tools.yaml"},
		},
		"volumeMounts": []map[string]any{
			{"name": "nullfield-config", "mountPath": "/etc/nullfield", "readOnly": true},
		},
		"livenessProbe": map[string]any{
			"httpGet":             map[string]any{"path": "/healthz", "port": cfg.AdminPort},
			"initialDelaySeconds": 3,
			"periodSeconds":       10,
		},
		"readinessProbe": map[string]any{
			"httpGet":             map[string]any{"path": "/readyz", "port": cfg.AdminPort},
			"initialDelaySeconds": 2,
			"periodSeconds":       5,
		},
		"resources": map[string]any{
			"requests": map[string]any{"cpu": cfg.ResourceRequests.CPU, "memory": cfg.ResourceRequests.Memory},
			"limits":   map[string]any{"cpu": cfg.ResourceLimits.CPU, "memory": cfg.ResourceLimits.Memory},
		},
		"securityContext": map[string]any{
			"runAsNonRoot":             true,
			"runAsUser":                65534,
			"readOnlyRootFilesystem":   true,
			"allowPrivilegeEscalation": false,
			"capabilities":             map[string]any{"drop": []string{"ALL"}},
		},
	}

	patches = append(patches, PatchOp{
		Op:    "add",
		Path:  "/spec/containers/-",
		Value: sidecar,
	})

	// Add ConfigMap volume for policy/registry.
	volume := map[string]any{
		"name": "nullfield-config",
		"projected": map[string]any{
			"sources": []map[string]any{},
		},
	}

	var sources []map[string]any
	if policyCM != "" {
		sources = append(sources, map[string]any{
			"configMap": map[string]any{
				"name": policyCM,
				"items": []map[string]any{
					{"key": "policy.yaml", "path": "policy.yaml"},
				},
			},
		})
	}
	if registryCM != "" {
		sources = append(sources, map[string]any{
			"configMap": map[string]any{
				"name": registryCM,
				"items": []map[string]any{
					{"key": "tools.yaml", "path": "tools.yaml"},
				},
			},
		})
	}
	if len(sources) > 0 {
		volume["projected"] = map[string]any{"sources": sources}
	}

	patches = append(patches, PatchOp{
		Op:    "add",
		Path:  "/spec/volumes/-",
		Value: volume,
	})

	// Mark as injected.
	patches = append(patches, PatchOp{
		Op:    "add",
		Path:  "/metadata/annotations/nullfield.io~1status",
		Value: "injected",
	})

	return patches
}
