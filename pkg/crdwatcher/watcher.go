// Package crdwatcher watches NullfieldPolicy and ToolRegistry CRDs and
// syncs their content to ConfigMaps that nullfield sidecars mount.
//
// This is a lightweight controller that uses the K8s API directly — no
// client-go dependency, no code generation, no kubebuilder.
package crdwatcher

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Watcher watches NullfieldPolicy and ToolRegistry CRDs and syncs
// their content to ConfigMaps.
type Watcher struct {
	apiBase   string
	token     string
	namespace string
	client    *http.Client
	logger    *slog.Logger

	// Optional sidecar-bridge fields. When ActiveTargetCM and
	// ActiveTargetLabel are both set, the watcher additionally syncs the
	// FIRST NullfieldPolicy carrying label `nullfield.io/active-for=<value>`
	// into <ActiveTargetCM>:<ActiveTargetCMKey> as a single policy.yaml.
	// This is what lets the per-policy CRDs in the cluster actually drive
	// a sidecar that mounts a single policy file.
	activeTargetCM    string
	activeTargetCMKey string
	activeTargetLabel string

	mu             sync.Mutex
	lastPolicyRV   string
	lastRegistryRV string
	lastActiveSig  string
}

// Config for the watcher.
type Config struct {
	Namespace    string
	SyncInterval time.Duration

	// ActiveTargetCM names a ConfigMap into which a single matching
	// NullfieldPolicy should be aggregated for a sidecar to consume.
	// Empty disables the bridge (default behaviour: per-policy ConfigMaps
	// only).
	ActiveTargetCM string

	// ActiveTargetCMKey is the data key inside ActiveTargetCM (typically
	// "policy.yaml" — the path the sidecar mounts as
	// /etc/nullfield/policy.yaml). Defaults to "policy.yaml".
	ActiveTargetCMKey string

	// ActiveTargetLabel is the value that selects which NullfieldPolicy
	// becomes the active one. The watcher picks the first CRD with
	// metadata.labels["nullfield.io/active-for"] == ActiveTargetLabel.
	ActiveTargetLabel string
}

// New creates a watcher using in-cluster credentials.
func New(cfg Config, logger *slog.Logger) (*Watcher, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("not running in-cluster")
	}

	token, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		return nil, fmt.Errorf("read SA token: %w", err)
	}

	ns := cfg.Namespace
	if ns == "" {
		nsBytes, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			return nil, fmt.Errorf("read namespace: %w", err)
		}
		ns = strings.TrimSpace(string(nsBytes))
	}

	cmKey := cfg.ActiveTargetCMKey
	if cmKey == "" {
		cmKey = "policy.yaml"
	}

	return &Watcher{
		apiBase:   fmt.Sprintf("https://%s:%s", host, port),
		token:     strings.TrimSpace(string(token)),
		namespace: ns,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		logger:            logger,
		activeTargetCM:    cfg.ActiveTargetCM,
		activeTargetCMKey: cmKey,
		activeTargetLabel: cfg.ActiveTargetLabel,
	}, nil
}

// Run starts the sync loop. Blocks until ctx is canceled.
func (w *Watcher) Run(ctx context.Context, interval time.Duration) {
	w.logger.Info("CRD watcher starting", "namespace", w.namespace, "interval", interval)

	w.sync(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.logger.Info("CRD watcher stopping")
			return
		case <-ticker.C:
			w.sync(ctx)
		}
	}
}

func (w *Watcher) sync(ctx context.Context) {
	w.syncPolicies(ctx)
	w.syncRegistries(ctx)
	w.syncActivePolicy(ctx)
}

// syncActivePolicy is the sidecar-bridge: pick the first NullfieldPolicy in
// the watched namespace carrying nullfield.io/active-for=<configured-label>
// and write its rendered YAML to the configured target ConfigMap key. The
// sidecar (mounting that ConfigMap) hot-reloads when the file content
// changes.
//
// No-ops when ActiveTargetCM or ActiveTargetLabel is empty (default).
func (w *Watcher) syncActivePolicy(ctx context.Context) {
	if w.activeTargetCM == "" || w.activeTargetLabel == "" {
		return
	}

	policies, err := w.listCRD(ctx, "nullfieldpolicies")
	if err != nil {
		w.logger.Warn("active-policy sync: failed to list policies", "error", err)
		return
	}

	items, _ := policies["items"].([]any)
	var picked map[string]any
	var pickedName string
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		meta, _ := obj["metadata"].(map[string]any)
		labels, _ := meta["labels"].(map[string]any)
		if labels == nil {
			continue
		}
		if v, _ := labels["nullfield.io/active-for"].(string); v == w.activeTargetLabel {
			picked = obj
			pickedName, _ = meta["name"].(string)
			break
		}
	}

	if picked == nil {
		// Tolerate "no match" — common during initial sync or label edits.
		// Don't write anything (would clobber a working ConfigMap).
		w.logger.Debug("active-policy sync: no NullfieldPolicy with label",
			"label", "nullfield.io/active-for="+w.activeTargetLabel)
		return
	}

	pickedSpec, _ := picked["spec"].(map[string]any)
	if pickedSpec == nil {
		w.logger.Warn("active-policy sync: picked policy has no spec", "name", pickedName)
		return
	}

	policyYAML, err := yaml.Marshal(map[string]any{
		"apiVersion": "nullfield.io/v1alpha1",
		"kind":       "NullfieldPolicy",
		"metadata": map[string]any{
			"name":      pickedName,
			"namespace": w.namespace,
		},
		"spec": pickedSpec,
	})
	if err != nil {
		w.logger.Warn("active-policy sync: failed to marshal", "name", pickedName, "error", err)
		return
	}

	// Cheap change-detection so we don't churn the ConfigMap (and trigger
	// pointless sidecar reloads) when nothing changed.
	w.mu.Lock()
	prev := w.lastActiveSig
	w.mu.Unlock()
	sig := pickedName + ":" + fmt.Sprint(len(policyYAML)) + ":" + string(policyYAML[:min(64, len(policyYAML))])
	if sig == prev {
		return
	}

	if err := w.upsertConfigMap(ctx, w.namespace, w.activeTargetCM,
		map[string]string{w.activeTargetCMKey: string(policyYAML)},
		map[string]string{
			"nullfield.io/managed-by":    "crd-controller",
			"nullfield.io/active-source": pickedName,
			"nullfield.io/sidecar-for":   w.activeTargetLabel,
		},
	); err != nil {
		w.logger.Warn("active-policy sync: failed to write ConfigMap",
			"configmap", w.activeTargetCM, "key", w.activeTargetCMKey, "error", err)
		return
	}

	w.mu.Lock()
	w.lastActiveSig = sig
	w.mu.Unlock()
	w.logger.Info("active-policy sync: bridged NullfieldPolicy to sidecar ConfigMap",
		"policy", pickedName,
		"configmap", w.activeTargetCM,
		"key", w.activeTargetCMKey,
		"label", w.activeTargetLabel)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (w *Watcher) syncPolicies(ctx context.Context) {
	policies, err := w.listCRD(ctx, "nullfieldpolicies")
	if err != nil {
		w.logger.Warn("failed to list NullfieldPolicies", "error", err)
		return
	}

	items, _ := policies["items"].([]any)
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		meta, _ := obj["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		ns, _ := meta["namespace"].(string)
		if ns == "" {
			ns = w.namespace
		}

		spec, _ := obj["spec"].(map[string]any)
		if spec == nil {
			continue
		}

		policyYAML, err := yaml.Marshal(map[string]any{
			"apiVersion": "nullfield.io/v1alpha1",
			"kind":       "NullfieldPolicy",
			"metadata": map[string]any{
				"name":      name,
				"namespace": ns,
			},
			"spec": spec,
		})
		if err != nil {
			w.logger.Warn("failed to marshal policy", "name", name, "error", err)
			continue
		}

		cmName := fmt.Sprintf("nullfield-policy-%s", name)
		if err := w.upsertConfigMap(ctx, ns, cmName, map[string]string{
			"policy.yaml": string(policyYAML),
		}, map[string]string{
			"nullfield.io/managed-by": "crd-controller",
			"nullfield.io/source":     fmt.Sprintf("NullfieldPolicy/%s", name),
		}); err != nil {
			w.logger.Warn("failed to sync policy ConfigMap", "name", cmName, "error", err)
		} else {
			w.logger.Info("synced NullfieldPolicy to ConfigMap", "policy", name, "configmap", cmName, "namespace", ns)
		}
	}
}

func (w *Watcher) syncRegistries(ctx context.Context) {
	registries, err := w.listCRD(ctx, "toolregistries")
	if err != nil {
		w.logger.Warn("failed to list ToolRegistries", "error", err)
		return
	}

	items, _ := registries["items"].([]any)
	for _, item := range items {
		obj, ok := item.(map[string]any)
		if !ok {
			continue
		}
		meta, _ := obj["metadata"].(map[string]any)
		name, _ := meta["name"].(string)
		ns, _ := meta["namespace"].(string)
		if ns == "" {
			ns = w.namespace
		}

		tools, _ := obj["tools"].([]any)

		registryYAML, err := yaml.Marshal(map[string]any{
			"apiVersion": "nullfield/v1alpha1",
			"kind":       "ToolRegistry",
			"metadata": map[string]any{
				"name": name,
			},
			"tools": tools,
		})
		if err != nil {
			w.logger.Warn("failed to marshal registry", "name", name, "error", err)
			continue
		}

		cmName := fmt.Sprintf("nullfield-registry-%s", name)
		if err := w.upsertConfigMap(ctx, ns, cmName, map[string]string{
			"tools.yaml": string(registryYAML),
		}, map[string]string{
			"nullfield.io/managed-by": "crd-controller",
			"nullfield.io/source":     fmt.Sprintf("ToolRegistry/%s", name),
		}); err != nil {
			w.logger.Warn("failed to sync registry ConfigMap", "name", cmName, "error", err)
		} else {
			w.logger.Info("synced ToolRegistry to ConfigMap", "registry", name, "configmap", cmName, "namespace", ns)
		}
	}
}

func (w *Watcher) listCRD(ctx context.Context, resource string) (map[string]any, error) {
	url := fmt.Sprintf("%s/apis/nullfield.io/v1alpha1/namespaces/%s/%s", w.apiBase, w.namespace, resource)
	return w.k8sGet(ctx, url)
}

func (w *Watcher) upsertConfigMap(ctx context.Context, ns, name string, data map[string]string, labels map[string]string) error {
	url := fmt.Sprintf("%s/api/v1/namespaces/%s/configmaps/%s", w.apiBase, ns, name)

	existing, err := w.k8sGet(ctx, url)
	if err == nil && existing != nil {
		cm := map[string]any{
			"apiVersion": "v1",
			"kind":       "ConfigMap",
			"metadata": map[string]any{
				"name":      name,
				"namespace": ns,
				"labels":    labels,
			},
			"data": data,
		}
		return w.k8sPut(ctx, url, cm)
	}

	cm := map[string]any{
		"apiVersion": "v1",
		"kind":       "ConfigMap",
		"metadata": map[string]any{
			"name":      name,
			"namespace": ns,
			"labels":    labels,
		},
		"data": data,
	}
	createURL := fmt.Sprintf("%s/api/v1/namespaces/%s/configmaps", w.apiBase, ns)
	return w.k8sPost(ctx, createURL, cm)
}

func (w *Watcher) k8sGet(ctx context.Context, url string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Accept", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("not found")
	}
	if resp.StatusCode >= 400 {
		msg := string(body)
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func (w *Watcher) k8sPut(ctx context.Context, url string, obj any) error {
	body, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("PUT %d: %s", resp.StatusCode, string(b))
	}
	return nil
}

func (w *Watcher) k8sPost(ctx context.Context, url string, obj any) error {
	body, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+w.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("POST %d: %s", resp.StatusCode, string(b))
	}
	return nil
}
