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

	mu             sync.Mutex
	lastPolicyRV   string
	lastRegistryRV string
}

// Config for the watcher.
type Config struct {
	Namespace    string
	SyncInterval time.Duration
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
		logger: logger,
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
