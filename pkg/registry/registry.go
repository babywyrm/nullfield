package registry

import (
	"os"
	"sync"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
	"gopkg.in/yaml.v3"
)

// Registry holds the set of approved tools. Thread-safe for hot-reload.
type Registry struct {
	mu    sync.RWMutex
	tools map[string]v1alpha1.ToolRegistryEntry
}

func New() *Registry {
	return &Registry{
		tools: make(map[string]v1alpha1.ToolRegistryEntry),
	}
}

func (r *Registry) IsRegistered(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.tools[name]
	return ok
}

func (r *Registry) Get(name string) (v1alpha1.ToolRegistryEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

func (r *Registry) All() []v1alpha1.ToolRegistryEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]v1alpha1.ToolRegistryEntry, 0, len(r.tools))
	for _, t := range r.tools {
		out = append(out, t)
	}
	return out
}

// LoadFromFile reads a ToolRegistry YAML file and replaces the current set.
func (r *Registry) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	var reg v1alpha1.ToolRegistry
	if err := yaml.Unmarshal(data, &reg); err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools = make(map[string]v1alpha1.ToolRegistryEntry, len(reg.Tools))
	for _, t := range reg.Tools {
		r.tools[t.Name] = t
	}
	return nil
}

// Register adds or replaces a single tool entry.
func (r *Registry) Register(entry v1alpha1.ToolRegistryEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[entry.Name] = entry
}
