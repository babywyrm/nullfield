package registry

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	v1alpha1 "github.com/babywyrm/nullfield/api/v1alpha1"
)

// DriftType classifies a change detected during reconciliation.
type DriftType string

const (
	DriftAdded   DriftType = "ADDED"
	DriftRemoved DriftType = "REMOVED"
	DriftChanged DriftType = "CHANGED"
)

// DriftEntry describes a single tool that drifted from the registry.
type DriftEntry struct {
	ToolName     string    `json:"toolName"`
	Type         DriftType `json:"type"`
	PreviousHash string    `json:"previousHash,omitempty"`
	CurrentHash  string    `json:"currentHash,omitempty"`
	DetectedAt   time.Time `json:"detectedAt"`
}

// IsRugPull returns true if this drift represents a tool definition change
// (the most dangerous form — a tool that was trusted changed its behavior).
func (d DriftEntry) IsRugPull() bool {
	return d.Type == DriftChanged
}

// DriftReport summarizes all differences between the registry and live tools.
type DriftReport struct {
	Timestamp time.Time    `json:"timestamp"`
	Added     []DriftEntry `json:"added,omitempty"`
	Removed   []DriftEntry `json:"removed,omitempty"`
	Changed   []DriftEntry `json:"changed,omitempty"`
}

// HasDrift returns true if any tool was added, removed, or changed.
func (r DriftReport) HasDrift() bool {
	return len(r.Added) > 0 || len(r.Removed) > 0 || len(r.Changed) > 0
}

// HasRugPull returns true if any registered tool changed its definition.
func (r DriftReport) HasRugPull() bool {
	return len(r.Changed) > 0
}

// RugPulls returns only the changed (rug-pulled) entries.
func (r DriftReport) RugPulls() []DriftEntry {
	return r.Changed
}

// Snapshot captures the current tool set with computed hashes.
type Snapshot struct {
	Timestamp time.Time                          `json:"timestamp"`
	Tools     map[string]v1alpha1.ToolRegistryEntry `json:"tools"`
	Hashes    map[string]string                  `json:"hashes"`
}

// LifecycleTracker monitors tool registration changes over time.
type LifecycleTracker struct {
	mu        sync.RWMutex
	snapshots []Snapshot
	maxHist   int
}

// NewLifecycleTracker creates a tracker that retains up to maxHistory snapshots.
func NewLifecycleTracker(maxHistory int) *LifecycleTracker {
	if maxHistory < 1 {
		maxHistory = 10
	}
	return &LifecycleTracker{maxHist: maxHistory}
}

// Snapshot captures the current state of a registry for later reconciliation.
func (lt *LifecycleTracker) Snapshot(r *Registry) Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snap := Snapshot{
		Timestamp: time.Now().UTC(),
		Tools:     make(map[string]v1alpha1.ToolRegistryEntry, len(r.tools)),
		Hashes:    make(map[string]string, len(r.tools)),
	}
	for name, entry := range r.tools {
		snap.Tools[name] = entry
		snap.Hashes[name] = ComputeHash(entry)
	}

	lt.mu.Lock()
	lt.snapshots = append(lt.snapshots, snap)
	if len(lt.snapshots) > lt.maxHist {
		lt.snapshots = lt.snapshots[len(lt.snapshots)-lt.maxHist:]
	}
	lt.mu.Unlock()

	return snap
}

// Reconcile compares a set of live tools against the registry and returns
// a drift report. Live tools are typically fetched from upstream tools/list.
func Reconcile(registered *Registry, liveTools []v1alpha1.ToolRegistryEntry) DriftReport {
	now := time.Now().UTC()
	report := DriftReport{Timestamp: now}

	registered.mu.RLock()
	regCopy := make(map[string]v1alpha1.ToolRegistryEntry, len(registered.tools))
	for k, v := range registered.tools {
		regCopy[k] = v
	}
	registered.mu.RUnlock()

	liveMap := make(map[string]v1alpha1.ToolRegistryEntry, len(liveTools))
	for _, t := range liveTools {
		liveMap[t.Name] = t
	}

	for name, live := range liveMap {
		reg, exists := regCopy[name]
		if !exists {
			report.Added = append(report.Added, DriftEntry{
				ToolName:    name,
				Type:        DriftAdded,
				CurrentHash: ComputeHash(live),
				DetectedAt:  now,
			})
			continue
		}
		regHash := computeHashWithOverride(reg)
		liveHash := ComputeHash(live)
		if regHash != liveHash {
			report.Changed = append(report.Changed, DriftEntry{
				ToolName:     name,
				Type:         DriftChanged,
				PreviousHash: regHash,
				CurrentHash:  liveHash,
				DetectedAt:   now,
			})
		}
	}

	for name := range regCopy {
		if _, exists := liveMap[name]; !exists {
			report.Removed = append(report.Removed, DriftEntry{
				ToolName:     name,
				Type:         DriftRemoved,
				PreviousHash: computeHashWithOverride(regCopy[name]),
				DetectedAt:   now,
			})
		}
	}

	sort.Slice(report.Added, func(i, j int) bool { return report.Added[i].ToolName < report.Added[j].ToolName })
	sort.Slice(report.Removed, func(i, j int) bool { return report.Removed[i].ToolName < report.Removed[j].ToolName })
	sort.Slice(report.Changed, func(i, j int) bool { return report.Changed[i].ToolName < report.Changed[j].ToolName })

	return report
}

// History returns the last N snapshots (most recent last).
func (lt *LifecycleTracker) History() []Snapshot {
	lt.mu.RLock()
	defer lt.mu.RUnlock()
	out := make([]Snapshot, len(lt.snapshots))
	copy(out, lt.snapshots)
	return out
}

// ComputeHash produces a deterministic SHA-256 hash of a tool entry's
// defining fields (name, description, scopes). This hash is compared
// across reconciliation cycles to detect rug-pulls.
func ComputeHash(entry v1alpha1.ToolRegistryEntry) string {
	if entry.SignatureHash != "" {
		return entry.SignatureHash
	}
	return computeCanonical(entry)
}

func computeHashWithOverride(entry v1alpha1.ToolRegistryEntry) string {
	if entry.SignatureHash != "" {
		return entry.SignatureHash
	}
	return computeCanonical(entry)
}

func computeCanonical(entry v1alpha1.ToolRegistryEntry) string {
	canonical := struct {
		Name          string   `json:"name"`
		Description   string   `json:"description"`
		AllowedScopes []string `json:"allowedScopes"`
	}{
		Name:          entry.Name,
		Description:   entry.Description,
		AllowedScopes: entry.AllowedScopes,
	}
	b, _ := json.Marshal(canonical)
	h := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%x", h)
}
