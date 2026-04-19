package controller

import (
	"sync"
	"time"
)

const DefaultSidecarTTL = 5 * time.Minute

type SidecarInfo struct {
	TargetName      string    `json:"targetName"`
	TargetNamespace string    `json:"targetNamespace"`
	PodName         string    `json:"podName"`
	Version         string    `json:"version"`
	ToolCount       int32     `json:"toolCount"`
	RuleCount       int32     `json:"ruleCount"`
	RegisteredAt    time.Time `json:"registeredAt"`
	LastHeartbeat   time.Time `json:"lastHeartbeat"`
}

type SidecarRegistry struct {
	mu       sync.RWMutex
	sidecars map[string]*SidecarInfo // keyed by podName
	ttl      time.Duration
}

func NewSidecarRegistry() *SidecarRegistry {
	return &SidecarRegistry{
		sidecars: make(map[string]*SidecarInfo),
		ttl:      DefaultSidecarTTL,
	}
}

func (r *SidecarRegistry) Register(info SidecarInfo) {
	now := time.Now()
	info.RegisteredAt = now
	info.LastHeartbeat = now

	r.mu.Lock()
	r.sidecars[info.PodName] = &info
	r.mu.Unlock()
}

func (r *SidecarRegistry) Heartbeat(podName string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	s, ok := r.sidecars[podName]
	if !ok {
		return false
	}
	s.LastHeartbeat = time.Now()
	return true
}

func (r *SidecarRegistry) List() []SidecarInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]SidecarInfo, 0, len(r.sidecars))
	for _, s := range r.sidecars {
		out = append(out, *s)
	}
	return out
}

// Sweep removes sidecars that haven't sent a heartbeat within the TTL.
func (r *SidecarRegistry) Sweep() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-r.ttl)
	removed := 0
	for pod, s := range r.sidecars {
		if s.LastHeartbeat.Before(cutoff) {
			delete(r.sidecars, pod)
			removed++
		}
	}
	return removed
}
