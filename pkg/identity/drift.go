package identity

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// DriftDetector tracks identity claims per session and detects changes.
// If scopes or groups change between requests in the same session
// without re-authentication, it may indicate manipulation.
type DriftDetector struct {
	mu       sync.Mutex
	sessions map[string]*claimsSnapshot
}

type claimsSnapshot struct {
	scopes string
	groups string
}

func NewDriftDetector() *DriftDetector {
	return &DriftDetector{
		sessions: make(map[string]*claimsSnapshot),
	}
}

// Check compares the current identity's claims against the stored snapshot
// for this session. Returns an error describing what drifted.
// First call for a session stores the baseline — no error.
func (d *DriftDetector) Check(id *Identity) error {
	if id == nil || id.SessionID == "" {
		return nil
	}

	currentScopes := normalizeSlice(id.Scopes)
	currentGroups := normalizeSlice(id.Groups)

	d.mu.Lock()
	defer d.mu.Unlock()

	snap, ok := d.sessions[id.SessionID]
	if !ok {
		d.sessions[id.SessionID] = &claimsSnapshot{
			scopes: currentScopes,
			groups: currentGroups,
		}
		return nil
	}

	var drifts []string

	if snap.scopes != currentScopes {
		drifts = append(drifts, fmt.Sprintf("scopes changed: %q → %q", snap.scopes, currentScopes))
	}
	if snap.groups != currentGroups {
		drifts = append(drifts, fmt.Sprintf("groups changed: %q → %q", snap.groups, currentGroups))
	}

	if len(drifts) > 0 {
		return fmt.Errorf("claims drift detected: %s", strings.Join(drifts, "; "))
	}
	return nil
}

// Clear removes the snapshot for a session.
func (d *DriftDetector) Clear(sessionID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.sessions, sessionID)
}

// Sweep removes all sessions (call periodically).
func (d *DriftDetector) Sweep() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sessions = make(map[string]*claimsSnapshot)
}

func normalizeSlice(s []string) string {
	if len(s) == 0 {
		return ""
	}
	sorted := make([]string, len(s))
	copy(sorted, s)
	sort.Strings(sorted)
	return strings.Join(sorted, ",")
}
