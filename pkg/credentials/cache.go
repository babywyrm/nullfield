package credentials

import (
	"context"
	"sync"
	"time"
)

// CachedProvider wraps any Provider with a TTL cache to avoid
// hitting external secret stores on every request.
type CachedProvider struct {
	inner Provider
	ttl   time.Duration
	mu    sync.RWMutex
	cache map[string]*cacheEntry
}

type cacheEntry struct {
	value   string
	fetched time.Time
}

func NewCachedProvider(inner Provider, ttl time.Duration) *CachedProvider {
	return &CachedProvider{
		inner: inner,
		ttl:   ttl,
		cache: make(map[string]*cacheEntry),
	}
}

func (p *CachedProvider) Fetch(ctx context.Context, ref string) (string, error) {
	p.mu.RLock()
	if entry, ok := p.cache[ref]; ok && time.Since(entry.fetched) < p.ttl {
		p.mu.RUnlock()
		return entry.value, nil
	}
	p.mu.RUnlock()

	val, err := p.inner.Fetch(ctx, ref)
	if err != nil {
		return "", err
	}

	p.mu.Lock()
	p.cache[ref] = &cacheEntry{value: val, fetched: time.Now()}
	p.mu.Unlock()

	return val, nil
}

// Sweep removes expired cache entries.
func (p *CachedProvider) Sweep() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, entry := range p.cache {
		if time.Since(entry.fetched) >= p.ttl {
			delete(p.cache, k)
		}
	}
}
