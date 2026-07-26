package identity

import (
	"net/http"
	"strings"
)

// Headers abstracts the one thing token extraction actually needs, so it works
// for both inbound adapters: the HTTP proxy holds an *http.Request, while the
// ext_authz decision service holds a map Envoy built.
type Headers interface {
	Get(name string) string
}

// HTTPHeaders adapts an *http.Request.
type HTTPHeaders struct{ Request *http.Request }

// Get returns a header value, or empty if there is no request to read.
func (h HTTPHeaders) Get(name string) string {
	if h.Request == nil {
		return ""
	}
	return h.Request.Header.Get(name)
}

// MapHeaders adapts the header map from an Envoy CheckRequest.
type MapHeaders map[string]string

// Get returns a header value.
//
// Envoy lowercases header names, but callers reasonably ask for the canonical
// form. Normalising here means a lookup for "Authorization" cannot silently miss
// a header that is present.
func (m MapHeaders) Get(name string) string {
	return m[strings.ToLower(name)]
}
