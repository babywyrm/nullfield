package identity

import (
	"net/http"
	"testing"
)

func TestHTTPHeadersReadsCaseInsensitively(t *testing.T) {
	r, err := http.NewRequest(http.MethodPost, "/mcp", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	r.Header.Set("Authorization", "Bearer abc")

	h := HTTPHeaders{Request: r}
	for _, name := range []string{"authorization", "Authorization", "AUTHORIZATION"} {
		if got := h.Get(name); got != "Bearer abc" {
			t.Errorf("Get(%q) = %q, want Bearer abc", name, got)
		}
	}
}

func TestHTTPHeadersOnANilRequestReturnsEmpty(t *testing.T) {
	// Returning empty beats panicking inside a request path.
	if got := (HTTPHeaders{}).Get("authorization"); got != "" {
		t.Errorf("Get on a nil request = %q, want empty", got)
	}
}

func TestMapHeadersReadsCaseInsensitively(t *testing.T) {
	// Envoy lowercases header names in CheckRequest, but a caller asking for the
	// canonical form must still get an answer.
	h := MapHeaders{"authorization": "Bearer abc"}
	for _, name := range []string{"authorization", "Authorization", "AUTHORIZATION"} {
		if got := h.Get(name); got != "Bearer abc" {
			t.Errorf("Get(%q) = %q, want Bearer abc", name, got)
		}
	}
}

func TestMapHeadersReturnsEmptyForAnAbsentHeader(t *testing.T) {
	if got := (MapHeaders{}).Get("authorization"); got != "" {
		t.Errorf("Get on an empty map = %q, want empty", got)
	}
}

func TestBothImplementationsSatisfyHeaders(t *testing.T) {
	var _ Headers = HTTPHeaders{}
	var _ Headers = MapHeaders{}
}
