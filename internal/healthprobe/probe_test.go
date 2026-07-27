package healthprobe

import "testing"

func TestRequested(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want bool
	}{
		{"no args", nil, false},
		{"single dash", []string{"-healthcheck"}, true},
		{"double dash", []string{"--healthcheck"}, true},
		{"among others", []string{"-v", "--healthcheck"}, true},
		{"unrelated", []string{"-serve"}, false},
		// A substring match would turn this into a probe and the service would
		// never start.
		{"not a substring match", []string{"-healthcheck-interval"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Requested(tc.args); got != tc.want {
				t.Errorf("Requested(%v) = %v, want %v", tc.args, got, tc.want)
			}
		})
	}
}

func TestURLFor(t *testing.T) {
	cases := []struct {
		name     string
		addr     string
		fallback string
		want     string
	}{
		{"port only", ":9091", "9091", "http://127.0.0.1:9091/healthz"},
		{"host and port", "0.0.0.0:9093", "9091", "http://127.0.0.1:9093/healthz"},
		{"empty falls back", "", "9091", "http://127.0.0.1:9091/healthz"},
		// A trailing colon carries no port, so the fallback has to win rather
		// than producing http://127.0.0.1:/healthz.
		{"trailing colon falls back", "0.0.0.0:", "9091", "http://127.0.0.1:9091/healthz"},
		{"ipv6 loopback", "[::1]:9095", "9091", "http://127.0.0.1:9095/healthz"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := URLFor(tc.addr, tc.fallback); got != tc.want {
				t.Errorf("URLFor(%q, %q) = %q, want %q", tc.addr, tc.fallback, got, tc.want)
			}
		})
	}
}
