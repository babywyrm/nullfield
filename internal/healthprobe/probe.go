// Package healthprobe lets a distroless container health-check itself.
//
// The runtime images are built on distroless, which carries no shell, wget, or
// curl. A Docker or Compose health check has nothing to invoke except the
// application binary itself, so the binary answers to -healthcheck by making
// the request in-process and exiting 0 or 1.
package healthprobe

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// probeTimeout bounds the whole check. A health probe that can hang is worse
// than one that fails, because an orchestrator reads a hang as neither.
const probeTimeout = 3 * time.Second

// Requested reports whether the process was invoked as a one-shot health probe
// rather than as the service.
func Requested(args []string) bool {
	for _, a := range args {
		if a == "-healthcheck" || a == "--healthcheck" {
			return true
		}
	}
	return false
}

// URLFor turns a listen address such as ":9091" or "0.0.0.0:9091" into the
// loopback URL a probe inside the same container should call. The host part is
// discarded deliberately: a service bound to 0.0.0.0 is still reached over
// loopback from inside, and a probe that dialled the advertised address would
// leave the container to check itself.
func URLFor(addr, fallbackPort string) string {
	port := fallbackPort
	if i := strings.LastIndex(addr, ":"); i >= 0 && i+1 < len(addr) {
		port = addr[i+1:]
	}
	return fmt.Sprintf("http://127.0.0.1:%s/healthz", port)
}

// Run performs the probe and exits. It never returns.
func Run(addr, fallbackPort string) {
	url := URLFor(addr, fallbackPort)

	client := &http.Client{Timeout: probeTimeout}
	resp, err := client.Get(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "healthcheck: %s: %v\n", url, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		fmt.Fprintf(os.Stderr, "healthcheck: %s returned %s\n", url, resp.Status)
		os.Exit(1)
	}
	os.Exit(0)
}
