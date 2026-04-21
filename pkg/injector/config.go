package injector

import "os"

// SidecarConfig defines the nullfield sidecar container template
// used for injection.
type SidecarConfig struct {
	Image           string
	ImagePullPolicy string
	ListenPort      int
	AdminPort       int

	DefaultUpstreamPort    int
	DefaultPolicyConfigMap string
	DefaultRegistryConfigMap string

	ResourceRequests ResourceSpec
	ResourceLimits   ResourceSpec
}

type ResourceSpec struct {
	CPU    string
	Memory string
}

func DefaultSidecarConfig() *SidecarConfig {
	return &SidecarConfig{
		Image:           envOr("NULLFIELD_INJECTOR_IMAGE", "ghcr.io/babywyrm/nullfield:latest"),
		ImagePullPolicy: envOr("NULLFIELD_INJECTOR_PULL_POLICY", "IfNotPresent"),
		ListenPort:      9090,
		AdminPort:       9091,

		DefaultUpstreamPort:      0,
		DefaultPolicyConfigMap:   envOr("NULLFIELD_INJECTOR_DEFAULT_POLICY_CM", ""),
		DefaultRegistryConfigMap: envOr("NULLFIELD_INJECTOR_DEFAULT_REGISTRY_CM", ""),

		ResourceRequests: ResourceSpec{CPU: "50m", Memory: "64Mi"},
		ResourceLimits:   ResourceSpec{CPU: "200m", Memory: "128Mi"},
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
