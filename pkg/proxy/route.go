package proxy

import (
	"fmt"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/babywyrm/nullfield/pkg/policy"
	"github.com/babywyrm/nullfield/pkg/registry"
)

// Route maps a set of tool names to an upstream MCP server with its
// own policy engine and tool registry.
type Route struct {
	Name       string
	Upstream   *httputil.ReverseProxy
	UpstreamAddr string
	ToolPrefix string
	ToolNames  []string
	Engine     policy.Engine
	Registry   *registry.Registry
}

// RouteConfig is the YAML-serializable configuration for a single route.
type RouteConfig struct {
	Name         string   `json:"name" yaml:"name"`
	Upstream     string   `json:"upstream" yaml:"upstream"`
	ToolPrefix   string   `json:"toolPrefix,omitempty" yaml:"toolPrefix,omitempty"`
	ToolNames    []string `json:"toolNames,omitempty" yaml:"toolNames,omitempty"`
	PolicyFile   string   `json:"policyFile,omitempty" yaml:"policyFile,omitempty"`
	RegistryFile string   `json:"registryFile,omitempty" yaml:"registryFile,omitempty"`
}

// GatewayConfig is the top-level config for gateway mode.
type GatewayConfig struct {
	Gateway struct {
		Routes []RouteConfig `json:"routes" yaml:"routes"`
	} `json:"gateway" yaml:"gateway"`
}

// Router resolves a tool name to a Route. Thread-safe after construction.
type Router struct {
	routes     []*Route
	prefixMap  map[string]*Route
	exactMap   map[string]*Route
}

func NewRouter(routes []*Route) *Router {
	r := &Router{
		routes:    routes,
		prefixMap: make(map[string]*Route),
		exactMap:  make(map[string]*Route),
	}
	for _, route := range routes {
		if route.ToolPrefix != "" {
			r.prefixMap[route.ToolPrefix] = route
		}
		for _, name := range route.ToolNames {
			r.exactMap[name] = route
		}
	}
	return r
}

// Resolve finds the route for a given tool name. Exact match takes
// priority over prefix match. Returns nil if no route matches.
func (r *Router) Resolve(toolName string) *Route {
	if route, ok := r.exactMap[toolName]; ok {
		return route
	}

	for prefix, route := range r.prefixMap {
		if strings.HasPrefix(toolName, prefix) {
			return route
		}
	}

	return nil
}

// Routes returns all configured routes.
func (r *Router) Routes() []*Route {
	return r.routes
}

// AllRegisteredTools returns a combined set of all tool names across
// all route registries.
func (r *Router) AllRegisteredTools() []string {
	var tools []string
	seen := make(map[string]bool)
	for _, route := range r.routes {
		for _, entry := range route.Registry.All() {
			if !seen[entry.Name] {
				tools = append(tools, entry.Name)
				seen[entry.Name] = true
			}
		}
	}
	return tools
}

// BuildRoute creates a Route from a RouteConfig, loading its policy
// and registry from files.
func BuildRoute(cfg RouteConfig) (*Route, error) {
	if cfg.Upstream == "" {
		return nil, fmt.Errorf("route %q: upstream is required", cfg.Name)
	}

	upstream, err := url.Parse("http://" + cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("route %q: invalid upstream %q: %w", cfg.Name, cfg.Upstream, err)
	}

	reg := registry.New()
	if cfg.RegistryFile != "" {
		if err := reg.LoadFromFile(cfg.RegistryFile); err != nil {
			return nil, fmt.Errorf("route %q: registry load failed: %w", cfg.Name, err)
		}
	}

	var engine policy.Engine
	if cfg.PolicyFile != "" {
		spec, err := policy.LoadSpecFromFile(cfg.PolicyFile)
		if err != nil {
			return nil, fmt.Errorf("route %q: policy load failed: %w", cfg.Name, err)
		}
		engine = policy.NewRuleEngine(spec.Rules)
	} else {
		engine = policy.NewRuleEngine(nil)
	}

	return &Route{
		Name:         cfg.Name,
		Upstream:     httputil.NewSingleHostReverseProxy(upstream),
		UpstreamAddr: upstream.Host,
		ToolPrefix:   cfg.ToolPrefix,
		ToolNames:    cfg.ToolNames,
		Engine:       engine,
		Registry:     reg,
	}, nil
}
