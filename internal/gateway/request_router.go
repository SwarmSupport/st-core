package gateway

import (
	"net"
	"net/http"
	"strings"
	"sync"

	"st-core/internal/configuration"
)

type Router struct {
	mu       sync.RWMutex
	sites    map[string]*Site
	resolver DomainResolver
	policy   TrafficPolicy
	origins  *OriginPool
}

type TrafficPolicy interface {
	ShouldHandle(string) bool
}

func NewRouter(cfg *configuration.Config, resolver DomainResolver, policy TrafficPolicy, origins *OriginPool) *Router {
	router := &Router{
		sites:    make(map[string]*Site),
		resolver: resolver,
		policy:   policy,
		origins:  origins,
	}
	for _, route := range cfg.Routes {
		host := normalizeRequestHost(route.Host)
		route.Host = host
		site := BuildSite(route, resolver, origins)
		router.sites[host] = site
	}
	return router
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	host := normalizeRequestHost(req.Host)
	if host == "" {
		http.Error(w, "host is required", http.StatusBadRequest)
		return
	}
	if r.policy != nil && !r.policy.ShouldHandle(host) {
		http.Error(w, "domain is bypassed by routing policy", http.StatusMisdirectedRequest)
		return
	}
	site := r.siteForHost(host)
	site.Proxy.ServeHTTP(w, req)
}

func (r *Router) siteForHost(host string) *Site {
	r.mu.RLock()
	site := r.sites[host]
	r.mu.RUnlock()
	if site != nil {
		return site
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if site = r.sites[host]; site != nil {
		return site
	}
	route := configuration.Route{
		Host: host,
		Upstream: configuration.UpstreamConfig{
			Host: host,
			Port: 443,
		},
	}
	site = BuildSite(route, r.resolver, r.origins)
	r.sites[host] = site
	return site
}

func BuildSite(route configuration.Route, resolver DomainResolver, origins *OriginPool) *Site {
	transport := BuildTransport(route, resolver, origins)
	reverseProxy := BuildReverseProxy(route, transport)
	return &Site{Host: route.Host, Config: route, Proxy: reverseProxy}
}

func normalizeRequestHost(host string) string {
	host = strings.TrimSpace(host)
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}
