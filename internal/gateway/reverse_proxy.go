package gateway

import (
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"st-core/internal/configuration"
)

func BuildReverseProxy(route configuration.Route, transport http.RoundTripper) *httputil.ReverseProxy {
	origin := net.JoinHostPort(route.Upstream.Host, route.Upstream.OriginPort())
	target := &url.URL{Scheme: "https", Host: origin}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = route.Upstream.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error host=%s origin=%s error=%v", r.Host, origin, err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
	return proxy
}
