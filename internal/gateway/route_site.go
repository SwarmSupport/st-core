package gateway

import (
	"net/http/httputil"

	"st-core/internal/configuration"
)

type Site struct {
	Host   string
	Config configuration.Route
	Proxy  *httputil.ReverseProxy
}
