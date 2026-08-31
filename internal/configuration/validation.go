package configuration

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func (c *Config) Validate() error {
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	routingMode := strings.ToLower(strings.TrimSpace(c.Routing.Mode))
	if routingMode == "" {
		routingMode = "rule"
	}
	switch routingMode {
	case "global", "rule", "bypass":
	default:
		return fmt.Errorf("routing.mode must be one of global, rule, or bypass")
	}
	if routingMode != "bypass" {
		if c.HTTPSListen == "" {
			return fmt.Errorf("https_listen is required")
		}
		if c.CA.Cert == "" {
			return fmt.Errorf("ca.cert is required")
		}
		if c.CA.Key == "" {
			return fmt.Errorf("ca.key is required")
		}
	}
	if c.DNS.DoHServer == "" {
		return fmt.Errorf("dns.doh_server is required")
	}
	dohURL, err := url.Parse(c.DNS.DoHServer)
	if err != nil || (dohURL.Scheme != "https" && dohURL.Scheme != "http") || dohURL.Host == "" {
		return fmt.Errorf("dns.doh_server must be a valid HTTP(S) URL")
	}
	for name, address := range map[string]string{
		"https_listen":        c.HTTPSListen,
		"http_listen":         c.HTTPListen,
		"dns.listen":          c.DNS.Listen,
		"proxy.http_listen":   c.Proxy.HTTPListen,
		"proxy.socks5_listen": c.Proxy.SOCKS5Listen,
	} {
		if address == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(address); err != nil {
			return fmt.Errorf("%s must use host:port format: %w", name, err)
		}
		if err := validateIPv4ListenAddress(name, address); err != nil {
			return err
		}
	}
	if strings.TrimSpace(c.DNS.LocalIPv4) != "" {
		return fmt.Errorf("dns.local_ipv4 is not supported")
	}
	if strings.TrimSpace(c.DNS.LocalIPv6) != "" {
		return fmt.Errorf("dns.local_ipv6 is not supported")
	}
	for _, address := range c.DNS.BootstrapAddresses {
		if net.ParseIP(address) == nil {
			return fmt.Errorf("dns.bootstrap_addresses must contain only IP addresses")
		}
	}
	if c.Routing.RefreshHours < 0 {
		return fmt.Errorf("routing.refresh_hours must be positive when set")
	}
	if routingMode == "rule" {
		rawRuleListURL := c.Routing.RuleListURL
		if rawRuleListURL == "" {
			rawRuleListURL = "https://testingcf.jsdelivr.net/gh/gfwlist/gfwlist/gfwlist.txt"
		}
		ruleListURL, err := url.Parse(rawRuleListURL)
		if err != nil || (ruleListURL.Scheme != "https" && ruleListURL.Scheme != "http") || ruleListURL.Host == "" {
			return fmt.Errorf("routing.rule_list_url must be a valid HTTP(S) URL in rule mode")
		}
	}
	if c.SpeedTest.DownloadBytes < 0 {
		return fmt.Errorf("speedtest.download_bytes must be positive when set")
	}
	if c.SpeedTest.TimeoutSeconds < 0 {
		return fmt.Errorf("speedtest.timeout_seconds must be positive when set")
	}
	if c.SpeedTest.CacheTTLSeconds < 0 {
		return fmt.Errorf("speedtest.cache_ttl_seconds must be positive when set")
	}
	for index, profile := range c.SpeedTest.Profiles {
		if strings.TrimSpace(profile.Name) == "" {
			return fmt.Errorf("speedtest.profiles[%d].name is required", index)
		}
		profileURL, err := url.Parse(profile.URL)
		if err != nil || (profileURL.Scheme != "https" && profileURL.Scheme != "http") || profileURL.Host == "" {
			return fmt.Errorf("speedtest profile %s: url must be a valid HTTP(S) URL", profile.Name)
		}
		if profile.MinBytes < 0 {
			return fmt.Errorf("speedtest profile %s: min_bytes must be positive when set", profile.Name)
		}
		if profile.MinBytes > c.SpeedTest.DownloadLimit() {
			return fmt.Errorf("speedtest profile %s: min_bytes must not exceed download_bytes", profile.Name)
		}
	}
	hosts := make(map[string]struct{})
	for i, route := range c.Routes {
		host := normalizeHost(route.Host)
		if host == "" {
			return fmt.Errorf("routes[%d].host is required", i)
		}
		if _, exists := hosts[host]; exists {
			return fmt.Errorf("duplicate route host: %s", host)
		}
		hosts[host] = struct{}{}
		addresses := route.Upstream.Endpoints()
		for _, address := range addresses {
			addressHost, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("route %s: invalid upstream address %q (expected host:port): %w", host, address, err)
			}
			if net.ParseIP(addressHost) == nil {
				return fmt.Errorf("route %s: upstream address %q must use an IP; domains are resolved through DoH", host, address)
			}
		}
		if strings.TrimSpace(route.Upstream.Host) == "" {
			return fmt.Errorf("route %s: upstream.host is required", host)
		}
		if route.Upstream.Port < 0 || route.Upstream.Port > 65535 {
			return fmt.Errorf("route %s: upstream.port must be between 1 and 65535 when set", host)
		}
	}
	return nil
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func validateIPv4ListenAddress(name, address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if host == "" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	if ip.To4() == nil {
		return fmt.Errorf("%s must not use an IPv6 address", name)
	}
	return nil
}
