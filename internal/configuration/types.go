package configuration

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

type Config struct {
	HTTPSListen string          `yaml:"https_listen"`
	HTTPListen  string          `yaml:"http_listen"`
	CA          CAConfig        `yaml:"ca"`
	DNS         DNSConfig       `yaml:"dns"`
	Proxy       ProxyConfig     `yaml:"proxy"`
	Routing     RoutingConfig   `yaml:"routing"`
	Origin      OriginConfig    `yaml:"origin"`
	SpeedTest   SpeedTestConfig `yaml:"speedtest"`
	Routes      []Route         `yaml:"routes"`
}

type CAConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type DNSConfig struct {
	DoHServer                string   `yaml:"doh_server"`
	BootstrapAddresses       []string `yaml:"bootstrap_addresses"`
	DirectDoHServer          string   `yaml:"direct_doh_server"`
	DirectBootstrapAddresses []string `yaml:"direct_bootstrap_addresses"`
	Listen                   string   `yaml:"listen"`
	LocalIPv4                string   `yaml:"local_ipv4"`
	LocalIPv6                string   `yaml:"local_ipv6"`
}

type ProxyConfig struct {
	HTTPListen   string `yaml:"http_listen"`
	SOCKS5Listen string `yaml:"socks5_listen"`
}

type RoutingConfig struct {
	Mode          string   `yaml:"mode"`
	RuleListURL   string   `yaml:"rule_list_url"`
	RuleListCache string   `yaml:"rule_list_cache"`
	RefreshHours  int      `yaml:"refresh_hours"`
	Rules         []string `yaml:"rules"`
}

type OriginConfig struct {
	Lists              map[string]string       `yaml:"lists"`
	Domains            map[string]OriginSource `yaml:"domains"`
	InsecureSkipVerify bool                    `yaml:"insecure_skip_verify"`
}

type OriginSource struct {
	List      string
	Addresses []string
}

func (s *OriginSource) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		return node.Decode(&s.List)
	case yaml.SequenceNode:
		return node.Decode(&s.Addresses)
	default:
		return fmt.Errorf("must be a named origin list, domain name, or an array of IP addresses or domain names")
	}
}

func (c RoutingConfig) RefreshInterval() time.Duration {
	if c.RefreshHours <= 0 {
		return 24 * time.Hour
	}
	return time.Duration(c.RefreshHours) * time.Hour
}

type SpeedTestConfig struct {
	Disabled        bool               `yaml:"disabled"`
	DownloadBytes   int64              `yaml:"download_bytes"`
	MinMbps         float64            `yaml:"min_mbps"`
	TimeoutSeconds  int                `yaml:"timeout_seconds"`
	CacheTTLSeconds int                `yaml:"cache_ttl_seconds"`
	Profiles        []SpeedTestProfile `yaml:"profiles"`
}

func (c SpeedTestConfig) MinimumMbps() float64 {
	if c.MinMbps <= 0 {
		return 1
	}
	return c.MinMbps
}

type SpeedTestProfile struct {
	Name     string `yaml:"name"`
	URL      string `yaml:"url"`
	MinBytes int64  `yaml:"min_bytes"`
}

func (c SpeedTestConfig) DownloadLimit() int64 {
	if c.DownloadBytes <= 0 {
		return 1_000_000
	}
	return c.DownloadBytes
}

func (c SpeedTestConfig) Timeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return 8 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

func (c SpeedTestConfig) CacheTTL() time.Duration {
	if c.CacheTTLSeconds <= 0 {
		return 30 * time.Minute
	}
	return time.Duration(c.CacheTTLSeconds) * time.Second
}

type Route struct {
	Host     string         `yaml:"host"`
	Upstream UpstreamConfig `yaml:"upstream"`
}

type UpstreamConfig struct {
	Address   string   `yaml:"address"`
	Addresses []string `yaml:"addresses"`
	Host      string   `yaml:"host"`
	Port      int      `yaml:"port"`
}

func (u UpstreamConfig) Endpoints() []string {
	endpoints := make([]string, 0, len(u.Addresses)+1)
	seen := make(map[string]struct{}, len(u.Addresses)+1)
	add := func(address string) {
		address = strings.TrimSpace(address)
		if address == "" {
			return
		}
		if _, exists := seen[address]; exists {
			return
		}
		seen[address] = struct{}{}
		endpoints = append(endpoints, address)
	}
	add(u.Address)
	for _, address := range u.Addresses {
		add(address)
	}
	return endpoints
}

func (u UpstreamConfig) OriginPort() string {
	if u.Port == 0 {
		return "443"
	}
	return strconv.Itoa(u.Port)
}
