package configuration

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v3"
)

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %q: %w", path, err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.HTTPSListen == "" {
		c.HTTPSListen = ":443"
	}
	if c.HTTPListen == "" {
		c.HTTPListen = ":80"
	}
	if c.DNS.Listen == "" {
		c.DNS.Listen = "127.0.0.1:53"
	}
	if c.DNS.DirectDoHServer == "" {
		c.DNS.DirectDoHServer = "https://dns.alidns.com/dns-query"
	}
	if len(c.DNS.DirectBootstrapAddresses) == 0 && c.DNS.DirectDoHServer == "https://dns.alidns.com/dns-query" {
		c.DNS.DirectBootstrapAddresses = []string{"223.5.5.5", "223.6.6.6"}
	}
	if c.Routing.Mode == "" {
		c.Routing.Mode = "rule"
	}
	if c.Routing.RuleListURL == "" {
		c.Routing.RuleListURL = "https://testingcf.jsdelivr.net/gh/gfwlist/gfwlist/gfwlist.txt"
	}
	if c.Routing.RuleListCache == "" {
		c.Routing.RuleListCache = "gfwlist.cache"
	}
}
