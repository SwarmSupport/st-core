package configuration

import (
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestOriginDomainTargets(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr bool
	}{
		{"scalar domain", "example.com: origin.example.net", false},
		{"mixed addresses", "example.com: [1.1.1.1, origin.example.net]", false},
		{"named list", "example.com: edge-list", false},
		{"invalid scalar", "example.com: bad_host", true},
		{"invalid array target", "example.com: [1.1.1.1, bad_host]", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				DNS:     DNSConfig{DoHServer: "https://dns.example.net/dns-query", DirectDoHServer: "https://direct.example.net/dns-query"},
				Routing: RoutingConfig{Mode: "bypass"},
				Origin:  OriginConfig{Lists: map[string]string{"edge-list": "https://example.net/list"}},
			}
			if err := yaml.Unmarshal([]byte("domains:\n  "+tt.yaml+"\n"), &cfg.Origin); err != nil {
				t.Fatal(err)
			}
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, want error %v", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "origin domain") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
