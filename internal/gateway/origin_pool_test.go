package gateway

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"

	"st-core/internal/configuration"
)

type testOriginResolver struct {
	addresses map[string][]net.IP
	calls     []string
}

func (r *testOriginResolver) Resolve(_ context.Context, domain string) ([]net.IP, error) {
	r.calls = append(r.calls, domain)
	addresses, ok := r.addresses[domain]
	if !ok {
		return nil, errors.New("lookup failed")
	}
	return addresses, nil
}

func TestOriginPoolResolvesDomainTargetsAtConnectionTime(t *testing.T) {
	resolver := &testOriginResolver{addresses: map[string][]net.IP{
		"origin.example.net": {net.ParseIP("192.0.2.10"), net.ParseIP("192.0.2.11")},
	}}
	pool, err := LoadOriginPool(context.Background(), resolver, configuration.OriginConfig{
		Domains: map[string]configuration.OriginSource{
			"example.com":   {List: "origin.example.net"},
			"*.example.com": {Addresses: []string{"192.0.2.10", "origin.example.net"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, exact, err := pool.Endpoints(context.Background(), "example.com", "443")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"192.0.2.10:443", "192.0.2.11:443"}; !reflect.DeepEqual(exact, want) {
		t.Fatalf("exact endpoints = %v, want %v", exact, want)
	}
	_, wildcard, err := pool.Endpoints(context.Background(), "www.example.com", "8443")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"192.0.2.10:8443", "192.0.2.11:8443"}; !reflect.DeepEqual(wildcard, want) {
		t.Fatalf("wildcard endpoints = %v, want %v", wildcard, want)
	}
	resolver.addresses["origin.example.net"] = []net.IP{net.ParseIP("192.0.2.12")}
	_, updated, err := pool.Endpoints(context.Background(), "example.com", "443")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"192.0.2.12:443"}; !reflect.DeepEqual(updated, want) {
		t.Fatalf("updated endpoints = %v, want %v", updated, want)
	}
}

func TestOriginPoolFiltersCurrentDNSAnswersByCIDRList(t *testing.T) {
	resolver := &testOriginResolver{addresses: map[string][]net.IP{
		"example.com": {net.ParseIP("104.20.8.2"), net.ParseIP("203.0.113.1")},
	}}
	pool := &OriginPool{
		resolver: resolver,
		exact: map[string]originRule{
			"example.com": {listName: "provider"},
		},
		lists: map[string]originList{
			"provider": parseIPList([]byte("104.16.0.0/13\n")),
		},
	}
	_, endpoints, err := pool.Endpoints(context.Background(), "example.com", "443")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"104.20.8.2:443"}; !reflect.DeepEqual(endpoints, want) {
		t.Fatalf("endpoints = %v, want %v", endpoints, want)
	}
}
