package speedtest

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"st-core/internal/configuration"
)

type fakeResolver map[string][]net.IP

func (r fakeResolver) Resolve(_ context.Context, host string) ([]net.IP, error) {
	if addresses, ok := r[host]; ok {
		return addresses, nil
	}
	return nil, errors.New("not configured")
}

func TestResolveTargetsKeepsProviderAndURLPort(t *testing.T) {
	selector := NewSelector(configuration.SpeedTestConfig{Profiles: []configuration.SpeedTestProfile{{
		Name: "example", URL: "http://download.example:8080/file", MinBytes: 1,
	}}})
	targets, err := selector.ResolveTargets(context.Background(), fakeResolver{
		"download.example": {net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.2")},
	})
	if err == nil { // Built-in providers were intentionally absent from the fake resolver.
		t.Fatal("expected partial resolution error")
	}
	if len(targets) != 2 || targets[0].Address != "192.0.2.1:8080" || targets[1].Address != "192.0.2.2:8080" {
		t.Fatalf("unexpected targets: %+v", targets)
	}
	for _, target := range targets {
		if target.Provider != "example" || target.profile.url.Hostname() != "download.example" {
			t.Fatalf("provider URL association lost: %+v", target)
		}
	}
}

func TestResolvedTargetUsesItsProviderURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "download.example:8080" || r.URL.Path != "/file" {
			t.Errorf("unexpected request: host=%s path=%s", r.Host, r.URL.Path)
		}
		_, _ = w.Write([]byte("payload"))
	}))
	defer server.Close()
	serverURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	selector := NewSelector(configuration.SpeedTestConfig{DownloadBytes: 7, Profiles: []configuration.SpeedTestProfile{{
		Name: "example", URL: "http://download.example:8080/file", MinBytes: 1,
	}}})
	profile := selector.profiles[0]
	target := Target{Address: serverURL.Host, Provider: "example", profile: profile}
	results := selector.TestTargets(context.Background(), "tcp", []Target{target})
	if len(results) != 1 || !results[0].OK || results[0].Provider != "example" || results[0].Bytes != 7 {
		t.Fatalf("unexpected result: %+v", results)
	}
	if strings.Contains(results[0].Address, "download.example") {
		t.Fatal("test did not pin the connection to the resolved address")
	}
}
