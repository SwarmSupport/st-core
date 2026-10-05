package speedtest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"st-core/internal/configuration"
)

// Website categories were checked with DoH and IPinfo during development.
// DNS is resolved again on every start; a site is only tested against its own
// current addresses, and a CDN address must also belong to its published list.
type Website struct {
	Name     string
	Host     string
	Path     string
	Provider string
	List     string
}

var startupWebsites = []Website{
	{Name: "GitHub", Host: "github.com", Provider: "microsoft"},
	{Name: "Hugging Face", Host: "huggingface.co", Provider: "cloudfront", List: "cft-iplist"},
	{Name: "Amazon", Host: "www.amazon.com", Provider: "cloudfront", List: "cft-iplist"},
	{Name: "AO3", Host: "archiveofourown.org", Provider: "cloudflare", List: "cf-iplist"},
	{Name: "Cloudflare", Host: "www.cloudflare.com", Provider: "cloudflare", List: "cf-iplist"},
	{Name: "Fastly", Host: "www.fastly.com", Provider: "fastly", List: "fl-iplist"},
	{Name: "Python", Host: "www.python.org", Provider: "fastly", List: "fl-iplist"},
	{Name: "Akamai", Host: "dash.akamaized.net", Path: "/akamai/test/1MBtestFile.chunk", Provider: "akamai", List: "aka-iplist"},
}

// StartupResult is a verified HTTPS result. The HTTP client checks the normal
// certificate chain and hostname while its TCP connection is pinned to Address.
type StartupResult struct {
	Website  string
	Host     string
	Provider string
	Address  string
	Bytes    int64
	Duration time.Duration
}

func (r StartupResult) Mbps() float64 {
	if r.Duration <= 0 {
		return 0
	}
	return float64(r.Bytes*8) / r.Duration.Seconds() / 1_000_000
}

// SelectAtStartup runs once per Core start. Failures are logged and never
// prevent listeners from starting. No selected address is uploaded here.
func SelectAtStartup(ctx context.Context, cfg configuration.SpeedTestConfig, resolver Resolver, listDirectory string) []StartupResult {
	if cfg.Disabled || resolver == nil {
		return nil
	}
	groups := make(map[string][]Website)
	for _, site := range startupWebsites {
		groups[site.Provider] = append(groups[site.Provider], site)
	}
	var selected []StartupResult
	for provider, websites := range groups {
		site := websites[rand.IntN(len(websites))]
		resolveCtx, cancel := context.WithTimeout(ctx, cfg.Timeout())
		ips, err := resolver.Resolve(resolveCtx, site.Host)
		cancel()
		if err != nil {
			log.Printf("startup IP selection provider=%s website=%s DNS error: %v", provider, site.Host, err)
			continue
		}
		var ranges []netip.Prefix
		if site.List != "" {
			ranges, err = readPrefixes(filepath.Join(listDirectory, site.List+".txt"))
			if err != nil {
				log.Printf("startup IP selection provider=%s list error: %v", provider, err)
				continue
			}
		}
		var best *StartupResult
		for _, address := range candidateAddresses(ips, ranges, site.List != "") {
			result, err := probeWebsite(ctx, cfg, site, address)
			if err != nil {
				log.Printf("startup IP selection website=%s address=%s rejected: %v", site.Host, address, err)
				continue
			}
			if result.Mbps() < cfg.MinimumMbps() {
				log.Printf("startup IP selection website=%s address=%s rejected: %.2fMbps below %.2fMbps", site.Host, address, result.Mbps(), cfg.MinimumMbps())
				continue
			}
			if best == nil || result.Mbps() > best.Mbps() {
				best = &result
			}
		}
		if best != nil {
			selected = append(selected, *best)
			log.Printf("startup IP selected website=%s provider=%s address=%s speed=%.2fMbps bytes=%d duration=%s", best.Host, best.Provider, best.Address, best.Mbps(), best.Bytes, best.Duration.Round(time.Millisecond))
		} else {
			log.Printf("startup IP selection website=%s provider=%s: no verified candidate", site.Host, provider)
		}
	}
	return selected
}

func readPrefixes(path string) ([]netip.Prefix, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var prefixes []netip.Prefix
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		if address, err := netip.ParseAddr(line); err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(address, address.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid IP range %q", path, line)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	if len(prefixes) == 0 {
		return nil, errors.New("IP list is empty")
	}
	return prefixes, nil
}

func prefixContains(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func candidateAddresses(ips []net.IP, ranges []netip.Prefix, requireList bool) []string {
	var candidates []string
	seen := make(map[string]struct{})
	for _, ip := range ips {
		address, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		address = address.Unmap()
		if requireList && !prefixContains(ranges, address) {
			continue
		}
		if _, exists := seen[address.String()]; exists {
			continue
		}
		seen[address.String()] = struct{}{}
		candidates = append(candidates, address.String())
	}
	return candidates
}

func probeWebsite(ctx context.Context, cfg configuration.SpeedTestConfig, site Website, ip string) (StartupResult, error) {
	address := net.JoinHostPort(ip, "443")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: cfg.Timeout()}).DialContext(ctx, network, address)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: cfg.Timeout(), CheckRedirect: func(*http.Request, []*http.Request) error { return errRedirectDisabled }}
	path := site.Path
	if path == "" {
		path = "/"
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+site.Host+path, nil)
	if err != nil {
		return StartupResult{}, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return StartupResult{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return StartupResult{}, fmt.Errorf("HTTP %s", response.Status)
	}
	read, err := io.Copy(io.Discard, io.LimitReader(response.Body, cfg.DownloadLimit()))
	if err != nil {
		return StartupResult{}, err
	}
	if read == 0 {
		return StartupResult{}, errors.New("empty response")
	}
	return StartupResult{Website: site.Name, Host: site.Host, Provider: site.Provider, Address: ip, Bytes: read, Duration: time.Since(started)}, nil
}
