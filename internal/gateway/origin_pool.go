package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"st-core/internal/configuration"
)

const maxOriginListSize = 256 << 10

type originRule struct {
	listName  string
	addresses []net.IP
}

type wildcardOrigin struct {
	suffix string
	rule   originRule
}

type OriginPool struct {
	lists              map[string][]net.IP
	exact              map[string]originRule
	wildcards          []wildcardOrigin
	insecureSkipVerify bool
}

type originListResult struct {
	name      string
	url       string
	addresses []net.IP
	err       error
}

func LoadOriginPool(ctx context.Context, resolver DomainResolver, cfg configuration.OriginConfig) (*OriginPool, error) {
	pool := &OriginPool{
		lists:              make(map[string][]net.IP),
		exact:              make(map[string]originRule),
		insecureSkipVerify: cfg.InsecureSkipVerify,
	}
	referencedLists := make(map[string]struct{})
	for rawPattern, source := range cfg.Domains {
		pattern := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rawPattern), "."))
		rule := originRule{listName: strings.TrimSpace(source.List)}
		if rule.listName != "" {
			referencedLists[rule.listName] = struct{}{}
		} else {
			rule.addresses = parseOriginAddresses(source.Addresses)
		}
		if strings.HasPrefix(pattern, "*.") {
			pool.wildcards = append(pool.wildcards, wildcardOrigin{
				suffix: strings.TrimPrefix(pattern, "*."),
				rule:   rule,
			})
			continue
		}
		pool.exact[pattern] = rule
	}
	sort.SliceStable(pool.wildcards, func(i, j int) bool {
		return len(pool.wildcards[i].suffix) > len(pool.wildcards[j].suffix)
	})
	if len(referencedLists) == 0 {
		return pool, nil
	}

	results := make(chan originListResult, len(referencedLists))
	for name := range referencedLists {
		rawURL := cfg.Lists[name]
		go func(name, rawURL string) {
			data, err := downloadOriginList(ctx, rawURL, resolver)
			addresses := parseIPList(data)
			if err == nil && len(addresses) == 0 {
				err = errors.New("list contained no IP addresses")
			}
			results <- originListResult{name: name, url: rawURL, addresses: addresses, err: err}
		}(name, rawURL)
	}

	var loadErrors []error
	for range referencedLists {
		result := <-results
		if result.err != nil {
			loadErrors = append(loadErrors, fmt.Errorf("%s: %w", result.name, result.err))
			continue
		}
		pool.lists[result.name] = result.addresses
		log.Printf("origin list=%s addresses=%d source=%s", result.name, len(result.addresses), result.url)
	}
	return pool, errors.Join(loadErrors...)
}

func (p *OriginPool) Endpoints(host, port string) (string, []string) {
	if p == nil {
		return "", nil
	}
	host = normalizeRequestHost(host)
	rule, matched := p.exact[host]
	if !matched {
		for _, wildcard := range p.wildcards {
			if host != wildcard.suffix && strings.HasSuffix(host, "."+wildcard.suffix) {
				rule = wildcard.rule
				matched = true
				break
			}
		}
	}
	if !matched {
		return "", nil
	}
	addresses := rule.addresses
	source := "custom"
	if rule.listName != "" {
		addresses = p.lists[rule.listName]
		source = rule.listName
	}
	endpoints := make([]string, 0, len(addresses))
	for _, address := range addresses {
		endpoints = append(endpoints, net.JoinHostPort(address.String(), port))
	}
	return source, endpoints
}

func parseOriginAddresses(rawAddresses []string) []net.IP {
	seen := make(map[string]struct{}, len(rawAddresses))
	addresses := make([]net.IP, 0, len(rawAddresses))
	for _, rawAddress := range rawAddresses {
		address := net.ParseIP(strings.TrimSpace(rawAddress))
		if address == nil {
			continue
		}
		normalized := address.String()
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		addresses = append(addresses, address)
	}
	return addresses
}

func parseIPList(data []byte) []net.IP {
	seen := make(map[string]struct{})
	var addresses []net.IP
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		address := net.ParseIP(line)
		if address == nil {
			continue
		}
		normalized := address.String()
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		addresses = append(addresses, address)
	}
	return addresses
}

func downloadOriginList(ctx context.Context, rawURL string, resolver DomainResolver) ([]byte, error) {
	if resolver == nil {
		return nil, errors.New("origin-list resolver is nil")
	}
	endpoint, err := url.Parse(rawURL)
	if err != nil || endpoint.Scheme != "https" || endpoint.Hostname() == "" {
		return nil, fmt.Errorf("invalid origin list URL %q", rawURL)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, target string) (net.Conn, error) {
		targetHost, targetPort, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(targetHost, endpoint.Hostname()) {
			return nil, fmt.Errorf("origin list redirected to unexpected host %s", targetHost)
		}
		addresses, err := resolver.Resolve(ctx, targetHost)
		if err != nil {
			return nil, err
		}
		var dialErrors []error
		for _, address := range addresses {
			connection, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), targetPort))
			if err == nil {
				return connection, nil
			}
			dialErrors = append(dialErrors, err)
		}
		return nil, errors.Join(dialErrors...)
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("origin list redirects are disabled")
		},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("server returned %s", response.Status)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxOriginListSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxOriginListSize {
		return nil, fmt.Errorf("list exceeds %d bytes", maxOriginListSize)
	}
	return data, nil
}
