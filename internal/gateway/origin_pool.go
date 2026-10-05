package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"st-core/internal/configuration"
)

const maxOriginListSize = 256 << 10

type originRule struct {
	listName string
	targets  []string
}

type wildcardOrigin struct {
	suffix string
	rule   originRule
}

type OriginPool struct {
	lists              map[string]originList
	exact              map[string]originRule
	wildcards          []wildcardOrigin
	resolver           DomainResolver
	insecureSkipVerify bool
}

type originListResult struct {
	name string
	url  string
	list originList
	err  error
}

type originList struct {
	addresses []net.IP
	prefixes  []netip.Prefix
}

func LoadOriginPool(ctx context.Context, resolver DomainResolver, cfg configuration.OriginConfig) (*OriginPool, error) {
	pool := &OriginPool{
		lists:              make(map[string]originList),
		exact:              make(map[string]originRule),
		resolver:           resolver,
		insecureSkipVerify: cfg.InsecureSkipVerify,
	}
	referencedLists := make(map[string]struct{})
	for rawPattern, source := range cfg.Domains {
		pattern := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rawPattern), "."))
		scalar := strings.TrimSpace(source.List)
		rule := originRule{}
		if _, exists := cfg.Lists[scalar]; scalar != "" && exists {
			rule.listName = scalar
			referencedLists[scalar] = struct{}{}
		} else if scalar != "" {
			rule.targets = []string{scalar}
		} else {
			rule.targets = append([]string(nil), source.Addresses...)
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
			list := parseIPList(data)
			if err == nil && len(list.addresses) == 0 && len(list.prefixes) == 0 {
				err = errors.New("list contained no IP addresses or CIDRs")
			}
			results <- originListResult{name: name, url: rawURL, list: list, err: err}
		}(name, rawURL)
	}

	var loadErrors []error
	for range referencedLists {
		result := <-results
		if result.err != nil {
			loadErrors = append(loadErrors, fmt.Errorf("%s: %w", result.name, result.err))
			continue
		}
		pool.lists[result.name] = result.list
		log.Printf("origin list=%s addresses=%d prefixes=%d source=%s", result.name, len(result.list.addresses), len(result.list.prefixes), result.url)
	}
	return pool, errors.Join(loadErrors...)
}

func (p *OriginPool) Endpoints(ctx context.Context, host, port string) (string, []string, error) {
	if p == nil {
		return "", nil, nil
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
		return "", nil, nil
	}
	source := "custom"
	var addresses []net.IP
	var resolveErrors []error
	if rule.listName != "" {
		list := p.lists[rule.listName]
		addresses = append(addresses, list.addresses...)
		source = rule.listName
		if len(list.prefixes) > 0 {
			if p.resolver == nil {
				resolveErrors = append(resolveErrors, fmt.Errorf("resolve origin %s: resolver is nil", host))
			} else {
				resolved, err := p.resolver.Resolve(ctx, host)
				if err != nil {
					resolveErrors = append(resolveErrors, fmt.Errorf("resolve origin %s: %w", host, err))
				} else {
					for _, address := range resolved {
						parsed, ok := netip.AddrFromSlice(address)
						if !ok {
							continue
						}
						parsed = parsed.Unmap()
						for _, prefix := range list.prefixes {
							if prefix.Contains(parsed) {
								addresses = append(addresses, address)
								break
							}
						}
					}
				}
			}
		}
	} else {
		for _, rawTarget := range rule.targets {
			target := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(rawTarget), "."))
			if address := net.ParseIP(target); address != nil {
				addresses = append(addresses, address)
				continue
			}
			if p.resolver == nil {
				resolveErrors = append(resolveErrors, fmt.Errorf("resolve custom origin %s: resolver is nil", target))
				continue
			}
			resolved, err := p.resolver.Resolve(ctx, target)
			if err != nil {
				resolveErrors = append(resolveErrors, fmt.Errorf("resolve custom origin %s: %w", target, err))
				continue
			}
			if len(resolved) == 0 {
				resolveErrors = append(resolveErrors, fmt.Errorf("resolve custom origin %s: no addresses returned", target))
			}
			addresses = append(addresses, resolved...)
		}
	}
	endpoints := make([]string, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		if address == nil {
			continue
		}
		endpoint := net.JoinHostPort(address.String(), port)
		if _, exists := seen[endpoint]; exists {
			continue
		}
		seen[endpoint] = struct{}{}
		endpoints = append(endpoints, endpoint)
	}
	return source, endpoints, errors.Join(resolveErrors...)
}

func parseIPList(data []byte) originList {
	seen := make(map[string]struct{})
	var list originList
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if prefix, err := netip.ParsePrefix(line); err == nil {
			list.prefixes = append(list.prefixes, prefix.Masked())
			continue
		}
		address := net.ParseIP(line)
		if address == nil {
			continue
		}
		normalized := address.String()
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		list.addresses = append(list.addresses, address)
	}
	return list
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
