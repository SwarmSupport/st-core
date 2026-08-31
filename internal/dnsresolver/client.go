package dnsresolver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const defaultCacheTTL = 5 * time.Minute

type cacheEntry struct {
	addresses []net.IP
	expires   time.Time
}

type Resolver struct {
	endpoint string
	client   *http.Client
	cacheTTL time.Duration
	mu       sync.RWMutex
	cache    map[string]cacheEntry
}

func New(endpoint string, configuredBootstrap []string) (*Resolver, error) {
	parsedEndpoint, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse DoH endpoint: %w", err)
	}
	endpointHost := parsedEndpoint.Hostname()
	bootstrap := make([]net.IP, 0, len(configuredBootstrap))
	for _, rawAddress := range configuredBootstrap {
		if address := net.ParseIP(rawAddress); address != nil {
			bootstrap = append(bootstrap, address)
		}
	}
	if address := net.ParseIP(endpointHost); address != nil {
		bootstrap = []net.IP{address}
	}
	if len(bootstrap) == 0 {
		lookupContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		bootstrap, err = net.DefaultResolver.LookupIP(lookupContext, "ip", endpointHost)
		if err != nil {
			return nil, fmt.Errorf("bootstrap DoH server %s: %w", endpointHost, err)
		}
	}
	tcpDialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, target string) (net.Conn, error) {
		targetHost, targetPort, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		if !strings.EqualFold(targetHost, endpointHost) {
			return nil, fmt.Errorf("DoH redirect to unexpected host %s", targetHost)
		}
		var dialErrors []error
		for _, address := range bootstrap {
			connection, err := tcpDialer.DialContext(ctx, network, net.JoinHostPort(address.String(), targetPort))
			if err == nil {
				return connection, nil
			}
			dialErrors = append(dialErrors, err)
		}
		return nil, errors.Join(dialErrors...)
	}
	resolver := &Resolver{
		endpoint: endpoint,
		client: &http.Client{
			Timeout:   10 * time.Second,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("DoH redirects are disabled")
			},
		},
		cacheTTL: defaultCacheTTL,
		cache:    make(map[string]cacheEntry),
	}
	return resolver, nil
}

func (r *Resolver) Resolve(ctx context.Context, domain string) ([]net.IP, error) {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return nil, errors.New("domain is empty")
	}
	if address := net.ParseIP(domain); address != nil {
		return []net.IP{address}, nil
	}
	if addresses, ok := r.cached(domain); ok {
		return addresses, nil
	}

	type result struct {
		addresses []string
		err       error
	}
	results := make(chan result, 2)
	for _, queryType := range []uint16{dns.TypeA, dns.TypeAAAA} {
		go func(queryType uint16) {
			addresses, err := queryDoH(ctx, r.client, r.endpoint, domain, queryType)
			results <- result{addresses: addresses, err: err}
		}(queryType)
	}

	var queryErrors []error
	var addresses []net.IP
	seen := make(map[string]struct{})
	for range 2 {
		result := <-results
		if result.err != nil {
			queryErrors = append(queryErrors, result.err)
			continue
		}
		for _, rawAddress := range result.addresses {
			address := net.ParseIP(rawAddress)
			if address == nil {
				continue
			}
			key := address.String()
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			addresses = append(addresses, address)
		}
	}
	if len(addresses) == 0 {
		if len(queryErrors) > 0 {
			return nil, fmt.Errorf("resolve %s through DoH: %w", domain, errors.Join(queryErrors...))
		}
		return nil, fmt.Errorf("resolve %s through DoH: no addresses returned", domain)
	}
	r.store(domain, addresses)
	return cloneIPs(addresses), nil
}

func (r *Resolver) Exchange(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	if request == nil {
		return nil, errors.New("DNS request is nil")
	}
	return exchangeDoH(ctx, r.client, r.endpoint, request)
}

func (r *Resolver) cached(domain string) ([]net.IP, bool) {
	r.mu.RLock()
	entry, ok := r.cache[domain]
	r.mu.RUnlock()
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return cloneIPs(entry.addresses), true
}

func (r *Resolver) store(domain string, addresses []net.IP) {
	r.mu.Lock()
	r.cache[domain] = cacheEntry{addresses: cloneIPs(addresses), expires: time.Now().Add(r.cacheTTL)}
	r.mu.Unlock()
}

func cloneIPs(addresses []net.IP) []net.IP {
	cloned := make([]net.IP, len(addresses))
	for index, address := range addresses {
		cloned[index] = append(net.IP(nil), address...)
	}
	return cloned
}

func QueryDoH(ctx context.Context, endpoint, domain string, qtype uint16) []string {
	addresses, err := queryDoH(ctx, http.DefaultClient, endpoint, domain, qtype)
	if err != nil {
		return nil
	}
	return addresses
}

func queryDoH(ctx context.Context, client *http.Client, endpoint, domain string, qtype uint16) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true
	result, err := exchangeDoH(ctx, client, endpoint, msg)
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, answer := range result.Answer {
		switch rr := answer.(type) {
		case *dns.A:
			ips = append(ips, rr.A.String())
		case *dns.AAAA:
			ips = append(ips, rr.AAAA.String())
		}
	}
	return ips, nil
}

func exchangeDoH(ctx context.Context, client *http.Client, endpoint string, msg *dns.Msg) (*dns.Msg, error) {
	payload, err := msg.Pack()
	if err != nil {
		return nil, fmt.Errorf("pack DNS query: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("create DoH request: %w", err)
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send DoH request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned %s", resp.Status)
	}
	result := new(dns.Msg)
	responsePayload, err := io.ReadAll(io.LimitReader(resp.Body, dns.MaxMsgSize))
	if err != nil {
		return nil, fmt.Errorf("read DoH response: %w", err)
	}
	if err := result.Unpack(responsePayload); err != nil {
		return nil, fmt.Errorf("decode DoH response: %w", err)
	}
	return result, nil
}
