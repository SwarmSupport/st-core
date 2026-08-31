package speedtest

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
	"strconv"
	"strings"
	"sync"
	"time"

	"st-core/internal/configuration"
)

const minimumUsefulDownload = 64 * 1024

var defaultProfiles = []configuration.SpeedTestProfile{
	{
		Name:     "cloudflare",
		URL:      "https://speed.cloudflare.com/__down?bytes={bytes}",
		MinBytes: minimumUsefulDownload,
	},
	{
		Name:     "fastly",
		URL:      "https://www.fastly-debug.com/speedtest",
		MinBytes: minimumUsefulDownload,
	},
	{
		Name:     "akamai",
		URL:      "https://dash.akamaized.net/akamai/test/1MBtestFile.chunk",
		MinBytes: minimumUsefulDownload,
	},
}

type profile struct {
	name     string
	url      *url.URL
	minBytes int64
}

type cacheEntry struct {
	addresses []string
	expires   time.Time
}

type inFlight struct {
	done chan struct{}
}

type Selector struct {
	disabled      bool
	downloadBytes int64
	timeout       time.Duration
	cacheTTL      time.Duration
	profiles      []profile
	dialer        *net.Dialer

	mu       sync.Mutex
	cache    map[string]cacheEntry
	inFlight map[string]*inFlight
}

type measurement struct {
	address  string
	provider string
	bytes    int64
	duration time.Duration
	index    int
	ok       bool
}

func NewSelector(cfg configuration.SpeedTestConfig) *Selector {
	selector := &Selector{
		disabled:      cfg.Disabled,
		downloadBytes: cfg.DownloadLimit(),
		timeout:       cfg.Timeout(),
		cacheTTL:      cfg.CacheTTL(),
		dialer:        &net.Dialer{Timeout: cfg.Timeout(), KeepAlive: 30 * time.Second},
		cache:         make(map[string]cacheEntry),
		inFlight:      make(map[string]*inFlight),
	}
	profiles := append([]configuration.SpeedTestProfile(nil), cfg.Profiles...)
	profiles = append(profiles, defaultProfiles...)
	for _, configured := range profiles {
		rawURL := strings.ReplaceAll(configured.URL, "{bytes}", strconv.FormatInt(selector.downloadBytes, 10))
		parsedURL, err := url.Parse(rawURL)
		if err != nil || parsedURL.Host == "" {
			continue
		}
		minBytes := configured.MinBytes
		if minBytes <= 0 {
			minBytes = min(minimumUsefulDownload, selector.downloadBytes)
		}
		selector.profiles = append(selector.profiles, profile{
			name:     configured.Name,
			url:      parsedURL,
			minBytes: minBytes,
		})
	}
	return selector
}

// Rank returns the candidate addresses ordered by measured download throughput.
// The input order is retained when no provider speed-test endpoint accepts an IP.
func (s *Selector) Rank(ctx context.Context, network string, addresses []string) []string {
	addresses = append([]string(nil), addresses...)
	if s == nil || s.disabled || len(addresses) < 2 || len(s.profiles) == 0 {
		return addresses
	}
	key := cacheKey(addresses)
	if ranked, ok := s.cached(key); ok {
		return ranked
	}

	call, owner := s.begin(key)
	if !owner {
		select {
		case <-call.done:
			if ranked, ok := s.cached(key); ok {
				return ranked
			}
		case <-ctx.Done():
		}
		return addresses
	}

	ranked := s.measure(ctx, network, addresses)
	if ctx.Err() == nil {
		s.store(key, ranked)
	}
	s.finish(key, call)
	return ranked
}

func (s *Selector) measure(ctx context.Context, network string, addresses []string) []string {
	results := make(chan measurement, len(addresses))
	for index, address := range addresses {
		go func(index int, address string) {
			result := s.measureAddress(ctx, network, address)
			result.index = index
			results <- result
		}(index, address)
	}

	measured := make([]measurement, 0, len(addresses))
	for range addresses {
		measured = append(measured, <-results)
	}
	sort.SliceStable(measured, func(i, j int) bool {
		if measured[i].ok != measured[j].ok {
			return measured[i].ok
		}
		if measured[i].ok {
			left := float64(measured[i].bytes) / measured[i].duration.Seconds()
			right := float64(measured[j].bytes) / measured[j].duration.Seconds()
			if left != right {
				return left > right
			}
		}
		return measured[i].index < measured[j].index
	})

	ranked := make([]string, 0, len(measured))
	for _, result := range measured {
		ranked = append(ranked, result.address)
		if result.ok {
			mbps := float64(result.bytes*8) / result.duration.Seconds() / 1_000_000
			log.Printf("speedtest provider=%s address=%s speed=%.2fMbps bytes=%d duration=%s", result.provider, result.address, mbps, result.bytes, result.duration.Round(time.Millisecond))
		}
	}
	if len(measured) > 0 && measured[0].ok {
		log.Printf("speedtest selected address=%s provider=%s cache_ttl=%s", measured[0].address, measured[0].provider, s.cacheTTL)
	}
	return ranked
}

func (s *Selector) measureAddress(ctx context.Context, network, address string) measurement {
	result := measurement{address: address}
	probeContext, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan measurement, len(s.profiles))
	for _, candidateProfile := range s.profiles {
		go func(candidateProfile profile) {
			bytesRead, duration, err := s.download(probeContext, network, address, candidateProfile)
			results <- measurement{
				address:  address,
				provider: candidateProfile.name,
				bytes:    bytesRead,
				duration: duration,
				ok:       err == nil,
			}
		}(candidateProfile)
	}
	for range s.profiles {
		candidate := <-results
		if candidate.ok {
			cancel()
			return candidate
		}
	}
	return result
}

func (s *Selector) download(ctx context.Context, network, address string, candidateProfile profile) (int64, time.Duration, error) {
	if _, _, err := net.SplitHostPort(address); err != nil {
		return 0, 0, fmt.Errorf("invalid candidate address %q: %w", address, err)
	}
	requestContext, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	transport := &http.Transport{
		Proxy:             nil,
		ForceAttemptHTTP2: true,
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return s.dialer.DialContext(ctx, network, address)
		},
		TLSHandshakeTimeout: s.timeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirectDisabled
		},
	}
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, candidateProfile.url.String(), nil)
	if err != nil {
		return 0, 0, err
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-cache")
	request.Header.Set("Range", fmt.Sprintf("bytes=0-%d", s.downloadBytes-1))

	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return 0, time.Since(started), err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return 0, time.Since(started), fmt.Errorf("speed-test endpoint returned %s", response.Status)
	}
	bytesRead, err := io.Copy(io.Discard, io.LimitReader(response.Body, s.downloadBytes))
	duration := time.Since(started)
	if err != nil {
		return bytesRead, duration, err
	}
	if bytesRead < candidateProfile.minBytes {
		return bytesRead, duration, fmt.Errorf("speed-test response too small: got %d bytes, need %d", bytesRead, candidateProfile.minBytes)
	}
	return bytesRead, duration, nil
}

var errRedirectDisabled = errors.New("speed-test redirects are disabled")

func cacheKey(addresses []string) string {
	sorted := append([]string(nil), addresses...)
	sort.Strings(sorted)
	return strings.Join(sorted, "\x00")
}

func (s *Selector) cached(key string) ([]string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.cache[key]
	if !ok || time.Now().After(entry.expires) {
		delete(s.cache, key)
		return nil, false
	}
	return append([]string(nil), entry.addresses...), true
}

func (s *Selector) store(key string, addresses []string) {
	s.mu.Lock()
	s.cache[key] = cacheEntry{
		addresses: append([]string(nil), addresses...),
		expires:   time.Now().Add(s.cacheTTL),
	}
	s.mu.Unlock()
}

func (s *Selector) begin(key string) (*inFlight, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if call := s.inFlight[key]; call != nil {
		return call, false
	}
	call := &inFlight{done: make(chan struct{})}
	s.inFlight[key] = call
	return call, true
}

func (s *Selector) finish(key string, call *inFlight) {
	s.mu.Lock()
	delete(s.inFlight, key)
	close(call.done)
	s.mu.Unlock()
}
