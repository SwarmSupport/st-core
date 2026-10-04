package routing

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"st-core/internal/configuration"
)

const maxRuleListSize = 4 << 20

var gfwListMirrors = []string{
	"https://testingcf.jsdelivr.net/gh/gfwlist/gfwlist/gfwlist.txt",
	"https://cdn.jsdelivr.net/gh/gfwlist/gfwlist/gfwlist.txt",
	"https://fastly.jsdelivr.net/gh/gfwlist/gfwlist/gfwlist.txt",
	"https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt",
}

type DomainResolver interface {
	Resolve(context.Context, string) ([]net.IP, error)
}

type Policy struct {
	mode    string
	include map[string]struct{}
	exclude map[string]struct{}
}

func Load(ctx context.Context, cfg configuration.RoutingConfig, resolver DomainResolver) (*Policy, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	if mode == "" {
		mode = "rule"
	}
	policy := &Policy{
		mode:    mode,
		include: make(map[string]struct{}),
		exclude: make(map[string]struct{}),
	}
	if mode != "rule" {
		return policy, nil
	}

	payload, source, err := loadRuleList(ctx, cfg, resolver)
	if err != nil {
		return nil, err
	}
	decoded, err := decodeRuleList(payload)
	if err != nil {
		return nil, fmt.Errorf("decode routing rule list from %s: %w", source, err)
	}
	policy.addRules(string(decoded))
	policy.addRules(strings.Join(cfg.Rules, "\n"))
	if len(policy.include) == 0 {
		return nil, fmt.Errorf("routing rule list from %s contained no domain rules", source)
	}
	log.Printf("routing mode=rule rules=%d exceptions=%d source=%s", len(policy.include), len(policy.exclude), source)
	return policy, nil
}

func (p *Policy) Mode() string {
	if p == nil || p.mode == "" {
		return "global"
	}
	return p.mode
}

func (p *Policy) ShouldHandle(host string) bool {
	if p == nil {
		return true
	}
	switch p.mode {
	case "global":
		return true
	case "bypass":
		return false
	}
	host = normalizeHost(host)
	if host == "" || matchesSuffix(p.exclude, host) {
		return false
	}
	return matchesSuffix(p.include, host)
}

func (p *Policy) addRules(text string) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "!") || strings.HasPrefix(line, "[") {
			continue
		}
		exception := strings.HasPrefix(line, "@@")
		line = strings.TrimPrefix(line, "@@")
		for _, domain := range domainsFromRule(line) {
			if exception {
				p.exclude[domain] = struct{}{}
			} else {
				p.include[domain] = struct{}{}
			}
		}
	}
}

func domainsFromRule(rule string) []string {
	if options := strings.IndexByte(rule, '$'); options >= 0 {
		rule = rule[:options]
	}
	rule = strings.ReplaceAll(rule, `\.`, ".")
	rule = strings.ReplaceAll(rule, `\/`, "/")
	rule = strings.ToLower(rule)

	seen := make(map[string]struct{})
	var domains []string
	add := func(candidate string) {
		candidate = normalizeHost(candidate)
		if candidate == "" {
			return
		}
		if net.ParseIP(candidate) == nil && !strings.Contains(candidate, ".") {
			return
		}
		if _, exists := seen[candidate]; exists {
			return
		}
		seen[candidate] = struct{}{}
		domains = append(domains, candidate)
	}

	trimmed := strings.Trim(rule, "|")
	trimmed = strings.TrimPrefix(trimmed, "||")
	if parsed, err := url.Parse(trimmed); err == nil && parsed.Hostname() != "" {
		add(parsed.Hostname())
	}
	for _, candidate := range domainPattern.FindAllString(trimmed, -1) {
		add(candidate)
	}
	for _, candidate := range ipv4Pattern.FindAllString(trimmed, -1) {
		add(candidate)
	}
	sort.Strings(domains)
	return domains
}

var (
	domainPattern = regexp.MustCompile(`[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)+`)
	ipv4Pattern   = regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`)
)

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	host = strings.ToLower(host)
	return host
}

func matchesSuffix(rules map[string]struct{}, host string) bool {
	for candidate := host; candidate != ""; {
		if _, exists := rules[candidate]; exists {
			return true
		}
		dot := strings.IndexByte(candidate, '.')
		if dot < 0 {
			return false
		}
		candidate = candidate[dot+1:]
	}
	return false
}

func loadRuleList(ctx context.Context, cfg configuration.RoutingConfig, resolver DomainResolver) ([]byte, string, error) {
	cached, cacheInfo, cacheErr := readCache(cfg.RuleListCache)
	cacheValid := cacheErr == nil && validateRuleList(cached) == nil
	if cacheErr == nil && !cacheValid {
		cacheErr = errors.New("cached rule list is invalid")
	}
	if cacheValid && time.Since(cacheInfo.ModTime()) < cfg.RefreshInterval() {
		return cached, cfg.RuleListCache, nil
	}

	downloaded, source, err := downloadRuleLists(ctx, ruleListURLs(cfg.RuleListURL), resolver)
	if err == nil {
		if cacheErr := writeCache(cfg.RuleListCache, downloaded); cacheErr != nil {
			log.Printf("routing rule cache path=%s error=%v", cfg.RuleListCache, cacheErr)
		}
		return downloaded, source, nil
	}
	if cacheValid {
		log.Printf("routing rule refresh url=%s error=%v; using stale cache", cfg.RuleListURL, err)
		return cached, cfg.RuleListCache, nil
	}
	return nil, "", fmt.Errorf("load routing rules: download %s: %w; cache %s: %v", cfg.RuleListURL, err, cfg.RuleListCache, cacheErr)
}

func ruleListURLs(configured string) []string {
	urls := []string{configured}
	knownGFWListURL := false
	for _, mirror := range gfwListMirrors {
		if configured == mirror {
			knownGFWListURL = true
			break
		}
	}
	if !knownGFWListURL {
		return urls
	}
	for _, mirror := range gfwListMirrors {
		if mirror != configured {
			urls = append(urls, mirror)
		}
	}
	return urls
}

type ruleListDownload struct {
	data   []byte
	source string
	err    error
}

func downloadRuleLists(ctx context.Context, urls []string, resolver DomainResolver) ([]byte, string, error) {
	if len(urls) == 0 {
		return nil, "", errors.New("no rule-list URLs configured")
	}
	downloadContext, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan ruleListDownload, len(urls))
	for _, rawURL := range urls {
		go func() {
			data, err := downloadRuleList(downloadContext, rawURL, resolver)
			if err == nil {
				err = validateRuleList(data)
			}
			results <- ruleListDownload{data: data, source: rawURL, err: err}
		}()
	}

	errorsByURL := make([]error, 0, len(urls))
	for range urls {
		result := <-results
		if result.err == nil {
			return result.data, result.source, nil
		}
		errorsByURL = append(errorsByURL, fmt.Errorf("%s: %w", result.source, result.err))
	}
	return nil, "", errors.Join(errorsByURL...)
}

func validateRuleList(data []byte) error {
	decoded, err := decodeRuleList(data)
	if err != nil {
		return err
	}
	policy := &Policy{include: make(map[string]struct{}), exclude: make(map[string]struct{})}
	policy.addRules(string(decoded))
	if len(policy.include) == 0 {
		return errors.New("rule list contained no domain rules")
	}
	return nil
}

func readCache(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	data, err := os.ReadFile(path)
	return data, info, err
}

func writeCache(path string, data []byte) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".gfwlist-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o644); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func downloadRuleList(ctx context.Context, rawURL string, resolver DomainResolver) ([]byte, error) {
	if resolver == nil {
		return nil, errors.New("rule-list resolver is nil")
	}
	endpoint, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
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
			return nil, fmt.Errorf("rule-list redirect to unexpected host %s", targetHost)
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
			return errors.New("rule-list redirects are disabled")
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
	data, err := io.ReadAll(io.LimitReader(response.Body, maxRuleListSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxRuleListSize {
		return nil, fmt.Errorf("rule list exceeds %d bytes", maxRuleListSize)
	}
	return data, nil
}

func decodeRuleList(data []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if bytes.HasPrefix(trimmed, []byte("[AutoProxy")) || bytes.HasPrefix(trimmed, []byte("!")) || bytes.HasPrefix(trimmed, []byte("||")) {
		return trimmed, nil
	}
	compact := make([]byte, 0, len(trimmed))
	for _, value := range trimmed {
		if value != '\r' && value != '\n' && value != ' ' && value != '\t' {
			compact = append(compact, value)
		}
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(compact)))
	count, err := base64.StdEncoding.Decode(decoded, compact)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(decoded[:count]), nil
}
