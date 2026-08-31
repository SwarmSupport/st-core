package loadbalancer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	DefaultProbeTimeout  = 2 * time.Second
	DefaultProbeInterval = 5 * time.Minute
)

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

type AddressRanker interface {
	Rank(context.Context, string, []string) []string
}

type AddressBalancer struct {
	mu              sync.RWMutex
	addresses       []string
	lastProbe       time.Time
	probing         bool
	dial            dialContextFunc
	probeTimeout    time.Duration
	refreshInterval time.Duration
	ranker          AddressRanker
}

func (b *AddressBalancer) SetRanker(ranker AddressRanker) {
	b.mu.Lock()
	b.ranker = ranker
	b.mu.Unlock()
}

func NewAddressBalancer(
	addresses []string,
	dial dialContextFunc,
	probeTimeout time.Duration,
	refreshInterval time.Duration,
) *AddressBalancer {
	return &AddressBalancer{
		addresses:       append([]string(nil), addresses...),
		dial:            dial,
		probeTimeout:    probeTimeout,
		refreshInterval: refreshInterval,
	}
}

func (b *AddressBalancer) DialContext(ctx context.Context, network string) (net.Conn, error) {
	addresses := b.Candidates(ctx, network)
	if len(addresses) == 0 {
		return nil, errors.New("no upstream addresses configured")
	}

	dialErrors := make([]error, 0, len(addresses))
	for _, address := range addresses {
		conn, err := b.dial(ctx, network, address)
		if err == nil {
			return conn, nil
		}
		dialErrors = append(dialErrors, fmt.Errorf("dial %s: %w", address, err))
		b.MarkFailure(address)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.Join(dialErrors...)
}

func (b *AddressBalancer) Candidates(ctx context.Context, network string) []string {
	addresses := b.snapshot()
	if len(addresses) > 1 {
		b.refreshRanking(ctx, network)
		addresses = b.snapshot()
	}
	return addresses
}

func (b *AddressBalancer) Update(addresses []string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	wanted := make(map[string]struct{}, len(addresses))
	for _, address := range addresses {
		wanted[address] = struct{}{}
	}
	updated := make([]string, 0, len(addresses))
	seen := make(map[string]struct{}, len(addresses))
	for _, address := range b.addresses {
		if _, keep := wanted[address]; keep {
			updated = append(updated, address)
			seen[address] = struct{}{}
		}
	}
	for _, address := range addresses {
		if _, exists := seen[address]; !exists {
			updated = append(updated, address)
			seen[address] = struct{}{}
		}
	}
	if slicesEqual(updated, b.addresses) {
		return
	}
	b.addresses = updated
	b.lastProbe = time.Time{}
}

func (b *AddressBalancer) refreshRanking(ctx context.Context, network string) {
	b.mu.Lock()
	due := b.lastProbe.IsZero() || time.Since(b.lastProbe) >= b.refreshInterval
	if !due || b.probing {
		b.mu.Unlock()
		return
	}
	initialProbe := b.lastProbe.IsZero()
	b.probing = true
	b.mu.Unlock()

	if initialProbe {
		b.probe(ctx, network)
		return
	}
	go b.probe(context.Background(), network)
}

type probeResult struct {
	address string
	latency time.Duration
	index   int
	healthy bool
}

func (b *AddressBalancer) probe(ctx context.Context, network string) {
	addresses := b.snapshot()
	results := make(chan probeResult, len(addresses))
	for index, address := range addresses {
		go func(index int, address string) {
			probeCtx, cancel := context.WithTimeout(ctx, b.probeTimeout)
			defer cancel()
			started := time.Now()
			conn, err := b.dial(probeCtx, network, address)
			latency := time.Since(started)
			if err == nil {
				conn.Close()
			}
			results <- probeResult{address: address, latency: latency, index: index, healthy: err == nil}
		}(index, address)
	}

	ranked := make([]probeResult, 0, len(addresses))
	for range addresses {
		ranked = append(ranked, <-results)
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].healthy != ranked[j].healthy {
			return ranked[i].healthy
		}
		if ranked[i].healthy && ranked[i].latency != ranked[j].latency {
			return ranked[i].latency < ranked[j].latency
		}
		return ranked[i].index < ranked[j].index
	})

	healthy := make([]string, 0, len(ranked))
	unhealthy := make([]string, 0, len(ranked))
	for _, result := range ranked {
		if result.healthy {
			healthy = append(healthy, result.address)
		} else {
			unhealthy = append(unhealthy, result.address)
		}
	}
	if ranker := b.addressRanker(); ranker != nil && len(healthy) > 1 && ctx.Err() == nil {
		healthy = validRanking(healthy, ranker.Rank(ctx, network, healthy))
	}
	addresses = append(healthy, unhealthy...)
	b.mu.Lock()
	b.addresses = addresses
	if ctx.Err() == nil {
		b.lastProbe = time.Now()
	} else {
		b.lastProbe = time.Time{}
	}
	b.probing = false
	b.mu.Unlock()
}

func (b *AddressBalancer) addressRanker() AddressRanker {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.ranker
}

func (b *AddressBalancer) snapshot() []string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return append([]string(nil), b.addresses...)
}

func (b *AddressBalancer) MarkFailure(address string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for index, candidate := range b.addresses {
		if candidate != address {
			continue
		}
		copy(b.addresses[index:], b.addresses[index+1:])
		b.addresses[len(b.addresses)-1] = address
		return
	}
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func validRanking(original, ranked []string) []string {
	if len(original) != len(ranked) {
		return original
	}
	wanted := make(map[string]int, len(original))
	for _, address := range original {
		wanted[address]++
	}
	for _, address := range ranked {
		if wanted[address] == 0 {
			return original
		}
		wanted[address]--
	}
	return ranked
}
