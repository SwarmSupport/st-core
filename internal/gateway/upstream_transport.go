package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"st-core/internal/configuration"
	"st-core/internal/loadbalancer"
	"st-core/internal/speedtest"
)

type DomainResolver interface {
	Resolve(context.Context, string) ([]net.IP, error)
}

type originDialer struct {
	route    configuration.Route
	resolver DomainResolver
	dialer   *net.Dialer
	balancer *loadbalancer.AddressBalancer
}

func BuildTransport(route configuration.Route, resolver DomainResolver, selectors ...*speedtest.Selector) *http.Transport {
	tcpDialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	origin := &originDialer{route: route, resolver: resolver, dialer: tcpDialer}
	origin.balancer = loadbalancer.NewAddressBalancer(
		route.Upstream.Endpoints(),
		tcpDialer.DialContext,
		loadbalancer.DefaultProbeTimeout,
		loadbalancer.DefaultProbeInterval,
	)
	if len(selectors) > 0 {
		origin.balancer.SetRanker(selectors[0])
	}
	return &http.Transport{
		DialContext:           origin.dialTCP,
		DialTLSContext:        origin.dialTLS,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          512,
		MaxIdleConnsPerHost:   64,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
}

func (d *originDialer) dialTCP(ctx context.Context, network, _ string) (net.Conn, error) {
	if err := d.refreshAddresses(ctx); err != nil && len(d.balancer.Candidates(ctx, network)) == 0 {
		return nil, err
	}
	return d.balancer.DialContext(ctx, network)
}

func (d *originDialer) dialTLS(ctx context.Context, network, _ string) (net.Conn, error) {
	if err := d.refreshAddresses(ctx); err != nil && len(d.balancer.Candidates(ctx, network)) == 0 {
		return nil, err
	}
	addresses := d.balancer.Candidates(ctx, network)
	if len(addresses) == 0 {
		return nil, fmt.Errorf("origin %s has no addresses", d.route.Upstream.Host)
	}

	var dialErrors []error
	for _, address := range addresses {
		conn, err := d.handshake(ctx, network, address, true)
		if err == nil {
			return conn, nil
		}
		dialErrors = append(dialErrors, fmt.Errorf("%s with SNI: %w", address, err))
		if ctx.Err() != nil {
			break
		}

		conn, err = d.handshake(ctx, network, address, false)
		if err == nil {
			return conn, nil
		}
		dialErrors = append(dialErrors, fmt.Errorf("%s without SNI: %w", address, err))
		d.balancer.MarkFailure(address)
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("connect to origin %s: %w", d.route.Upstream.Host, errors.Join(dialErrors...))
}

func (d *originDialer) handshake(ctx context.Context, network, address string, sendSNI bool) (net.Conn, error) {
	rawConnection, err := d.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	tlsConnection := tls.Client(rawConnection, originTLSConfig(d.route.Upstream.Host, sendSNI))
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := tlsConnection.HandshakeContext(handshakeCtx); err != nil {
		rawConnection.Close()
		return nil, err
	}
	return tlsConnection, nil
}

func (d *originDialer) refreshAddresses(ctx context.Context) error {
	addresses := append([]string(nil), d.route.Upstream.Endpoints()...)
	resolved, err := d.resolver.Resolve(ctx, d.route.Upstream.Host)
	if err != nil && len(addresses) == 0 {
		return err
	}
	seen := make(map[string]struct{}, len(addresses)+len(resolved))
	for _, address := range addresses {
		seen[address] = struct{}{}
	}
	for _, address := range resolved {
		endpoint := net.JoinHostPort(address.String(), d.route.Upstream.OriginPort())
		if _, exists := seen[endpoint]; exists {
			continue
		}
		seen[endpoint] = struct{}{}
		addresses = append(addresses, endpoint)
	}
	d.balancer.Update(addresses)
	return err
}

func originTLSConfig(host string, sendSNI bool) *tls.Config {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if sendSNI {
		return &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("origin returned no certificate")
			}
			intermediates := x509.NewCertPool()
			for _, certificate := range state.PeerCertificates[1:] {
				intermediates.AddCert(certificate)
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
				DNSName:       host,
				Intermediates: intermediates,
			})
			return err
		},
	}
}
