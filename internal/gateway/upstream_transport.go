package gateway

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"st-core/internal/configuration"
	"st-core/internal/loadbalancer"
)

type DomainResolver interface {
	Resolve(context.Context, string) ([]net.IP, error)
}

type originDialer struct {
	route    configuration.Route
	resolver DomainResolver
	dialer   *net.Dialer
	balancer *loadbalancer.AddressBalancer
	origins  *OriginPool
}

func BuildTransport(route configuration.Route, resolver DomainResolver, origins *OriginPool) *http.Transport {
	tcpDialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	origin := &originDialer{route: route, resolver: resolver, dialer: tcpDialer, origins: origins}
	origin.balancer = loadbalancer.NewAddressBalancer(
		route.Upstream.Endpoints(),
		tcpDialer.DialContext,
		loadbalancer.DefaultProbeTimeout,
		loadbalancer.DefaultProbeInterval,
	)
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
	source, configured, configuredErr := d.configuredCandidates(ctx)
	var dialErrors []error
	if configuredErr != nil {
		dialErrors = append(dialErrors, configuredErr)
	}
	for _, address := range configured {
		connection, err := d.dialer.DialContext(ctx, network, address)
		if err == nil {
			logConfiguredOrigin(d.route.Upstream.Host, address, source)
			return connection, nil
		}
		dialErrors = append(dialErrors, fmt.Errorf("configured origin %s: %w", address, err))
		if ctx.Err() != nil {
			return nil, errors.Join(dialErrors...)
		}
	}
	refreshErr := d.refreshAddresses(ctx)
	if refreshErr != nil {
		dialErrors = append(dialErrors, refreshErr)
	}
	connection, err := d.balancer.DialContext(ctx, network)
	if err != nil {
		dialErrors = append(dialErrors, err)
		return nil, errors.Join(dialErrors...)
	}
	return connection, nil
}

func (d *originDialer) dialTLS(ctx context.Context, network, _ string) (net.Conn, error) {
	source, configured, configuredErr := d.configuredCandidates(ctx)
	dialErrors := make([]error, 0, len(configured))
	if configuredErr != nil {
		dialErrors = append(dialErrors, configuredErr)
	}
	for _, address := range configured {
		conn, err := d.handshake(ctx, network, address)
		if err == nil {
			logConfiguredOrigin(d.route.Upstream.Host, address, source)
			return conn, nil
		}
		dialErrors = append(dialErrors, fmt.Errorf("configured origin %s without SNI: %w", address, err))
		if ctx.Err() != nil {
			return nil, fmt.Errorf("connect to origin %s: %w", d.route.Upstream.Host, errors.Join(dialErrors...))
		}
	}

	refreshErr := d.refreshAddresses(ctx)
	if refreshErr != nil {
		dialErrors = append(dialErrors, refreshErr)
	}
	addresses := excludeAddresses(d.balancer.Candidates(ctx, network), configured)
	if len(addresses) == 0 {
		dialErrors = append(dialErrors, fmt.Errorf("origin %s has no DNS or route addresses", d.route.Upstream.Host))
		return nil, fmt.Errorf("connect to origin %s: %w", d.route.Upstream.Host, errors.Join(dialErrors...))
	}

	for _, address := range addresses {
		conn, err := d.handshake(ctx, network, address)
		if err == nil {
			return conn, nil
		}
		dialErrors = append(dialErrors, fmt.Errorf("origin %s without SNI: %w", address, err))
		d.balancer.MarkFailure(address)
		if ctx.Err() != nil {
			return nil, fmt.Errorf("connect to origin %s: %w", d.route.Upstream.Host, errors.Join(dialErrors...))
		}
	}

	return nil, fmt.Errorf("connect to origin %s: %w", d.route.Upstream.Host, errors.Join(dialErrors...))
}

func (d *originDialer) configuredCandidates(ctx context.Context) (string, []string, error) {
	return d.origins.Endpoints(ctx, d.route.Upstream.Host, d.route.Upstream.OriginPort())
}

func (d *originDialer) handshake(ctx context.Context, network, address string) (net.Conn, error) {
	rawConnection, err := d.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	allowInsecure := d.origins != nil && d.origins.insecureSkipVerify
	tlsConnection := tls.Client(rawConnection, originTLSConfig(d.route.Upstream.Host, allowInsecure))
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := tlsConnection.HandshakeContext(handshakeCtx); err != nil {
		rawConnection.Close()
		return nil, err
	}
	return tlsConnection, nil
}

func logConfiguredOrigin(host, address, source string) {
	log.Printf("configured origin host=%s address=%s source=%s", host, address, source)
}

func excludeAddresses(addresses, excluded []string) []string {
	if len(excluded) == 0 {
		return addresses
	}
	excludedSet := make(map[string]struct{}, len(excluded))
	for _, address := range excluded {
		excludedSet[address] = struct{}{}
	}
	filtered := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if _, exists := excludedSet[address]; !exists {
			filtered = append(filtered, address)
		}
	}
	return filtered
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

func originTLSConfig(serverName string, allowInsecure bool) *tls.Config {
	config := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// The origin handshake omits SNI. VerifyConnection checks the certificate
		// against the configured hostname without sending that name on the wire.
		InsecureSkipVerify: true,
	}
	if !allowInsecure {
		host := strings.TrimSuffix(strings.TrimSpace(serverName), ".")
		config.VerifyConnection = func(state tls.ConnectionState) error {
			return verifyOriginCertificate(state, host, nil)
		}
	}
	return config
}

func verifyOriginCertificate(state tls.ConnectionState, host string, roots *x509.CertPool) error {
	if len(state.PeerCertificates) == 0 {
		return errors.New("origin presented no certificate")
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}
