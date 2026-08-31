package proxyserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

type TrafficPolicy interface {
	ShouldHandle(string) bool
}

type DomainResolver interface {
	Resolve(context.Context, string) ([]net.IP, error)
}

type Dialer struct {
	localIP   net.IP
	tcpDialer *net.Dialer
	policy    TrafficPolicy
	resolver  DomainResolver
}

func NewDialer(localIP string) *Dialer {
	return NewDialerWithPolicy(localIP, nil, nil)
}

func NewDialerWithPolicy(localIP string, policy TrafficPolicy, resolver DomainResolver) *Dialer {
	parsedIP := net.ParseIP(localIP).To4()
	if parsedIP == nil {
		parsedIP = net.IPv4(127, 0, 0, 1)
	}
	return &Dialer{
		localIP:   parsedIP,
		tcpDialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
		policy:    policy,
		resolver:  resolver,
	}
}

func (d *Dialer) DialContext(ctx context.Context, network, target string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy target %q: %w", target, err)
	}
	if address := net.ParseIP(host); address != nil {
		if d.policy != nil && d.policy.ShouldHandle(host) {
			return d.tcpDialer.DialContext(ctx, network, net.JoinHostPort(d.localIP.String(), port))
		}
		return d.tcpDialer.DialContext(ctx, network, net.JoinHostPort(address.String(), port))
	}
	if d.policy != nil && !d.policy.ShouldHandle(host) {
		return d.dialDirect(ctx, network, host, port)
	}
	return d.tcpDialer.DialContext(ctx, network, net.JoinHostPort(d.localIP.String(), port))
}

func (d *Dialer) dialDirect(ctx context.Context, network, host, port string) (net.Conn, error) {
	if d.resolver == nil {
		return d.tcpDialer.DialContext(ctx, network, net.JoinHostPort(host, port))
	}
	addresses, err := d.resolver.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var dialErrors []error
	for _, address := range addresses {
		connection, err := d.tcpDialer.DialContext(ctx, network, net.JoinHostPort(address.String(), port))
		if err == nil {
			return connection, nil
		}
		dialErrors = append(dialErrors, fmt.Errorf("dial %s: %w", address, err))
		if ctx.Err() != nil {
			break
		}
	}
	if len(dialErrors) == 0 {
		return nil, fmt.Errorf("resolve %s: no addresses returned", host)
	}
	return nil, errors.Join(dialErrors...)
}
