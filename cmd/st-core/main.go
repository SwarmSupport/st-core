package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"st-core/internal/certificate"
	"st-core/internal/configuration"
	"st-core/internal/dnsresolver"
	"st-core/internal/dnsserver"
	"st-core/internal/gateway"
	"st-core/internal/proxyserver"
	"st-core/internal/routing"
	"st-core/internal/speedtest"
)

const localIPv4 = "127.0.0.1"
const maxSpeedtestAddresses = 1024

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("st-core", flag.ContinueOnError)
	configPath := flags.String("config", "config.yaml", "configuration file")
	flags.Usage = usage
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	args = flags.Args()
	if len(args) == 0 || args[0] == "help" {
		usage()
		return nil
	}
	cfg, err := configuration.Load(*configPath)
	if err != nil {
		return err
	}
	switch args[0] {
	case "check":
		if len(args) != 1 {
			return errors.New("usage: st-core [-config path] check")
		}
		if err := cfg.Validate(); err != nil {
			return err
		}
		fmt.Println("configuration valid")
		return nil
	case "ca":
		return runCA(cfg, args[1:])
	case "speedtest":
		return runSpeedtest(cfg, args[1:])
	case "start", "serve":
		if len(args) != 2 {
			return errors.New("usage: st-core [-config path] start <all|proxy|dns|https|http>")
		}
		return serve(cfg, args[1])
	default:
		return fmt.Errorf("unknown command %q (run st-core help)", args[0])
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: st-core [-config config.yaml] <command>

Commands:
  check                         Validate configuration
  ca generate                   Create the configured CA certificate and key
  ca install                    Trust the configured CA for the current user
  ca remove                     Remove that CA from the current user's trust store
  start all                     Start all configured servers
  start proxy                   Start HTTP and SOCKS5 proxy servers
  start dns                     Start the policy DNS server
  start https                   Start the HTTPS gateway
  start http                    Start the HTTP gateway
  speedtest                     Resolve provider URLs and test their IPs
  speedtest <IP:port|CIDR> [...] Test specified IPs (CIDR uses port 443)
  help                          Show this help

"serve" is an alias for "start".`)
}

func serve(cfg *configuration.Config, target string) error {
	switch target {
	case "all", "proxy", "dns", "https", "http":
	default:
		return fmt.Errorf("unknown server %q; use all, proxy, dns, https, or http", target)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	resolver, err := dnsresolver.New(cfg.DNS.DoHServer, cfg.DNS.BootstrapAddresses)
	if err != nil {
		return err
	}
	directResolver, err := dnsresolver.New(cfg.DNS.DirectDoHServer, cfg.DNS.DirectBootstrapAddresses)
	if err != nil {
		return err
	}
	policyContext, cancelPolicy := context.WithTimeout(context.Background(), 30*time.Second)
	policy, err := routing.Load(policyContext, cfg.Routing, resolver)
	cancelPolicy()
	if err != nil {
		return err
	}
	log.Printf("routing mode=%s", policy.Mode())
	serverErrors := make(chan error, 5)
	started := 0
	start := func(name, address string, fn func() error) {
		started++
		go func() {
			log.Printf("%s listening on %s", name, address)
			if err := fn(); err != nil && err != http.ErrServerClosed {
				serverErrors <- fmt.Errorf("%s: %w", name, err)
			}
		}()
	}
	if target == "all" || target == "https" || target == "http" {
		if policy.Mode() == "bypass" {
			if target != "all" {
				return errors.New("HTTP and HTTPS gateways are disabled in bypass routing mode")
			}
		} else {
			originContext, cancelOrigin := context.WithTimeout(context.Background(), 30*time.Second)
			originPool, originErr := gateway.LoadOriginPool(originContext, resolver, cfg.Origin)
			cancelOrigin()
			if originErr != nil {
				log.Printf("origin list error: %v", originErr)
			}
			router := gateway.NewRouter(cfg, resolver, policy, originPool)
			if target == "all" || target == "https" {
				certManager, err := certificate.Load(cfg.CA.Cert, cfg.CA.Key)
				if err != nil {
					return fmt.Errorf("load CA (run 'st-core ca generate' first): %w", err)
				}
				gatewayServer := &http.Server{Addr: cfg.HTTPSListen, Handler: router, TLSConfig: BuildTLSConfig(certManager), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
				start("HTTPS gateway", cfg.HTTPSListen, func() error { return serveHTTPS4(gatewayServer, cfg.HTTPSListen) })
			}
			if target == "all" || target == "http" {
				httpGatewayServer := &http.Server{Addr: cfg.HTTPListen, Handler: router, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
				start("HTTP gateway", cfg.HTTPListen, func() error { return serveHTTP4(httpGatewayServer, cfg.HTTPListen) })
			}
		}
	}
	if target == "all" || target == "dns" {
		dnsProxy := dnsserver.NewWithPolicy(cfg.DNS.Listen, localIPv4, policy, directResolver)
		start("policy DNS", cfg.DNS.Listen, dnsProxy.ListenAndServe)
	}
	if target == "all" || target == "proxy" {
		proxyDialer := proxyserver.NewDialerWithPolicy(localIPv4, policy, directResolver)
		if cfg.Proxy.HTTPListen != "" {
			httpProxy := proxyserver.NewHTTPServer(cfg.Proxy.HTTPListen, proxyDialer)
			start("HTTP proxy", cfg.Proxy.HTTPListen, httpProxy.ListenAndServe)
		}
		if cfg.Proxy.SOCKS5Listen != "" {
			socksProxy := &proxyserver.SOCKS5Server{Address: cfg.Proxy.SOCKS5Listen, Dialer: proxyDialer}
			start("SOCKS5 proxy", cfg.Proxy.SOCKS5Listen, socksProxy.ListenAndServe)
		}
	}
	if started == 0 {
		return fmt.Errorf("no %s servers are configured", target)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go speedtest.SelectAtStartup(ctx, cfg.SpeedTest, resolver, "iplist")
	select {
	case err := <-serverErrors:
		return err
	case <-ctx.Done():
		return nil
	}
}

func runCA(cfg *configuration.Config, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: st-core [-config path] ca <generate|install|remove>")
	}
	if cfg.CA.Cert == "" || cfg.CA.Key == "" {
		return errors.New("ca.cert and ca.key are required")
	}
	switch args[0] {
	case "generate":
		if err := certificate.GenerateCA(cfg.CA.Cert, cfg.CA.Key); err != nil {
			return err
		}
		fmt.Printf("CA created: %s\n", cfg.CA.Cert)
	case "install":
		if err := certificate.InstallCA(cfg.CA.Cert); err != nil {
			return err
		}
		fmt.Printf("CA trusted: %s\n", cfg.CA.Cert)
	case "remove":
		if err := certificate.RemoveCA(cfg.CA.Cert); err != nil {
			return err
		}
		fmt.Printf("CA trust removed: %s\n", cfg.CA.Cert)
	default:
		return fmt.Errorf("unknown CA command %q", args[0])
	}
	return nil
}

func runSpeedtest(cfg *configuration.Config, args []string) error {
	var addresses []string
	if len(args) > 0 {
		var err error
		addresses, err = expandSpeedtestTargets(args)
		if err != nil {
			return err
		}
	}
	options := cfg.SpeedTest
	options.Disabled = false // An explicit CLI request always runs the test.
	selector := speedtest.NewSelector(options)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	resolved, resolveErr := selector.ResolveTargets(ctx, systemResolver{})
	if resolveErr != nil {
		log.Printf("provider DNS warning: %v", resolveErr)
	}
	var results []speedtest.Result
	if len(args) == 0 {
		if len(resolved) == 0 {
			return errors.New("no provider download URLs resolved to test IPs")
		}
		results = selector.TestTargets(ctx, "tcp", resolved)
	} else {
		matched := make(map[string][]speedtest.Target)
		for _, target := range resolved {
			matched[target.Address] = append(matched[target.Address], target)
		}
		var providerTargets []speedtest.Target
		var unknownAddresses []string
		for _, address := range addresses {
			if targets := matched[address]; len(targets) > 0 {
				providerTargets = append(providerTargets, targets...)
			} else {
				unknownAddresses = append(unknownAddresses, address)
			}
		}
		results = selector.TestTargets(ctx, "tcp", providerTargets)
		results = append(results, selector.Test(ctx, "tcp", unknownAddresses)...)
	}
	successes := 0
	for _, result := range results {
		if !result.OK {
			fmt.Printf("%s provider=%s unavailable\n", result.Address, providerLabel(result.Provider))
			continue
		}
		successes++
		fmt.Printf("%s provider=%s %.2f Mbps (%d bytes in %s)\n", result.Address, result.Provider, result.Mbps(), result.Bytes, result.Duration.Round(time.Millisecond))
	}
	if successes == 0 {
		return errors.New("no speed-test endpoint accepted the specified addresses")
	}
	return nil
}

type systemResolver struct{}

func (systemResolver) Resolve(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

func providerLabel(name string) string {
	if name == "" {
		return "unknown"
	}
	return name
}

func expandSpeedtestTargets(inputs []string) ([]string, error) {
	addresses := make([]string, 0, len(inputs))
	seen := make(map[string]struct{})
	add := func(address string) error {
		if _, exists := seen[address]; exists {
			return nil
		}
		if len(addresses) >= maxSpeedtestAddresses {
			return fmt.Errorf("speedtest accepts at most %d distinct addresses", maxSpeedtestAddresses)
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address)
		return nil
	}
	for _, input := range inputs {
		if strings.Contains(input, "/") {
			prefix, err := netip.ParsePrefix(input)
			if err != nil || !prefix.Addr().Is4() {
				return nil, fmt.Errorf("speedtest target %q must be an IPv4 CIDR or IP:port", input)
			}
			count := uint64(1) << uint(32-prefix.Bits())
			if count > maxSpeedtestAddresses {
				return nil, fmt.Errorf("CIDR %q contains %d addresses; limit is %d", input, count, maxSpeedtestAddresses)
			}
			ip := prefix.Masked().Addr()
			for range count {
				if err := add(net.JoinHostPort(ip.String(), "443")); err != nil {
					return nil, err
				}
				ip = ip.Next()
			}
			continue
		}
		host, portText, err := net.SplitHostPort(input)
		port, portErr := strconv.Atoi(portText)
		if err != nil || net.ParseIP(host) == nil || portErr != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("speedtest address %q must be IP:port", input)
		}
		if err := add(net.JoinHostPort(host, portText)); err != nil {
			return nil, err
		}
	}
	return addresses, nil
}

func BuildTLSConfig(certs *certificate.Manager) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := normalizeHost(hello.ServerName)
			if host == "" {
				return nil, fmt.Errorf("TLS client did not provide a server name")
			}
			return certs.CertificateForHost(host)
		},
	}
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.ToLower(host)
	host = strings.TrimSuffix(host, ".")
	return host
}

func serveHTTP4(server *http.Server, address string) error {
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	return server.Serve(listener)
}

func serveHTTPS4(server *http.Server, address string) error {
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	return server.ServeTLS(listener, "", "")
}
