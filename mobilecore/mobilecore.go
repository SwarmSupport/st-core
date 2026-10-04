// Package mobilecore exposes loopback HTTP and SOCKS5 proxies to Android and iOS
// applications through gomobile bind. The host app owns the lifecycle.
package mobilecore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"st-core/internal/proxyserver"
)

// Core is a single instance of the mobile proxy service.
type Core struct {
	mu            sync.Mutex
	httpListener  net.Listener
	socksListener net.Listener
	httpProxy     *proxyserver.HTTPServer
	socksProxy    *proxyserver.SOCKS5Server
	workers       sync.WaitGroup
	errMu         sync.Mutex
	lastErr       error
}

func NewCore() *Core { return &Core{} }

// Start binds the requested ports on IPv4 loopback. A negative port disables
// that proxy; zero asks the OS for a free port. Start returns after binding.
func (c *Core) Start(httpPort, socksPort int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.httpListener != nil || c.socksListener != nil {
		return errors.New("mobile core is already running")
	}
	if (httpPort < 0 && socksPort < 0) || httpPort < -1 || httpPort > 65535 || socksPort < -1 || socksPort > 65535 {
		return errors.New("specify at least one port between 0 and 65535; use -1 to disable a proxy")
	}
	c.errMu.Lock()
	c.lastErr = nil
	c.errMu.Unlock()
	var httpListener, socksListener net.Listener
	var err error
	if httpPort >= 0 {
		httpListener, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", httpPort))
		if err != nil {
			return fmt.Errorf("bind HTTP proxy: %w", err)
		}
	}
	if socksPort >= 0 {
		socksListener, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", socksPort))
		if err != nil {
			if httpListener != nil {
				_ = httpListener.Close()
			}
			return fmt.Errorf("bind SOCKS5 proxy: %w", err)
		}
	}
	c.httpListener, c.socksListener = httpListener, socksListener
	dialer := proxyserver.NewDialer("127.0.0.1")
	if httpListener != nil {
		c.httpProxy = proxyserver.NewHTTPServer(httpListener.Addr().String(), dialer)
		c.workers.Add(1)
		go func() {
			defer c.workers.Done()
			if err := c.httpProxy.Serve(httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				c.recordError(fmt.Errorf("HTTP proxy: %w", err))
				_ = httpListener.Close()
			}
		}()
	}
	if socksListener != nil {
		c.socksProxy = &proxyserver.SOCKS5Server{Address: socksListener.Addr().String(), Dialer: dialer}
		c.workers.Add(1)
		go func() {
			defer c.workers.Done()
			if err := c.socksProxy.Serve(socksListener); err != nil && !errors.Is(err, net.ErrClosed) {
				c.recordError(fmt.Errorf("SOCKS5 proxy: %w", err))
			}
		}()
	}
	return nil
}

func (c *Core) HTTPAddress() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.httpListener == nil {
		return ""
	}
	return c.httpListener.Addr().String()
}

func (c *Core) SOCKS5Address() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.socksListener == nil {
		return ""
	}
	return c.socksListener.Addr().String()
}

// LastError returns an unexpected listener failure, if one occurred.
func (c *Core) LastError() string {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	if c.lastErr == nil {
		return ""
	}
	return c.lastErr.Error()
}

func (c *Core) recordError(err error) {
	c.errMu.Lock()
	c.lastErr = errors.Join(c.lastErr, err)
	c.errMu.Unlock()
}

// Stop closes listeners and active tunnels, then waits for serving loops to exit.
func (c *Core) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.httpListener == nil && c.socksListener == nil {
		return nil
	}
	if c.socksListener != nil {
		_ = c.socksListener.Close()
		c.socksProxy.CloseClients()
	}
	var err error
	if c.httpProxy != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = c.httpProxy.Shutdown(ctx)
		cancel()
	}
	c.workers.Wait()
	if c.socksProxy != nil {
		c.socksProxy.CloseClients()
	}
	c.errMu.Lock()
	err = errors.Join(err, c.lastErr)
	c.errMu.Unlock()
	c.httpListener, c.socksListener = nil, nil
	c.httpProxy, c.socksProxy = nil, nil
	return err
}
