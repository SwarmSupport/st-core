package proxyserver

import (
	"bufio"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type HTTPServer struct {
	server    *http.Server
	transport *http.Transport
	dialer    *Dialer
	mu        sync.Mutex
	tunnels   map[net.Conn]net.Conn
}

func NewHTTPServer(address string, dialer *Dialer) *HTTPServer {
	proxy := &HTTPServer{dialer: dialer}
	proxy.transport = &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	proxy.server = &http.Server{
		Addr:              address,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	return proxy
}

func (s *HTTPServer) ListenAndServe() error {
	listener, err := net.Listen("tcp4", s.server.Addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	return s.Serve(listener)
}

func (s *HTTPServer) Serve(listener net.Listener) error { return s.server.Serve(listener) }

func (s *HTTPServer) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	for client, upstream := range s.tunnels {
		_ = client.Close()
		_ = upstream.Close()
	}
	s.mu.Unlock()
	s.transport.CloseIdleConnections()
	return s.server.Shutdown(ctx)
}

func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodConnect {
		s.serveConnect(w, request)
		return
	}
	s.serveForward(w, request)
}

func (s *HTTPServer) serveConnect(w http.ResponseWriter, request *http.Request) {
	target := withDefaultPort(request.Host, "443")
	upstream, err := s.dialer.DialContext(request.Context(), "tcp", target)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		log.Printf("HTTP CONNECT target=%s error=%v", target, err)
		return
	}

	controller := http.NewResponseController(w)
	client, readerWriter, err := controller.Hijack()
	if err != nil {
		upstream.Close()
		http.Error(w, "proxy does not support hijacking", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	if s.tunnels == nil {
		s.tunnels = make(map[net.Conn]net.Conn)
	}
	s.tunnels[client] = upstream
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.tunnels, client)
		s.mu.Unlock()
	}()
	if _, err := readerWriter.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	if err := readerWriter.Flush(); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	if err := forwardBuffered(readerWriter.Reader, upstream); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	relay(client, upstream)
}

func withDefaultPort(authority, defaultPort string) string {
	if host, port, err := net.SplitHostPort(authority); err == nil {
		if port == "" {
			return net.JoinHostPort(host, defaultPort)
		}
		return authority
	}
	host := strings.TrimPrefix(strings.TrimSuffix(authority, "]"), "[")
	return net.JoinHostPort(host, defaultPort)
}

func forwardBuffered(reader *bufio.Reader, upstream net.Conn) error {
	buffered := reader.Buffered()
	if buffered == 0 {
		return nil
	}
	payload := make([]byte, buffered)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return err
	}
	_, err := upstream.Write(payload)
	return err
}

func (s *HTTPServer) serveForward(w http.ResponseWriter, request *http.Request) {
	outbound := request.Clone(request.Context())
	if outbound.URL.Scheme == "" {
		outbound.URL.Scheme = "http"
	}
	if outbound.URL.Host == "" {
		outbound.URL.Host = request.Host
	}
	outbound.RequestURI = ""
	removeHopHeaders(outbound.Header)

	response, err := s.transport.RoundTrip(outbound)
	if err != nil {
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
		log.Printf("HTTP proxy target=%s error=%v", outbound.URL.Host, err)
		return
	}
	defer response.Body.Close()
	removeHopHeaders(response.Header)
	for key, values := range response.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	if _, err := io.Copy(w, response.Body); err != nil {
		log.Printf("HTTP proxy response target=%s error=%v", outbound.URL.Host, err)
	}
}

var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, key := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(key))
		}
	}
	for _, key := range hopHeaders {
		header.Del(key)
	}
}
