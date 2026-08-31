package proxyserver

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type HTTPServer struct {
	server    *http.Server
	transport *http.Transport
	dialer    *Dialer
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
	return s.server.Serve(listener)
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
