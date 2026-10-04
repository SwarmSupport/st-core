package dnsserver

import (
	"context"
	"log"
	"net"
	"time"

	"github.com/miekg/dns"
)

type TrafficPolicy interface {
	ShouldHandle(string) bool
}

type UpstreamResolver interface {
	Exchange(context.Context, *dns.Msg) (*dns.Msg, error)
}

type Server struct {
	ipv4     net.IP
	policy   TrafficPolicy
	resolver UpstreamResolver
	udp      *dns.Server
	tcp      *dns.Server
}

func New(address, ipv4 string) *Server {
	return NewWithPolicy(address, ipv4, nil, nil)
}

func NewWithPolicy(address, ipv4 string, policy TrafficPolicy, resolver UpstreamResolver) *Server {
	server := &Server{
		ipv4:     net.ParseIP(ipv4).To4(),
		policy:   policy,
		resolver: resolver,
	}
	handler := dns.HandlerFunc(server.handle)
	server.udp = &dns.Server{Addr: address, Net: "udp4", Handler: handler}
	server.tcp = &dns.Server{Addr: address, Net: "tcp4", Handler: handler}
	return server
}

func (s *Server) ListenAndServe() error {
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- s.udp.ListenAndServe() }()
	go func() { errorsChannel <- s.tcp.ListenAndServe() }()
	err := <-errorsChannel
	_ = s.udp.Shutdown()
	_ = s.tcp.Shutdown()
	return err
}

func (s *Server) handle(writer dns.ResponseWriter, request *dns.Msg) {
	if !s.shouldReturnLocal(request) {
		s.forward(writer, request)
		return
	}
	response := new(dns.Msg)
	response.SetReply(request)
	response.Authoritative = true
	response.Compress = true
	for _, question := range request.Question {
		header := dns.RR_Header{Name: question.Name, Class: dns.ClassINET, Ttl: 60}
		switch question.Qtype {
		case dns.TypeA:
			header.Rrtype = dns.TypeA
			response.Answer = append(response.Answer, &dns.A{Hdr: header, A: s.ipv4})
		case dns.TypeANY:
			header.Rrtype = dns.TypeA
			response.Answer = append(response.Answer, &dns.A{Hdr: header, A: s.ipv4})
		}
	}
	if err := writer.WriteMsg(response); err != nil {
		_ = writer.Close()
	}
}

func (s *Server) shouldReturnLocal(request *dns.Msg) bool {
	if len(request.Question) == 0 || s.policy == nil {
		return true
	}
	for _, question := range request.Question {
		if !s.policy.ShouldHandle(question.Name) {
			return false
		}
	}
	return true
}

func (s *Server) forward(writer dns.ResponseWriter, request *dns.Msg) {
	if s.resolver == nil {
		s.writeFailure(writer, request)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	response, err := s.resolver.Exchange(ctx, request)
	if err != nil {
		log.Printf("DNS forward question=%s error=%v", questionName(request), err)
		s.writeFailure(writer, request)
		return
	}
	response.Id = request.Id
	if err := writer.WriteMsg(response); err != nil {
		_ = writer.Close()
	}
}

func (s *Server) writeFailure(writer dns.ResponseWriter, request *dns.Msg) {
	response := new(dns.Msg)
	response.SetRcode(request, dns.RcodeServerFailure)
	if err := writer.WriteMsg(response); err != nil {
		_ = writer.Close()
	}
}

func questionName(request *dns.Msg) string {
	if len(request.Question) == 0 {
		return ""
	}
	return request.Question[0].Name
}
