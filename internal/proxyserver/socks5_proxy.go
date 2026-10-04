package proxyserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	socksVersion5       = 5
	socksNoAuth         = 0
	socksNoAcceptable   = 0xff
	socksConnect        = 1
	socksAddressIPv4    = 1
	socksAddressDomain  = 3
	socksAddressIPv6    = 4
	socksReplySucceeded = 0
	socksReplyFailure   = 1
)

type SOCKS5Server struct {
	Address string
	Dialer  *Dialer
	mu      sync.Mutex
	clients map[net.Conn]struct{}
}

func (s *SOCKS5Server) ListenAndServe() error {
	listener, err := net.Listen("tcp4", s.Address)
	if err != nil {
		return err
	}
	defer listener.Close()
	return s.Serve(listener)
}

func (s *SOCKS5Server) Serve(listener net.Listener) error {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		s.mu.Lock()
		if s.clients == nil {
			s.clients = make(map[net.Conn]struct{})
		}
		s.clients[connection] = struct{}{}
		s.mu.Unlock()
		go func() {
			defer func() {
				s.mu.Lock()
				delete(s.clients, connection)
				s.mu.Unlock()
			}()
			if err := s.handle(connection); err != nil {
				log.Printf("SOCKS5 client=%s error=%v", connection.RemoteAddr(), err)
			}
		}()
	}
}

func (s *SOCKS5Server) CloseClients() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for connection := range s.clients {
		_ = connection.Close()
	}
}

func (s *SOCKS5Server) handle(client net.Conn) error {
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if err := negotiateSOCKS5(client); err != nil {
		return err
	}
	target, err := readSOCKS5Target(client)
	if err != nil {
		_ = writeSOCKS5Reply(client, socksReplyFailure)
		return err
	}

	dialContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	upstream, err := s.Dialer.DialContext(dialContext, "tcp", target)
	if err != nil {
		_ = writeSOCKS5Reply(client, socksReplyFailure)
		return fmt.Errorf("connect to %s: %w", target, err)
	}
	if err := writeSOCKS5Reply(client, socksReplySucceeded); err != nil {
		upstream.Close()
		return err
	}
	_ = client.SetDeadline(time.Time{})
	relay(client, upstream)
	return nil
}

func negotiateSOCKS5(connection net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(connection, header); err != nil {
		return err
	}
	if header[0] != socksVersion5 {
		return fmt.Errorf("unsupported SOCKS version %d", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(connection, methods); err != nil {
		return err
	}
	selected := byte(socksNoAcceptable)
	for _, method := range methods {
		if method == socksNoAuth {
			selected = socksNoAuth
			break
		}
	}
	if _, err := connection.Write([]byte{socksVersion5, selected}); err != nil {
		return err
	}
	if selected == socksNoAcceptable {
		return errors.New("client does not support SOCKS5 no-auth mode")
	}
	return nil
}

func readSOCKS5Target(connection net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(connection, header); err != nil {
		return "", err
	}
	if header[0] != socksVersion5 || header[1] != socksConnect || header[2] != 0 {
		return "", errors.New("unsupported SOCKS5 request")
	}
	var host string
	switch header[3] {
	case socksAddressIPv4:
		address := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(connection, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case socksAddressIPv6:
		address := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(connection, address); err != nil {
			return "", err
		}
		host = net.IP(address).String()
	case socksAddressDomain:
		length := []byte{0}
		if _, err := io.ReadFull(connection, length); err != nil {
			return "", err
		}
		domain := make([]byte, int(length[0]))
		if _, err := io.ReadFull(connection, domain); err != nil {
			return "", err
		}
		host = string(domain)
	default:
		return "", fmt.Errorf("unsupported SOCKS5 address type %d", header[3])
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(connection, portBytes); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))), nil
}

func writeSOCKS5Reply(connection net.Conn, reply byte) error {
	_, err := connection.Write([]byte{socksVersion5, reply, 0, socksAddressIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
