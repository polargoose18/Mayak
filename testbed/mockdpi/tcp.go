package mockdpi

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

// tcpServer accepts connections and runs a handler per connection. Close
// stops the listener, closes every open connection and waits for handlers.
type tcpServer struct {
	ln net.Listener

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

// startTCP listens on a random loopback port and closes the server in
// t.Cleanup. It returns the listen address.
func startTCP(t testing.TB, handler func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mockdpi: listen: %v", err)
	}
	s := &tcpServer{ln: ln, conns: make(map[net.Conn]struct{})}
	s.wg.Add(1)
	go s.acceptLoop(handler)
	t.Cleanup(s.close)
	return listenAddr(ln)
}

func (s *tcpServer) acceptLoop(handler func(net.Conn)) {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return // the listener was closed
		}
		if !s.track(c) {
			_ = c.Close()
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.untrack(c)
			defer c.Close()
			handler(c)
		}()
	}
}

func (s *tcpServer) track(c net.Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c] = struct{}{}
	return true
}

func (s *tcpServer) untrack(c net.Conn) {
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *tcpServer) close() {
	s.mu.Lock()
	s.closed = true
	_ = s.ln.Close()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

var errBlockedSNI = errors.New("mockdpi: blocked SNI")

// startResetAfterHello starts a TLS server that resets the connection right
// after reading a ClientHello whose SNI is blacklisted.
func startResetAfterHello(t testing.TB, cert tls.Certificate, blocked []string) string {
	t.Helper()
	list := make(map[string]bool, len(blocked))
	for _, name := range blocked {
		list[normalizeName(name)] = true
	}
	return startTCP(t, func(c net.Conn) {
		cfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
			// Called after the ClientHello is read, before any answer is sent.
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				if list[normalizeName(hello.ServerName)] {
					resetConn(hello.Conn)
					return nil, errBlockedSNI
				}
				return nil, nil
			},
		}
		tc := tls.Server(c, cfg)
		if err := tc.Handshake(); err != nil {
			return
		}
		_, _ = io.Copy(io.Discard, tc) // hold the connection until the client leaves
	})
}

// resetConn closes c so that the peer sees a TCP RST instead of a FIN.
func resetConn(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
	_ = c.Close()
}

// startBlackhole starts a TCP server that accepts connections and never
// answers.
func startBlackhole(t testing.TB) string {
	t.Helper()
	return startTCP(t, func(c net.Conn) {
		_, _ = io.Copy(io.Discard, c)
	})
}

func normalizeName(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

// reserveClosedPort returns a loopback address whose port had a listener a
// moment ago and has none now, so connecting gets an immediate RST. The port
// could in theory be taken by another process before the test connects.
func reserveClosedPort(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mockdpi: listen: %v", err)
	}
	addr := listenAddr(ln)
	if err := ln.Close(); err != nil {
		t.Fatalf("mockdpi: close: %v", err)
	}
	return addr
}
