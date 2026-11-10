package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/polargoose18/mayak/internal/classify"
)

// refuseBogonDial is a net.Dialer.Control hook: it re-checks the address the
// node is actually connecting to and refuses bogons, whatever DNS said.
func refuseBogonDial(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("dial control: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("dial control: parse %s: %w", network, err)
	}
	if classify.IsBogon(ip.Unmap()) {
		return errors.New("dial control: bogon address refused")
	}
	return nil
}

// defaultDialContext dials TCP with a bogon re-check on the real address.
func defaultDialContext(timeout time.Duration) func(context.Context, string, string) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout, Control: refuseBogonDial}
	return d.DialContext
}

// resolvePublic resolves host and refuses the request if any candidate
// address is a bogon.
func (s *ctrlServer) resolvePublic(ctx context.Context, host string) ([]netip.Addr, error) {
	addrs, err := s.lookupHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve host: %w", err)
	}
	if len(addrs) == 0 {
		return nil, errors.New("resolve host: no addresses")
	}
	for _, ip := range addrs {
		if classify.IsBogon(ip.Unmap()) {
			return nil, errors.New("host resolves to a non-public address")
		}
	}
	return addrs, nil
}
