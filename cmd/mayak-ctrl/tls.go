package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

// newSelfSignedCert generates an ephemeral ECDSA P-256 self-signed
// certificate for the any-SNI listener. It returns the certificate and the
// SHA-256 fingerprint of the DER-encoded certificate as hex.
func newSelfSignedCert() (tls.Certificate, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("generate serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Mayak Control Node (ephemeral)"},
		SerialNumber:          serial,
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", fmt.Errorf("create certificate: %w", err)
	}
	sum := sha256.Sum256(der)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, hex.EncodeToString(sum[:]), nil
}

// anySNIHandler prepares the second listener, which completes a TLS
// handshake for any SNI. With --tls-cert/--tls-key it loads that PEM pair;
// otherwise it generates an ephemeral self-signed certificate and prints its
// SHA-256 fingerprint to stderr. An empty --tls-addr disables the listener
// (nil listener, nil error). It never logs SNI or client addresses.
func anySNIHandler(cfg *Config) (net.Listener, error) {
	if cfg.TLSAddr == "" {
		return nil, nil
	}

	var cert tls.Certificate
	var fingerprint string
	switch {
	case cfg.TLSCert != "" && cfg.TLSKey != "":
		var err error
		cert, err = tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("load TLS key pair: %w", err)
		}
	case cfg.TLSCert == "" && cfg.TLSKey == "":
		var err error
		cert, fingerprint, err = newSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral cert: %w", err)
		}
	default:
		return nil, errors.New("--tls-cert and --tls-key must be given together")
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return &cert, nil
		},
	}

	ln, err := net.Listen("tcp", cfg.TLSAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.TLSAddr, err)
	}

	if fingerprint != "" {
		fmt.Fprintf(os.Stderr, "any-SNI TLS certificate sha256 fingerprint: %s\n", fingerprint)
	}
	return tls.NewListener(ln, tlsCfg), nil
}

// serveTLSListener accepts connections on the any-SNI listener and closes
// each one right after explicitly completing its lazy TLS handshake.
func serveTLSListener(ln net.Listener) {
	defer ln.Close()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			if err := c.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
				return
			}
			if tlsConn, ok := c.(*tls.Conn); ok {
				_ = tlsConn.Handshake()
			}
		}(c)
	}
}
