// Command mayak-ctrl is the control node (SPEC section 21.1).
//
// It serves three endpoints:
//
//	GET /v1/ping                     -> 200, empty body
//	GET /v1/reach?host=<host>        -> {"reachable": bool}
//	GET /v1/fetch?host=<host>&path=<path>
//	                                 -> {"status": int, "size": int, "body_hash": "<hex>"}
//
// It serves a host only if the host is in its own signed targets list, it
// refuses query keys other than host/path (never ip or port), it never dials
// a bogon address, it rate-limits per client, and it never logs a client
// address.
//
// A second TLS listener (--tls-addr) accepts any SNI and closes the
// connection immediately after the handshake, so the agent can observe
// whether an arbitrary handshake completes from outside.
package main

import (
	"fmt"
	"os"
)

// main parses flags, starts the any-SNI TLS listener and the HTTP API.
func main() {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	srv, err := newCtrlServer(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	if cfg.TLSAddr == "" {
		fmt.Fprintln(os.Stderr, "any-SNI TLS listener disabled (--tls-addr is empty)")
	} else {
		tlsLn, err := anySNIHandler(cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		go serveTLSListener(tlsLn)
	}

	if err := srv.http.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
