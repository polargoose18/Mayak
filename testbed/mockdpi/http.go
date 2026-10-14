package mockdpi

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

// StubBody is the text of the block page served by the stub_page scenario.
const StubBody = "Доступ ограничен"

// echoReply is the JSON body of the control HTTP echo. It deliberately has
// no client address.
type echoReply struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Host   string `json:"host"`
	SNI    string `json:"sni"` // empty for plain HTTP
}

func echoHandler(w http.ResponseWriter, r *http.Request) {
	reply := echoReply{Method: r.Method, Path: r.URL.Path, Host: r.Host}
	if r.TLS != nil {
		reply.SNI = r.TLS.ServerName
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(reply)
}

func stubHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte("<html><body><h1>" + StubBody + "</h1></body></html>"))
}

// newServer returns an unstarted test server whose error log is silenced:
// net/http would otherwise print the client's address into it.
func newServer(h http.HandlerFunc) *httptest.Server {
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	return srv
}

// startStubPage starts the block page over plain HTTP and over TLS (single
// certificate, so any SNI).
func startStubPage(t testing.TB, cert tls.Certificate) (httpAddr, tlsAddr string) {
	t.Helper()
	plain := newServer(stubHandler)
	plain.Start()
	t.Cleanup(plain.Close)

	secure := newServer(stubHandler)
	secure.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	secure.StartTLS()
	t.Cleanup(secure.Close)

	return listenAddr(plain.Listener), listenAddr(secure.Listener)
}

// startControlHTTP starts the control HTTP echo, plain and over TLS. The TLS
// server has a single certificate, so it is served for any SNI.
func startControlHTTP(t testing.TB, cert tls.Certificate) (tlsAddr, httpAddr string) {
	t.Helper()
	plain := newServer(echoHandler)
	plain.Start()
	t.Cleanup(plain.Close)

	secure := newServer(echoHandler)
	secure.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	secure.StartTLS()
	t.Cleanup(secure.Close)

	return listenAddr(secure.Listener), listenAddr(plain.Listener)
}
