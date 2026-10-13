package mockdpi

import (
	"crypto/tls"
	"encoding/json"
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

func startStubPage(t testing.TB) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(stubHandler))
	t.Cleanup(srv.Close)
	return listenAddr(srv.Listener)
}

// startControlHTTP starts the control HTTP echo, plain and over TLS. The TLS
// server has a single certificate, so it is served for any SNI.
func startControlHTTP(t testing.TB, cert tls.Certificate) (tlsAddr, httpAddr string) {
	t.Helper()
	plain := httptest.NewServer(http.HandlerFunc(echoHandler))
	t.Cleanup(plain.Close)

	secure := httptest.NewUnstartedServer(http.HandlerFunc(echoHandler))
	secure.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	secure.StartTLS()
	t.Cleanup(secure.Close)

	return listenAddr(secure.Listener), listenAddr(plain.Listener)
}
