package mpctls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/egress"
	"tokenhive.local/half-mpc-tls/internal/protocol"
	"tokenhive.local/half-mpc-tls/internal/tunnel"
)

func TestDevelopmentTLS12ThroughProviderTunnel(t *testing.T) {
	certificate, roots := testCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})
	defer tlsListener.Close()
	go serveTLSEcho(tlsListener)

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := egress.NewPolicy([]string{host}, []uint16{uint16(port)})
	if err != nil {
		t.Fatal(err)
	}

	hubControl, providerControl := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = (&tunnel.Provider{Policy: policy}).Serve(ctx, providerControl)
	}()
	hubTunnel := tunnel.NewClient(hubControl)
	defer hubTunnel.Close()

	target := protocol.Target{Host: host, Port: uint16(port), SNI: "localhost"}
	openCtx, openCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer openCancel()
	raw, err := hubTunnel.Open(openCtx, target)
	if err != nil {
		t.Fatalf("open provider tunnel: %v", err)
	}

	engine := DevelopmentEngine{RootCAs: roots}
	secured, err := engine.Open(openCtx, raw, target)
	if err != nil {
		t.Fatalf("open TLS engine: %v", err)
	}
	defer secured.Close()

	request := []byte("request through TLS 1.2")
	if _, err := secured.Write(request); err != nil {
		t.Fatalf("write TLS request: %v", err)
	}
	response := make([]byte, len(request))
	if _, err := io.ReadFull(secured, response); err != nil {
		t.Fatalf("read TLS response: %v", err)
	}
	if string(response) != string(request) {
		t.Fatalf("unexpected TLS response %q", response)
	}

	tlsConn, ok := secured.(*tls.Conn)
	if !ok {
		t.Fatal("development engine did not return a TLS connection")
	}
	state := tlsConn.ConnectionState()
	if state.Version != tls.VersionTLS12 || state.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("unexpected TLS state: %+v", state)
	}
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)
	return certificate, roots
}

func serveTLSEcho(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}
