package hub

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/providerconn"
)

func TestDataListenerAuthenticatesAndKeepsIndependentSlots(t *testing.T) {
	serverTLS, clients := testDataTLSConfigs(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := providerconn.NewRegistry()
	defer registry.Close()
	failures := make(chan error, 1)
	go serveData(ctx, listener, serverTLS, "tokenhive.test", map[string]struct{}{"provider-1": {}}, registry, failures)
	for slot := range 2 {
		connection, err := tls.Dial("tcp", listener.Addr().String(), clients["provider-1"])
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		if err := providerconn.WriteDataHello(connection, uint16(slot)); err != nil {
			t.Fatal(err)
		}
	}
	// Handshake and hello parsing happen asynchronously on the listener.
	deadline := time.Now().Add(time.Second)
	releases := make([]func(), 0, 2)
	for len(releases) < 2 {
		_, release, err := registry.ReserveProvider(ctx, "provider-1")
		if err == nil {
			releases = append(releases, release)
			defer release()
			continue
		}
		if time.Now().After(deadline) {
			t.Fatal("authenticated slots replaced each other or failed registration")
		}
		time.Sleep(time.Millisecond)
	}
	for _, test := range []struct {
		provider string
		hello    []byte
	}{
		{"provider-1", []byte("THD1\x01\x00")},
		{"provider-1", []byte("OLD!\x00\x00")},
		{"provider-2", []byte("THD1\x00\x00")},
	} {
		connection, err := tls.Dial("tcp", listener.Addr().String(), clients[test.provider])
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		_, _ = connection.Write(test.hello)
		var buffer [1]byte
		_, err = connection.Read(buffer[:])
		_ = connection.Close()
		if err == nil {
			t.Fatal("invalid slot or unlisted identity accepted")
		}
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatalf("invalid hello was not rejected promptly: %v", err)
		}
	}
	select {
	case err := <-failures:
		t.Fatal(err)
	default:
	}
}

func testDataTLSConfigs(t *testing.T) (*tls.Config, map[string]*tls.Config) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TokenHive test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	issue := func(serial int64, dnsName, providerID string, usage x509.ExtKeyUsage) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: dnsName},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		}
		if dnsName != "" {
			template.DNSNames = []string{dnsName}
		}
		if providerID != "" {
			template.URIs = []*url.URL{{
				Scheme: "spiffe",
				Host:   "tokenhive.test",
				Path:   "/provider/" + providerID,
			}}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}

	serverCertificate := issue(2, "hub.test", "", x509.ExtKeyUsageServerAuth)
	clients := make(map[string]*tls.Config)
	for index, providerID := range []string{"provider-1", "provider-2"} {
		clients[providerID] = &tls.Config{
			MinVersion:   tls.VersionTLS13,
			ServerName:   "hub.test",
			RootCAs:      roots,
			Certificates: []tls.Certificate{issue(int64(index+3), "", providerID, x509.ExtKeyUsageClientAuth)},
		}
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate},
		ClientCAs:    roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}, clients
}
