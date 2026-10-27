package mpctls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	"tokenhive.local/half-mpc-tls/internal/protocol"
)

// DevelopmentEngine terminates ordinary TLS 1.2 inside Hub. It proves that
// the Provider egress tunnel works, but provides no Provider credential
// privacy and must never be enabled in production.
type DevelopmentEngine struct {
	RootCAs            *x509.CertPool
	InsecureSkipVerify bool
}

func (DevelopmentEngine) Mode() SecurityMode {
	return SecurityModeDevelopmentHubTLS
}

func (e DevelopmentEngine) Open(ctx context.Context, transport net.Conn, target protocol.Target) (net.Conn, error) {
	if err := target.Validate(); err != nil {
		return nil, err
	}
	serverName := target.SNI
	if serverName == "" {
		serverName = target.Host
	}

	config := &tls.Config{
		MinVersion:             tls.VersionTLS12,
		MaxVersion:             tls.VersionTLS12,
		ServerName:             serverName,
		RootCAs:                e.RootCAs,
		InsecureSkipVerify:     e.InsecureSkipVerify, // Development-only test hook.
		SessionTicketsDisabled: true,
		Renegotiation:          tls.RenegotiateNever,
		NextProtos:             []string{"http/1.1"},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		},
	}

	connection := tls.Client(transport, config)
	if err := connection.HandshakeContext(ctx); err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("TLS 1.2 handshake: %w", err)
	}
	state := connection.ConnectionState()
	if state.Version != tls.VersionTLS12 {
		_ = connection.Close()
		return nil, fmt.Errorf("unexpected TLS version 0x%x", state.Version)
	}
	if !allowedCipherSuite(state.CipherSuite) {
		_ = connection.Close()
		return nil, fmt.Errorf("unexpected TLS cipher suite 0x%x", state.CipherSuite)
	}
	if state.NegotiatedProtocol != "http/1.1" {
		_ = connection.Close()
		return nil, fmt.Errorf("upstream did not negotiate HTTP/1.1")
	}
	return connection, nil
}

func allowedCipherSuite(cipherSuite uint16) bool {
	switch cipherSuite {
	case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
		return true
	default:
		return false
	}
}
