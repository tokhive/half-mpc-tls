package mpctls

import (
	"context"
	"net"

	"tokenhive.local/half-mpc-tls/internal/protocol"
)

type SecurityMode string

const (
	// SecurityModeDevelopmentHubTLS exposes all TLS traffic secrets to Hub.
	// It exists only to validate M0 networking and orchestration.
	SecurityModeDevelopmentHubTLS SecurityMode = "development-hub-terminated-tls"
	SecurityModeSelectiveMPC      SecurityMode = "tls12-selective-mpc"
)

type Engine interface {
	Mode() SecurityMode
	Open(ctx context.Context, transport net.Conn, target protocol.Target) (net.Conn, error)
}
