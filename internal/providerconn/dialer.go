package providerconn

import (
	"context"
	"errors"
	"net"
	"strconv"
	"tokenhive.local/half-mpc-tls/internal/egress"
	"tokenhive.local/half-mpc-tls/internal/protocol"
	"tokenhive.local/half-mpc-tls/internal/sidecar"
)

// AgentDialer maps the reserved sidecar target to a local mode-0600 Unix
// socket and sends every other allowed target through the Provider network.
// It is intended for tunnel.Provider after egress.Policy has approved a target.
type AgentDialer struct {
	SidecarSocket  string
	SidecarSockets map[string]string
	Policy         *egress.Policy
	Network        net.Dialer
}

func (d AgentDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address == net.JoinHostPort(BridgeHost, "1") {
		if (d.SidecarSocket == "" && len(d.SidecarSockets) == 0) || d.Policy == nil {
			return nil, errors.New("Provider local bridge is not configured")
		}
		client, server := net.Pipe()
		go d.serveBridge(server)
		return client, nil
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if host == SidecarHost {
		port, err := strconv.Atoi(portText)
		profiles := sidecar.CapacityProfiles()
		if err != nil || port < 1 || port > len(profiles) {
			return nil, errors.New("unsupported sidecar port")
		}
		capacity, _ := sidecar.CapacityProfile(profiles[port-1])
		socket, err := d.socketForCapacity(capacity)
		if err != nil {
			return nil, err
		}
		return d.Network.DialContext(ctx, "unix", socket)
	}
	if host == BridgeHost {
		return nil, errors.New("unsupported bridge port")
	}
	if network != "tcp" {
		return nil, errors.New("Provider upstream network must be tcp")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || d.Policy == nil {
		return nil, errors.New("Provider upstream policy is required")
	}
	if err := d.Policy.Check(protocol.Target{Host: host, Port: uint16(port)}); err != nil {
		return nil, err
	}
	return d.Network.DialContext(ctx, network, address)
}
