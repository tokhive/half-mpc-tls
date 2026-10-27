package providerconn

import (
	"context"
	"errors"
	"net"

	"tokenhive.local/half-mpc-tls/internal/protocol"
	"tokenhive.local/half-mpc-tls/internal/sidecar"
)

// SidecarPorts returns reserved logical ports, not local TCP listeners.
func SidecarPorts() []uint16 { return []uint16{1, 2, 3, 4, 5, 6} }

func capacityPort(capacity sidecar.MPCCapacity) (uint16, error) {
	name, err := sidecar.CapacityName(capacity)
	if err != nil {
		return 0, err
	}
	for index, candidate := range sidecar.CapacityProfiles() {
		if name == candidate {
			return uint16(index + 1), nil
		}
	}
	return 0, errors.New("unsupported capacity")
}

func (r *Registry) DialProviderSidecarForCapacity(ctx context.Context, providerID string, capacity sidecar.MPCCapacity) (net.Conn, error) {
	port, err := capacityPort(capacity)
	if err != nil {
		return nil, err
	}
	client := r.client(ctx, providerID)
	if client == nil {
		return nil, ErrProviderUnavailable
	}
	return client.OpenBuffered(ctx, protocol.Target{Host: SidecarHost, Port: port})
}

func (d AgentDialer) socketForCapacity(capacity sidecar.MPCCapacity) (string, error) {
	name, err := sidecar.CapacityName(capacity)
	if err != nil {
		return "", err
	}
	if path := d.SidecarSockets[name]; path != "" {
		return path, nil
	}
	if d.SidecarSocket != "" {
		return d.SidecarSocket, nil
	}
	return "", errors.New("Provider sidecar capacity is not configured")
}
