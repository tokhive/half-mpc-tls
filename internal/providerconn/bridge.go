package providerconn

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"time"

	"tokenhive.local/half-mpc-tls/internal/protocol"
	"tokenhive.local/half-mpc-tls/internal/sidecar"
)

// BridgeHost is a control endpoint, never a network destination. Its stream
// owns a Provider-local sidecar attachment and upstream socket until closed.
const BridgeHost = "provider-bridge.tokenhive.internal"
const maxBridgeRequest = 4096

type bridgeRequest struct {
	Capacity        sidecar.MPCCapacity `json:"capacity"`
	Version         uint16              `json:"version"`
	SessionID       uint64              `json:"session_id"`
	Target          protocol.Target     `json:"target"`
	AttachmentToken string              `json:"attachment_token"`
}

// StartProviderBridge transfers only control metadata over the reverse tunnel.
// TLS bytes travel between the Provider's local sidecar and upstream socket.
func (r *Registry) StartProviderBridge(ctx context.Context, providerID string, sessionID uint64, target protocol.Target, token string, capacity sidecar.MPCCapacity) (net.Conn, error) {
	if ctx == nil || sessionID == 0 || !sidecar.IsSupportedMPCCapacity(capacity) {
		return nil, errors.New("invalid Provider bridge parameters")
	}
	client := r.client(ctx, providerID)
	if client == nil {
		return nil, ErrProviderUnavailable
	}
	connection, err := client.OpenBuffered(ctx, protocol.Target{Host: BridgeHost, Port: SidecarPort})
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	request, err := json.Marshal(bridgeRequest{Capacity: capacity, Version: 1, SessionID: sessionID, Target: target, AttachmentToken: token})
	if err == nil && len(request) <= maxBridgeRequest {
		packet := make([]byte, 4+len(request))
		binary.BigEndian.PutUint32(packet, uint32(len(request)))
		copy(packet[4:], request)
		_, err = connection.Write(packet)
		if err == nil {
			var status [1]byte
			_, err = io.ReadFull(connection, status[:])
			if err == nil && status[0] != 1 {
				err = errors.New("Provider local bridge rejected")
			}
		}
	} else if err == nil {
		err = errors.New("Provider bridge request too large")
	}
	stopped := stop()
	if err != nil || !stopped || ctx.Err() != nil {
		_ = connection.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err == nil {
			err = errors.New("Provider bridge setup cancelled")
		}
		return nil, err
	}
	return connection, nil
}

func (d AgentDialer) serveBridge(control net.Conn) {
	defer control.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	setup, cancelSetup := context.WithTimeout(ctx, 10*time.Second)
	defer cancelSetup()
	_ = control.SetDeadline(time.Now().Add(10 * time.Second))
	fail := func() { _, _ = control.Write([]byte{0}) }
	var size [4]byte
	if _, err := io.ReadFull(control, size[:]); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(size[:])
	if length == 0 || length > maxBridgeRequest {
		fail()
		return
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(control, body); err != nil {
		return
	}
	var request bridgeRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || request.Version != 1 || request.SessionID == 0 || d.Policy == nil {
		fail()
		return
	}
	if _, err := decoder.Token(); err != io.EOF {
		fail()
		return
	}
	if request.Target.Host == SidecarHost || request.Target.Host == BridgeHost || d.Policy.Check(request.Target) != nil {
		fail()
		return
	}
	socket, err := d.socketForCapacity(request.Capacity)
	if err != nil {
		fail()
		return
	}
	attachment, err := sidecar.DialAttachment(setup, socket, sidecar.RoleProvider,
		request.SessionID, 1, sidecar.OperationAttachUpstreamChannel, request.AttachmentToken)
	if err != nil {
		fail()
		return
	}
	defer attachment.Abort()
	upstream, err := d.Network.DialContext(setup, "tcp", request.Target.Address())
	if err != nil {
		fail()
		return
	}
	defer upstream.Close()
	if _, err := control.Write([]byte{1}); err != nil {
		return
	}
	_ = control.SetDeadline(time.Time{})
	go func() {
		// This is a lifetime handle, not a TLS stream. EOF or any unexpected
		// further input destroys both local endpoints.
		var unexpected [1]byte
		_, _ = control.Read(unexpected[:])
		cancel()
	}()
	_ = sidecar.BridgeProviderUpstream(ctx, attachment, upstream)
}
