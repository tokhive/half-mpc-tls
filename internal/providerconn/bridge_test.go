package providerconn

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/egress"
	"tokenhive.local/half-mpc-tls/internal/protocol"
	"tokenhive.local/half-mpc-tls/internal/sidecar"
	"tokenhive.local/half-mpc-tls/internal/tunnel"
)

func TestLocalBridgeDeliversAndAcknowledgesWithoutHubTLSRelay(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "sidecar.sock")
	local, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	host, portText, _ := net.SplitHostPort(upstream.Addr().String())
	port, _ := strconv.Atoi(portText)
	policy, _ := egress.NewPolicy([]string{host, BridgeHost}, []uint16{uint16(port), SidecarPort})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	hub, provider := net.Pipe()
	go func() {
		_ = (&tunnel.Provider{Policy: policy, Dialer: AgentDialer{SidecarSocket: socket, Policy: policy}}).Serve(ctx, provider)
	}()
	registry := NewRegistry()
	defer registry.Close()
	if _, err := registry.Attach("p", hub); err != nil {
		t.Fatal(err)
	}
	sidecarDone := make(chan error, 1)
	responseSeen := make(chan struct{})
	go func() {
		conn, err := local.Accept()
		if err != nil {
			sidecarDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		codec := protocol.NewCodec(conn, conn)
		if _, err := codec.ReadFrame(); err != nil {
			sidecarDone <- err
			return
		}
		hello, _ := json.Marshal(sidecar.RPCHelloAck{Capabilities: sidecar.SelectiveMPCCapabilities(sidecar.RoleProvider)})
		if err := codec.WriteFrame(protocol.FrameSidecarHelloAck, 0, 0, hello); err != nil {
			sidecarDone <- err
			return
		}
		frame, err := codec.ReadFrame()
		if err != nil {
			sidecarDone <- err
			return
		}
		var command sidecar.RPCCommand
		if json.Unmarshal(frame.Payload, &command) != nil || frame.SessionID != 7 || command.Operation != sidecar.OperationAttachUpstreamChannel {
			sidecarDone <- errors.New("wrong attachment binding")
			return
		}
		result, _ := json.Marshal(sidecar.RPCResult{RequestID: 1, Status: sidecar.RPCStatusOK, Data: json.RawMessage(`{"state":"attached"}`)})
		if err := codec.WriteFrame(protocol.FrameSidecarResult, 0, 7, result); err != nil {
			sidecarDone <- err
			return
		}
		if err := codec.WriteFrame(protocol.FrameSidecarStream, 0, 7, []byte("encrypted-request")); err != nil {
			sidecarDone <- err
			return
		}
		sawACK, sawResponse := false, false
		for range 2 {
			frame, err = codec.ReadFrame()
			if err != nil {
				sidecarDone <- err
				return
			}
			switch frame.Type {
			case protocol.FrameDeliveryAck:
				ack, err := protocol.DecodeDeliveryAck(frame.Payload)
				if err != nil || sawACK || ack.Bytes != 17 || ack.SHA256 != sha256.Sum256([]byte("encrypted-request")) {
					sidecarDone <- errors.New("bad delivery evidence")
					return
				}
				sawACK = true
			case protocol.FrameSidecarStream:
				if sawResponse || string(frame.Payload) != "encrypted-response" {
					sidecarDone <- errors.New("bad response")
					return
				}
				sawResponse = true
			default:
				sidecarDone <- errors.New("unexpected bridge frame")
				return
			}
		}
		if !sawACK || !sawResponse {
			sidecarDone <- errors.New("missing bridge evidence")
			return
		}
		close(responseSeen)
		// Closing the Hub lifetime handle must close this local attachment.
		frame, err = codec.ReadFrame()
		if err == nil && frame.Type == protocol.FrameSidecarStreamEnd {
			_, err = codec.ReadFrame()
		}
		if err == nil {
			sidecarDone <- errors.New("bridge survived lease closure")
			return
		}
		sidecarDone <- nil
	}()
	networkDone := make(chan error, 1)
	go func() {
		conn, err := upstream.Accept()
		if err != nil {
			networkDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
		data := make([]byte, 17)
		if _, err := io.ReadFull(conn, data); err != nil {
			networkDone <- err
			return
		}
		if string(data) != "encrypted-request" {
			networkDone <- errors.New("bad local request")
			return
		}
		_, err = conn.Write([]byte("encrypted-response"))
		networkDone <- err
		var end [1]byte
		_, _ = conn.Read(end[:])
	}()
	control, err := registry.StartProviderBridge(ctx, "p", 7, protocol.Target{Host: host, Port: uint16(port)}, strings.Repeat("a", 64), sidecar.BaselineMPCCapacity())
	if err != nil {
		t.Fatal(err)
	}
	if err := <-networkDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-responseSeen:
	case err := <-sidecarDone:
		t.Fatalf("sidecar: %v", err)
	case <-ctx.Done():
		t.Fatal("sidecar did not receive response")
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-sidecarDone; err != nil {
		t.Fatal(err)
	}
}

func TestLocalBridgeRejectsDisallowedTargetBeforeAttaching(t *testing.T) {
	policy, _ := egress.NewPolicy([]string{BridgeHost}, []uint16{SidecarPort})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	hub, provider := net.Pipe()
	go func() {
		_ = (&tunnel.Provider{Policy: policy, Dialer: AgentDialer{SidecarSocket: "/not-used.sock", Policy: policy}}).Serve(ctx, provider)
	}()
	registry := NewRegistry()
	defer registry.Close()
	_, _ = registry.Attach("p", hub)
	conn, err := registry.StartProviderBridge(ctx, "p", 1, protocol.Target{Host: "blocked.example", Port: 443}, strings.Repeat("a", 64), sidecar.BaselineMPCCapacity())
	if err == nil {
		conn.Close()
		t.Fatal("accepted disallowed target")
	}
}

func TestReservedSidecarPortsDoNotExpandUpstreamEgress(t *testing.T) {
	policy, _ := egress.NewPolicy([]string{"api.example.com"}, []uint16{443})
	dialer := AgentDialer{Policy: policy, SidecarSocket: "/unused.sock"}
	_, err := dialer.DialContext(context.Background(), "tcp", "api.example.com:2")
	if err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("reserved port expanded egress: %v", err)
	}
}

func TestCapacitySocketSelectionDoesNotMixProfiles(t *testing.T) {
	d := AgentDialer{SidecarSocket: "/default.sock", SidecarSockets: map[string]string{"16k": "/16k.sock", "1m": "/1m.sock"}}
	capacity, _ := sidecar.CapacityProfile("16k")
	path, err := d.socketForCapacity(capacity)
	if err != nil || path != "/16k.sock" {
		t.Fatalf("wrong capacity socket: %q %v", path, err)
	}
	capacity.MaxRequestRecords++
	if _, err := d.socketForCapacity(capacity); err == nil {
		t.Fatal("uncommitted capacity accepted")
	}
}
