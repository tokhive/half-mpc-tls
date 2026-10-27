package precompute

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/protocol"
	"tokenhive.local/half-mpc-tls/internal/response"
	"tokenhive.local/half-mpc-tls/internal/sidecar"
)

type forbiddenUpstream struct{}

func (forbiddenUpstream) Open(context.Context, protocol.Target) (net.Conn, error) {
	return nil, errors.New("must not dial upstream on a version mismatch")
}

func TestWarmerRejectsVersionMismatchBeforeCreatingSession(t *testing.T) {
	for _, routeVersion := range []string{sidecar.TLS12, sidecar.TLS13} {
		t.Run(routeVersion, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			directory := t.TempDir()
			done := make(chan error, 2)
			sockets := make([]string, 2)
			for i, role := range []string{sidecar.RoleHub, sidecar.RoleProvider} {
				sockets[i] = filepath.Join(directory, string(role)+".sock")
				listener, err := net.Listen("unix", sockets[i])
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				caps := sidecar.SelectiveMPCCapabilities(role)
				if routeVersion == sidecar.TLS12 {
					caps = sidecar.TLS13CapabilitiesWithCapacity(role, sidecar.BaselineMPCCapacity())
				}
				go func() {
					conn, err := listener.Accept()
					if err != nil {
						done <- err
						return
					}
					defer conn.Close()
					deadline, _ := ctx.Deadline()
					_ = conn.SetDeadline(deadline)
					codec := protocol.NewCodec(conn, conn)
					frame, err := codec.ReadFrame()
					if err != nil {
						done <- err
						return
					}
					if frame.Type != protocol.FrameSidecarHello {
						done <- errors.New("missing hello")
						return
					}
					ack, _ := json.Marshal(sidecar.RPCHelloAck{Capabilities: caps})
					if err := codec.WriteFrame(protocol.FrameSidecarHelloAck, 0, 0, ack); err != nil {
						done <- err
						return
					}
					_, err = codec.ReadFrame()
					if !errors.Is(err, io.EOF) {
						done <- errors.New("version mismatch did not close before commands")
						return
					}
					done <- nil
				}()
			}
			warmer, err := NewSidecarWarmer(SidecarWarmerConfig{HubSocket: sockets[0], ProviderSocket: sockets[1], Upstream: forbiddenUpstream{}})
			if err != nil {
				t.Fatal(err)
			}
			key := testKey()
			key.TLSVersion = routeVersion
			_, err = warmer.Warm(ctx, key)
			if !errors.Is(err, ErrInvalidKey) || !strings.Contains(err.Error(), "TLS version") {
				t.Fatalf("unexpected mismatch result: %v", err)
			}
			for range 2 {
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestTransportFailureUnblocksLeasedResponse(t *testing.T) {
	source, upstream := net.Pipe()
	defer upstream.Close()
	stream, err := response.NewStream(source)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &SidecarSession{ctx: ctx, cancel: cancel, responses: stream}
	s.healthy.Store(true)
	defer s.Close()
	go func() { _, _ = io.WriteString(upstream, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n") }()
	req, _ := http.NewRequest(http.MethodPost, "https://example.com", nil)
	r, err := stream.Next(req)
	if err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { _, err := io.ReadAll(r.Body); finished <- err }()
	s.startTask(func() error { return io.ErrUnexpectedEOF })
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("truncated response accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("lost transport left response blocked")
	}
	if s.Healthy() {
		t.Fatal("failed session remained healthy")
	}
}

func TestImmediateRelayFailureDuringInitializationClosesAllTasks(t *testing.T) {
	for range 100 {
		local, peer := net.Pipe()
		ctx, cancel := context.WithCancel(context.Background())
		s := &SidecarSession{ctx: ctx, cancel: cancel, localBridge: local}
		s.healthy.Store(true)
		// Missing MPC attachments fail immediately, while the lifetime reader can
		// already be blocked. Initialization and failure cleanup must not race Wait.
		s.startTransportTasks()
		done := make(chan struct{})
		go func() { _ = s.Close(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("initialization cleanup stalled")
		}
		_ = peer.Close()
	}
}
