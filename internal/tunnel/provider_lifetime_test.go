package tunnel

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/egress"
	"tokenhive.local/half-mpc-tls/internal/protocol"
)

// An Agent keeps its parent context alive across many one-shot data tunnels.
// Retired tunnels must not retain a watcher (and its TLS connection) until the
// Agent itself shuts down.
func TestProviderRetiredConnectionsReleaseWatchers(t *testing.T) {
	policy, err := egress.NewPolicy([]string{"allowed.example"}, []uint16{443})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	baseline := runtime.NumGoroutine()
	for range 128 {
		peer, connection := net.Pipe()
		_ = peer.Close()
		err := (&Provider{Policy: policy}).Serve(ctx, connection)
		_ = connection.Close()
		if !errors.Is(err, io.EOF) {
			t.Fatalf("closed peer: %v", err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for runtime.NumGoroutine() > baseline+8 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if retained := runtime.NumGoroutine() - baseline; retained > 8 {
		t.Fatalf("128 retired connections retained %d goroutines while parent remains live", retained)
	}
}

func TestProviderCancellationUnblocksIdleConnection(t *testing.T) {
	policy, err := egress.NewPolicy([]string{"allowed.example"}, []uint16{443})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peer, connection := net.Pipe()
	defer peer.Close()
	defer connection.Close()
	done := make(chan error, 1)
	go func() { done <- (&Provider{Policy: policy}).Serve(ctx, connection) }()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled Provider remains blocked reading an idle connection")
	}
}

type pendingDialer struct {
	started   chan struct{}
	cancelled chan struct{}
}

func (d pendingDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	close(d.started)
	<-ctx.Done()
	close(d.cancelled)
	return nil, ctx.Err()
}

func TestProviderDisconnectCancelsPendingDial(t *testing.T) {
	policy, err := egress.NewPolicy([]string{"allowed.example"}, []uint16{443})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	peer, connection := net.Pipe()
	defer peer.Close()
	defer connection.Close()
	dialer := pendingDialer{started: make(chan struct{}), cancelled: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- (&Provider{Policy: policy, Dialer: dialer}).Serve(ctx, connection) }()
	payload, err := protocol.EncodeTarget(protocol.Target{Host: "allowed.example", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if err := protocol.NewCodec(peer, peer).WriteFrame(protocol.FrameOpen, 0, 1, payload); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dialer.started:
	case <-time.After(time.Second):
		t.Fatal("Provider did not start upstream dial")
	}
	_ = peer.Close()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("disconnected tunnel: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Provider did not finish disconnect cleanup")
	}
	select {
	case <-dialer.cancelled:
	default:
		t.Fatal("upstream dial outlived its disconnected tunnel")
	}
}
