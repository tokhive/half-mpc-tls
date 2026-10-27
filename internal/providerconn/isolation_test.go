package providerconn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/protocol"
)

func TestReservationsIsolateBlockedBackgroundTraffic(t *testing.T) {
	registry := NewRegistry()
	defer registry.Close()
	peers := make([]net.Conn, 2)
	for slot := range peers {
		hub, peer := net.Pipe()
		peers[slot] = peer
		defer peer.Close()
		if _, err := registry.AttachSlot("provider-1", uint16(slot), hub); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	backgroundCtx, releaseBackground, err := registry.ReserveProvider(ctx, "provider-1")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseBackground()
	onlineCtx, releaseOnline, err := registry.ReserveProvider(ctx, "provider-1")
	if err != nil {
		t.Fatal(err)
	}
	defer releaseOnline()
	if _, _, err := registry.ReserveProvider(ctx, "provider-1"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("exhaustion must not share a reserved tunnel: %v", err)
	}
	// Fill one session's inbound queue until its physical read loop stops.
	blocked := make(chan struct{})
	backgroundDone := make(chan error, 1)
	go func() {
		codec := protocol.NewCodec(peers[0], peers[0])
		open, err := codec.ReadFrame()
		if err == nil {
			err = codec.WriteFrame(protocol.FrameOpened, 0, open.SessionID, nil)
		}
		for i := 0; err == nil && i < 17; i++ {
			err = codec.WriteFrame(protocol.FrameData, 0, open.SessionID, []byte("background"))
		}
		close(blocked)
		if err == nil {
			err = codec.WriteFrame(protocol.FrameData, 0, open.SessionID, []byte("blocked"))
		}
		backgroundDone <- err
	}()
	background, err := registry.DialProviderSidecar(backgroundCtx, "provider-1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { releaseBackground(); _ = background.Close() }()
	select {
	case <-blocked:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-backgroundDone:
		t.Fatalf("background connection did not block: %v", err)
	default:
	}
	onlineDone := make(chan error, 1)
	go func() {
		codec := protocol.NewCodec(peers[1], peers[1])
		open, err := codec.ReadFrame()
		if err == nil {
			err = codec.WriteFrame(protocol.FrameOpened, 0, open.SessionID, nil)
		}
		if err == nil {
			frame, readErr := codec.ReadFrame()
			err = readErr
			if err == nil {
				digest := sha256.Sum256(frame.Payload)
				ack, _ := protocol.EncodeDeliveryAck(protocol.DeliveryAck{Bytes: uint64(len(frame.Payload)), SHA256: digest})
				err = codec.WriteFrame(protocol.FrameDeliveryAck, 0, open.SessionID, ack)
			}
		}
		if err == nil {
			err = codec.WriteFrame(protocol.FrameData, 0, open.SessionID, []byte("online"))
		}
		onlineDone <- err
	}()
	online, err := registry.DialProviderSidecar(onlineCtx, "provider-1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { releaseOnline(); _ = online.Close() }()
	_ = online.SetDeadline(time.Now().Add(time.Second))
	if _, err := online.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := online.(interface{ FlushDelivery() error }).FlushDelivery(); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 6)
	if _, err := io.ReadFull(online, reply); err != nil || string(reply) != "online" {
		t.Fatalf("online blocked: %q %v", reply, err)
	}
	if err := <-onlineDone; err != nil {
		t.Fatal(err)
	}
	releaseBackground()
	select {
	case <-backgroundDone:
	case <-ctx.Done():
		t.Fatal("reservation release did not unblock transport")
	}
	// Release physical transports before deferred logical Close writes.
	releaseOnline()
}

func TestReservationCannotMigrateOrReleaseNewGeneration(t *testing.T) {
	registry := NewRegistry()
	defer registry.Close()
	oldHub, oldPeer := net.Pipe()
	defer oldPeer.Close()
	if _, err := registry.AttachSlot("provider-1", 4, oldHub); err != nil {
		t.Fatal(err)
	}
	pinned, release, err := registry.ReserveProvider(context.Background(), "provider-1")
	if err != nil {
		t.Fatal(err)
	}
	newHub, newPeer := net.Pipe()
	defer newPeer.Close()
	generation, err := registry.AttachSlot("provider-1", 4, newHub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.DialProviderSidecar(pinned, "provider-1"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("old session migrated: %v", err)
	}
	release()
	release()
	select {
	case <-registry.DoneSlot("provider-1", 4, generation):
		t.Fatal("old release removed new connection")
	default:
	}
	newCtx, newRelease, err := registry.ReserveProvider(context.Background(), "provider-1")
	if err != nil {
		t.Fatal(err)
	}
	defer newRelease()
	if registry.client(newCtx, "provider-2") != nil {
		t.Fatal("reservation crossed Provider identity")
	}
	if NewRegistry().client(newCtx, "provider-1") != nil {
		t.Fatal("reservation crossed registry")
	}
	registry.Close()
	postClose, postClosePeer := net.Pipe()
	defer postClose.Close()
	defer postClosePeer.Close()
	if _, err := registry.Attach("provider-1", postClose); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("attach after close: %v", err)
	}
}

type byteWriter struct{ bytes.Buffer }

func (w *byteWriter) Write(p []byte) (int, error) { return w.Buffer.Write(p[:1]) }

func TestDataHelloFramingAndRejections(t *testing.T) {
	for _, slot := range []uint16{0, 31, 255} {
		var wire byteWriter
		if err := WriteDataHello(&wire, slot); err != nil {
			t.Fatal(err)
		}
		got, err := ReadDataHello(bytes.NewReader(wire.Bytes()))
		if err != nil || got != slot {
			t.Fatalf("slot %d: %d %v", slot, got, err)
		}
	}
	for _, packet := range [][]byte{[]byte("THD1"), []byte("BAD!\x00\x00"), []byte("THD1\x01\x00")} {
		if _, err := ReadDataHello(bytes.NewReader(packet)); err == nil {
			t.Fatalf("accepted malformed hello %x", packet)
		}
	}
	if err := WriteDataHello(io.Discard, 256); err == nil {
		t.Fatal("accepted out-of-range slot")
	}
}
