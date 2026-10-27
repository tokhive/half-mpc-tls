package tunnel

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/egress"
	"tokenhive.local/half-mpc-tls/internal/protocol"
)

func TestTunnelRoundTrip(t *testing.T) {
	echoListener := listenTCP(t)
	defer echoListener.Close()
	go serveEcho(echoListener)

	host, portText, err := net.SplitHostPort(echoListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := egress.NewPolicy([]string{host}, []uint16{uint16(port)})
	if err != nil {
		t.Fatal(err)
	}

	hubControl, providerControl := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	provider := &Provider{Policy: policy}
	providerDone := make(chan error, 1)
	go func() { providerDone <- provider.Serve(ctx, providerControl) }()

	client := NewClient(hubControl)
	defer client.Close()
	openCtx, openCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer openCancel()
	conn, err := client.Open(openCtx, protocol.Target{Host: host, Port: uint16(port)})
	if err != nil {
		t.Fatalf("open tunnel: %v", err)
	}
	defer conn.Close()

	message := []byte("tokenhive tunnel")
	if _, err := conn.Write(message); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	response := make([]byte, len(message))
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if string(response) != string(message) {
		t.Fatalf("unexpected response %q", response)
	}
}

func TestTunnelRejectsDisallowedTarget(t *testing.T) {
	policy, err := egress.NewPolicy([]string{"allowed.example"}, []uint16{443})
	if err != nil {
		t.Fatal(err)
	}
	hubControl, providerControl := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = (&Provider{Policy: policy}).Serve(ctx, providerControl) }()

	client := NewClient(hubControl)
	defer client.Close()
	openCtx, openCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer openCancel()
	_, err = client.Open(openCtx, protocol.Target{Host: "blocked.example", Port: 443})
	if err == nil {
		t.Fatal("expected disallowed target to fail")
	}
}

func TestTunnelDrainsDataBeforeEOF(t *testing.T) {
	listener := listenTCP(t)
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("final response bytes"))
		_ = conn.Close()
	}()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := egress.NewPolicy([]string{host}, []uint16{uint16(port)})
	if err != nil {
		t.Fatal(err)
	}

	hubControl, providerControl := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = (&Provider{Policy: policy}).Serve(ctx, providerControl) }()
	client := NewClient(hubControl)
	defer client.Close()

	openCtx, openCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer openCancel()
	conn, err := client.Open(openCtx, protocol.Target{Host: host, Port: uint16(port)})
	if err != nil {
		t.Fatal(err)
	}
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if string(response) != "final response bytes" {
		t.Fatalf("unexpected response %q", response)
	}
}

type fixedDialer struct {
	connection net.Conn
}

func (d fixedDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return d.connection, nil
}

func TestTunnelWriteWaitsForCumulativeUpstreamDeliveryAck(t *testing.T) {
	upstreamProxy, upstreamServer := net.Pipe()
	defer upstreamServer.Close()
	policy, err := egress.NewPolicy([]string{"api.example.com"}, []uint16{443})
	if err != nil {
		t.Fatal(err)
	}
	hubControl, providerControl := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = (&Provider{Policy: policy, Dialer: fixedDialer{connection: upstreamProxy}}).Serve(ctx, providerControl)
	}()
	client := NewClient(hubControl)
	defer client.Close()
	openCtx, openCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer openCancel()
	connection, err := client.Open(openCtx, protocol.Target{Host: "api.example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	payload := bytes.Repeat([]byte{0x5a}, protocol.MaxDataFrameSize*2+17)
	writeDone := make(chan error, 1)
	go func() {
		written, writeErr := connection.Write(payload)
		if writeErr == nil && written != len(payload) {
			writeErr = io.ErrShortWrite
		}
		writeDone <- writeErr
	}()

	select {
	case err := <-writeDone:
		t.Fatalf("write returned before upstream consumed bytes: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(upstreamServer, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) {
		t.Fatal("upstream bytes do not match tunnel write")
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write did not complete after cumulative delivery ACK")
	}
}

func TestTunnelRejectsDeliveryAckWithWrongCumulativeHash(t *testing.T) {
	hubControl, fakeProvider := net.Pipe()
	client := NewClient(hubControl)
	defer client.Close()
	providerDone := make(chan error, 1)
	go func() {
		codec := protocol.NewCodec(fakeProvider, fakeProvider)
		open, err := codec.ReadFrame()
		if err != nil {
			providerDone <- err
			return
		}
		if open.Type != protocol.FrameOpen {
			providerDone <- errors.New("expected open frame")
			return
		}
		if err := codec.WriteFrame(protocol.FrameOpened, 0, open.SessionID, nil); err != nil {
			providerDone <- err
			return
		}
		data, err := codec.ReadFrame()
		if err != nil {
			providerDone <- err
			return
		}
		wrongDigest := sha256.Sum256([]byte("different TLS bytes"))
		ack, err := protocol.EncodeDeliveryAck(protocol.DeliveryAck{
			Bytes:  uint64(len(data.Payload)),
			SHA256: wrongDigest,
		})
		if err != nil {
			providerDone <- err
			return
		}
		providerDone <- codec.WriteFrame(protocol.FrameDeliveryAck, 0, open.SessionID, ack)
	}()

	openCtx, openCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer openCancel()
	connection, err := client.Open(openCtx, protocol.Target{Host: "api.example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Write([]byte("TLS ciphertext")); !errors.Is(err, protocol.ErrInvalidFrame) {
		t.Fatalf("expected invalid ACK rejection, got %v", err)
	}
	if err := <-providerDone; err != nil {
		t.Fatal(err)
	}
}

func listenTCP(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return listener
}

func serveEcho(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}

func ExampleClient() {
	fmt.Println("Hub opens logical net.Conn instances through a Provider control connection")
	// Output: Hub opens logical net.Conn instances through a Provider control connection
}

func TestBufferedWritesPipelineAndExplicitDeliveryBarrier(t *testing.T) {
	upstream, server := net.Pipe()
	defer server.Close()
	policy, _ := egress.NewPolicy([]string{"api.example.com"}, []uint16{443})
	hub, provider := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _ = (&Provider{Policy: policy, Dialer: fixedDialer{upstream}}).Serve(ctx, provider) }()
	client := NewClient(hub)
	defer client.Close()
	conn, err := client.OpenBuffered(ctx, protocol.Target{Host: "api.example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	// Neither write waits for the destination to read. This also models a
	// framed protocol writing its header before its body.
	if _, err := conn.Write([]byte("head")); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("body")); err != nil {
		t.Fatal(err)
	}
	barrier := make(chan error, 1)
	go func() { barrier <- conn.(interface{ FlushDelivery() error }).FlushDelivery() }()
	select {
	case err := <-barrier:
		t.Fatalf("premature delivery: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	data := make([]byte, 8)
	if _, err := io.ReadFull(server, data); err != nil {
		t.Fatal(err)
	}
	if string(data) != "headbody" {
		t.Fatalf("bad stream: %q", data)
	}
	if err := <-barrier; err != nil {
		t.Fatal(err)
	}
}

func TestBufferedWindowBoundsUnacknowledgedFrames(t *testing.T) {
	upstream, server := net.Pipe()
	defer server.Close()
	policy, _ := egress.NewPolicy([]string{"api.example.com"}, []uint16{443})
	hub, provider := net.Pipe()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() { _ = (&Provider{Policy: policy, Dialer: fixedDialer{upstream}}).Serve(ctx, provider) }()
	client := NewClient(hub)
	defer client.Close()
	conn, err := client.OpenBuffered(ctx, protocol.Target{Host: "api.example.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	for range deliveryWindowFrames {
		if _, err := conn.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
	}
	next := make(chan error, 1)
	go func() { _, err := conn.Write([]byte{2}); next <- err }()
	select {
	case err := <-next:
		t.Fatalf("window did not block: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	var first [1]byte
	if _, err := io.ReadFull(server, first[:]); err != nil {
		t.Fatal(err)
	}
	if err := <-next; err != nil {
		t.Fatal(err)
	}
}
