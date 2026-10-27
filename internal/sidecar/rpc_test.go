package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/protocol"
)

func TestRPCClientHandshakeAndCommand(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})

	serverDone := make(chan error, 1)
	go func() {
		codec := protocol.NewCodec(serverConn, serverConn)
		frame, err := codec.ReadFrame()
		if err != nil {
			serverDone <- err
			return
		}
		if frame.Type != protocol.FrameSidecarHello || frame.SessionID != 0 {
			serverDone <- errors.New("unexpected hello frame")
			return
		}
		var hello RPCHello
		if err := decodeStrictJSON(frame.Payload, &hello); err != nil {
			serverDone <- err
			return
		}
		ack, err := json.Marshal(RPCHelloAck{
			Capabilities: SelectiveMPCCapabilities(RoleHub),
		})
		if err != nil {
			serverDone <- err
			return
		}
		if err := codec.WriteFrame(protocol.FrameSidecarHelloAck, 0, 0, ack); err != nil {
			serverDone <- err
			return
		}

		frame, err = codec.ReadFrame()
		if err != nil {
			serverDone <- err
			return
		}
		if frame.Type != protocol.FrameSidecarCommand || frame.SessionID != 17 {
			serverDone <- errors.New("unexpected command frame")
			return
		}
		var command RPCCommand
		if err := decodeStrictJSON(frame.Payload, &command); err != nil {
			serverDone <- err
			return
		}
		result, err := json.Marshal(RPCResult{
			RequestID: command.RequestID,
			Status:    RPCStatusOK,
		})
		if err != nil {
			serverDone <- err
			return
		}
		serverDone <- codec.WriteFrame(protocol.FrameSidecarResult, 0, frame.SessionID, result)
	}()

	client, err := NewRPCClient(protocol.NewCodec(clientConn, clientConn), RoleHub)
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := client.Handshake()
	if err != nil {
		t.Fatal(err)
	}
	if capabilities.Role != RoleHub {
		t.Fatalf("unexpected role %q", capabilities.Role)
	}
	if err := client.WriteCommand(17, RPCCommand{
		RequestID: 23,
		Operation: OperationCreateSession,
		Params:    json.RawMessage(`{"upstream":"api.example.com"}`),
	}); err != nil {
		t.Fatal(err)
	}
	result, err := client.ReadResult(17, 23)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != RPCStatusOK {
		t.Fatalf("unexpected status %q", result.Status)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestRPCClientRejectsWrongRoleOperation(t *testing.T) {
	client := &RPCClient{
		codec:        protocol.NewCodec(nil, nil),
		expectedRole: RoleHub,
		ready:        true,
	}
	err := client.WriteCommand(1, RPCCommand{
		RequestID: 1,
		Operation: OperationBindCredential,
		Params:    json.RawMessage(`{}`),
	})
	if !errors.Is(err, ErrRPCRole) {
		t.Fatalf("expected role error, got %v", err)
	}
}

func TestDecodeStrictJSONRejectsUnknownField(t *testing.T) {
	var hello RPCHello
	err := decodeStrictJSON([]byte(`{"protocol_version":1,"expected_role":"hub","extra":true}`), &hello)
	if err == nil {
		t.Fatal("expected unknown field rejection")
	}
}

func TestRPCClientWritesBoundedStream(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	client := &RPCClient{
		codec:        protocol.NewCodec(clientConn, clientConn),
		expectedRole: RoleHub,
		ready:        true,
	}
	input := bytes.Repeat([]byte{0x5a}, protocol.MaxDataFrameSize+7)
	done := make(chan error, 1)
	go func() {
		codec := protocol.NewCodec(serverConn, serverConn)
		first, err := codec.ReadFrame()
		if err != nil {
			done <- err
			return
		}
		second, err := codec.ReadFrame()
		if err != nil {
			done <- err
			return
		}
		end, err := codec.ReadFrame()
		if err != nil {
			done <- err
			return
		}
		if first.Type != protocol.FrameSidecarStream || second.Type != protocol.FrameSidecarStream ||
			end.Type != protocol.FrameSidecarStreamEnd || first.SessionID != 8 || second.SessionID != 8 ||
			end.SessionID != 8 || len(first.Payload)+len(second.Payload) != len(input) {
			done <- errors.New("unexpected stream frame sequence")
			return
		}
		done <- nil
	}()
	if err := client.WriteStream(8, bytes.NewReader(input)); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRPCClientRejectsUnstableCancellationReason(t *testing.T) {
	client := &RPCClient{
		codec:        protocol.NewCodec(nil, nil),
		expectedRole: RoleHub,
		ready:        true,
	}
	if err := client.WriteCancel(1, "contains secret detail"); !errors.Is(err, ErrRPCProtocol) {
		t.Fatalf("expected protocol error, got %v", err)
	}
}

func TestAttachmentTranslatesFullDuplexFrames(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	attachment := &Attachment{
		codec:     protocol.NewCodec(clientConn, clientConn),
		closer:    clientConn,
		sessionID: 44,
	}
	input := bytes.Repeat([]byte{0x31}, protocol.MaxDataFrameSize+9)
	serverDone := make(chan error, 1)
	go func() {
		codec := protocol.NewCodec(serverConn, serverConn)
		var received []byte
		for len(received) < len(input) {
			frame, err := codec.ReadFrame()
			if err != nil {
				serverDone <- err
				return
			}
			if frame.Type != protocol.FrameSidecarStream || frame.SessionID != 44 {
				serverDone <- errors.New("unexpected attachment input frame")
				return
			}
			received = append(received, frame.Payload...)
		}
		if !bytes.Equal(received, input) {
			serverDone <- errors.New("attachment input mismatch")
			return
		}
		end, err := codec.ReadFrame()
		if err != nil {
			serverDone <- err
			return
		}
		if end.Type != protocol.FrameSidecarStreamEnd || end.SessionID != 44 || len(end.Payload) != 0 {
			serverDone <- errors.New("unexpected attachment input end")
			return
		}
		if err := codec.WriteFrame(protocol.FrameSidecarStream, 0, 44, []byte("response")); err != nil {
			serverDone <- err
			return
		}
		if err := codec.WriteFrame(protocol.FrameSidecarStreamEnd, 0, 44, nil); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	written, err := attachment.Write(input)
	if err != nil || written != len(input) {
		t.Fatalf("write attachment: written=%d err=%v", written, err)
	}
	if err := attachment.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := attachment.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("expected closed pipe after CloseWrite, got %v", err)
	}
	response, err := io.ReadAll(attachment)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "response" {
		t.Fatalf("unexpected response %q", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}

func TestAttachmentAbortUnblocksConcurrentWrite(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer serverConn.Close()
	attachment := &Attachment{
		codec:     protocol.NewCodec(clientConn, clientConn),
		closer:    clientConn,
		sessionID: 46,
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := attachment.Write(bytes.Repeat([]byte{0x7a}, protocol.MaxDataFrameSize))
		writeDone <- err
	}()
	time.Sleep(10 * time.Millisecond)
	abortDone := make(chan error, 1)
	go func() { abortDone <- attachment.Abort() }()
	select {
	case <-time.After(time.Second):
		t.Fatal("Abort blocked behind a concurrent attachment write")
	case <-abortDone:
	}
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("blocked attachment write unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("attachment write did not unblock after Abort")
	}
	if _, err := attachment.Write([]byte("late")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("write after Abort error = %v", err)
	}
}

func TestRelaySidecarToUpstreamAcknowledgesOnlyAfterWrite(t *testing.T) {
	attachmentConn, sidecarConn := net.Pipe()
	upstreamConn, upstreamPeer := net.Pipe()
	t.Cleanup(func() {
		_ = attachmentConn.Close()
		_ = sidecarConn.Close()
		_ = upstreamConn.Close()
		_ = upstreamPeer.Close()
	})
	attachment := &Attachment{
		codec:     protocol.NewCodec(attachmentConn, attachmentConn),
		closer:    attachmentConn,
		sessionID: 45,
		operation: OperationAttachUpstreamChannel,
	}
	ciphertext := []byte("tls record ciphertext")
	acknowledged := make(chan protocol.DeliveryAck, 1)
	sidecarDone := make(chan error, 1)
	go func() {
		codec := protocol.NewCodec(sidecarConn, sidecarConn)
		if err := codec.WriteFrame(protocol.FrameSidecarStream, 0, 45, ciphertext); err != nil {
			sidecarDone <- err
			return
		}
		frame, err := codec.ReadFrame()
		if err != nil {
			sidecarDone <- err
			return
		}
		if frame.Type != protocol.FrameDeliveryAck || frame.Flags != 0 || frame.SessionID != 45 {
			sidecarDone <- errors.New("unexpected delivery ACK frame")
			return
		}
		ack, err := protocol.DecodeDeliveryAck(frame.Payload)
		if err != nil {
			sidecarDone <- err
			return
		}
		acknowledged <- ack
		sidecarDone <- codec.WriteFrame(protocol.FrameSidecarStreamEnd, 0, 45, nil)
	}()

	relayDone := make(chan error, 1)
	go func() {
		relayDone <- relaySidecarToUpstream(attachment, upstreamConn)
	}()
	select {
	case ack := <-acknowledged:
		t.Fatalf("delivery was acknowledged before upstream consumed it: %+v", ack)
	case <-time.After(20 * time.Millisecond):
	}
	received := make([]byte, len(ciphertext))
	if _, err := io.ReadFull(upstreamPeer, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, ciphertext) {
		t.Fatalf("unexpected upstream bytes %q", received)
	}
	ack := <-acknowledged
	if ack.Bytes != uint64(len(ciphertext)) || ack.SHA256 != sha256.Sum256(ciphertext) {
		t.Fatalf("unexpected delivery ACK: %+v", ack)
	}
	if err := <-sidecarDone; err != nil {
		t.Fatal(err)
	}
	if err := <-relayDone; err != nil {
		t.Fatal(err)
	}
}

func TestDialAttachmentRejectsInvalidTokenBeforeDial(t *testing.T) {
	_, err := DialAttachment(
		context.Background(),
		"/does/not/matter",
		RoleHub,
		1,
		1,
		OperationAttachMPCChannel,
		"not-a-token",
	)
	if !errors.Is(err, ErrRPCProtocol) {
		t.Fatalf("expected protocol error, got %v", err)
	}
}
