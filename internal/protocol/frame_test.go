package protocol

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	var wire bytes.Buffer
	writer := NewCodec(nil, &wire)
	if err := writer.WriteFrame(FrameData, 7, 42, []byte("payload")); err != nil {
		t.Fatalf("write frame: %v", err)
	}

	reader := NewCodec(&wire, nil)
	frame, err := reader.ReadFrame()
	if err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if frame.Type != FrameData || frame.Flags != 7 || frame.SessionID != 42 || frame.Sequence != 1 {
		t.Fatalf("unexpected frame metadata: %+v", frame)
	}
	if string(frame.Payload) != "payload" {
		t.Fatalf("unexpected payload: %q", frame.Payload)
	}
}

func TestCodecRejectsSequenceGap(t *testing.T) {
	var wire bytes.Buffer
	writer := NewCodec(nil, &wire)
	if err := writer.WriteFrame(FramePing, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteFrame(FramePong, 0, 0, nil); err != nil {
		t.Fatal(err)
	}

	data := wire.Bytes()
	data = data[headerSize:]
	reader := NewCodec(bytes.NewReader(data), nil)
	_, err := reader.ReadFrame()
	if !errors.Is(err, ErrSequence) {
		t.Fatalf("expected sequence error, got %v", err)
	}
}

func TestCodecRejectsOversizedPayload(t *testing.T) {
	codec := NewCodec(nil, &bytes.Buffer{})
	err := codec.WriteFrame(FrameData, 0, 1, make([]byte, MaxPayloadSize+1))
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected payload error, got %v", err)
	}
}

func TestCodecRejectsOversizedAgentControlPayload(t *testing.T) {
	codec := NewCodec(bytes.NewReader(nil), io.Discard)
	err := codec.WriteFrame(FrameAgentHello, 0, 0, make([]byte, MaxAgentControlPayload+1))
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected Agent payload limit error, got %v", err)
	}
}

func TestCodecRejectsOversizedDataBeforeWriting(t *testing.T) {
	var wire bytes.Buffer
	codec := NewCodec(nil, &wire)
	err := codec.WriteFrame(FrameSidecarStream, 0, 1, make([]byte, MaxDataFrameSize+1))
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("expected payload error, got %v", err)
	}
	if wire.Len() != 0 {
		t.Fatalf("oversized frame wrote %d bytes", wire.Len())
	}
}

func TestCodecMatchesRustWireVector(t *testing.T) {
	type wireVector struct {
		FrameType  FrameType `json:"frame_type"`
		Flags      uint16    `json:"flags"`
		SessionID  uint64    `json:"session_id"`
		Sequence   uint64    `json:"sequence"`
		PayloadHex string    `json:"payload_hex"`
		WireHex    string    `json:"wire_hex"`
	}
	data, err := os.ReadFile("../../testdata/sidecar-frame-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector wireVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	payload, err := hex.DecodeString(vector.PayloadHex)
	if err != nil {
		t.Fatal(err)
	}
	var wire bytes.Buffer
	codec := NewCodec(nil, &wire)
	if err := codec.WriteFrame(vector.FrameType, vector.Flags, vector.SessionID, payload); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(wire.Bytes()); got != vector.WireHex {
		t.Fatalf("wire mismatch: got %s, want %s", got, vector.WireHex)
	}
	if vector.Sequence != 1 {
		t.Fatalf("fixture must describe first frame, got sequence %d", vector.Sequence)
	}
}
