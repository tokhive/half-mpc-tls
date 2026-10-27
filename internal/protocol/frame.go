package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	Version                = 1
	MaxPayloadSize         = 1 << 20
	MaxDataFrameSize       = 64 << 10
	MaxAgentControlPayload = 16 << 10
	headerSize             = 28
	frameMagic             = uint32(0x54485631) // THV1
)

type FrameType uint8

const (
	FrameOpen FrameType = iota + 1
	FrameOpened
	FrameData
	FrameEOF
	FrameClose
	FrameError
	FramePing
	FramePong
	FrameSidecarHello
	FrameSidecarHelloAck
	FrameSidecarCommand
	FrameSidecarResult
	FrameSidecarStream
	FrameSidecarStreamEnd
	FrameSidecarCancel
	FrameDeliveryAck
	FrameAgentHello
	FrameAgentHelloAck
	FrameAgentHeartbeat
	FrameAgentHeartbeatAck
)

func (t FrameType) valid() bool {
	return t >= FrameOpen && t <= FrameAgentHeartbeatAck
}

func (t FrameType) maxPayloadSize() int {
	if t == FrameData || t == FrameSidecarStream {
		return MaxDataFrameSize
	}
	if t >= FrameAgentHello && t <= FrameAgentHeartbeatAck {
		return MaxAgentControlPayload
	}
	return MaxPayloadSize
}

type Frame struct {
	Type      FrameType
	Flags     uint16
	SessionID uint64
	Sequence  uint64
	Payload   []byte
}

var (
	ErrInvalidFrame    = errors.New("invalid control frame")
	ErrSequence        = errors.New("unexpected control frame sequence")
	ErrPayloadTooLarge = errors.New("control frame payload too large")
)

// Codec serializes writes and reads independently. Exactly one logical reader
// should consume frames; any number of goroutines may write them.
type Codec struct {
	r io.Reader
	w io.Writer

	readMu  sync.Mutex
	writeMu sync.Mutex
	recvSeq uint64
	sendSeq uint64
}

func NewCodec(r io.Reader, w io.Writer) *Codec {
	return &Codec{r: r, w: w}
}

func (c *Codec) WriteFrame(frameType FrameType, flags uint16, sessionID uint64, payload []byte) error {
	if !frameType.valid() {
		return fmt.Errorf("%w: type %d", ErrInvalidFrame, frameType)
	}
	if len(payload) > frameType.maxPayloadSize() {
		return fmt.Errorf("%w: %d", ErrPayloadTooLarge, len(payload))
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.sendSeq++
	header := make([]byte, headerSize+len(payload))
	binary.BigEndian.PutUint32(header[0:4], frameMagic)
	header[4] = Version
	header[5] = byte(frameType)
	binary.BigEndian.PutUint16(header[6:8], flags)
	binary.BigEndian.PutUint64(header[8:16], sessionID)
	binary.BigEndian.PutUint64(header[16:24], c.sendSeq)
	binary.BigEndian.PutUint32(header[24:28], uint32(len(payload)))

	copy(header[headerSize:], payload)
	if err := writeAll(c.w, header); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

func (c *Codec) ReadFrame() (Frame, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	header := make([]byte, headerSize)
	if _, err := io.ReadFull(c.r, header); err != nil {
		return Frame{}, fmt.Errorf("read frame header: %w", err)
	}
	if binary.BigEndian.Uint32(header[0:4]) != frameMagic || header[4] != Version {
		return Frame{}, fmt.Errorf("%w: magic or version", ErrInvalidFrame)
	}

	frameType := FrameType(header[5])
	if !frameType.valid() {
		return Frame{}, fmt.Errorf("%w: type %d", ErrInvalidFrame, frameType)
	}

	sequence := binary.BigEndian.Uint64(header[16:24])
	if sequence != c.recvSeq+1 {
		return Frame{}, fmt.Errorf("%w: got %d, want %d", ErrSequence, sequence, c.recvSeq+1)
	}

	payloadSize := binary.BigEndian.Uint32(header[24:28])
	if uint64(payloadSize) > uint64(frameType.maxPayloadSize()) {
		return Frame{}, fmt.Errorf("%w: %d", ErrPayloadTooLarge, payloadSize)
	}

	payload := make([]byte, payloadSize)
	if _, err := io.ReadFull(c.r, payload); err != nil {
		return Frame{}, fmt.Errorf("read frame payload: %w", err)
	}
	c.recvSeq = sequence

	return Frame{
		Type:      frameType,
		Flags:     binary.BigEndian.Uint16(header[6:8]),
		SessionID: binary.BigEndian.Uint64(header[8:16]),
		Sequence:  sequence,
		Payload:   payload,
	}, nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
