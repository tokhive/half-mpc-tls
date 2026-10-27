package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const DeliveryAckPayloadSize = 8 + sha256.Size

type DeliveryAck struct {
	Bytes  uint64
	SHA256 [sha256.Size]byte
}

func EncodeDeliveryAck(ack DeliveryAck) ([]byte, error) {
	if ack.Bytes == 0 {
		return nil, fmt.Errorf("%w: delivery ACK byte count is zero", ErrInvalidFrame)
	}
	payload := make([]byte, DeliveryAckPayloadSize)
	binary.BigEndian.PutUint64(payload[:8], ack.Bytes)
	copy(payload[8:], ack.SHA256[:])
	return payload, nil
}

func DecodeDeliveryAck(payload []byte) (DeliveryAck, error) {
	if len(payload) != DeliveryAckPayloadSize {
		return DeliveryAck{}, fmt.Errorf("%w: delivery ACK payload length", ErrInvalidFrame)
	}
	ack := DeliveryAck{Bytes: binary.BigEndian.Uint64(payload[:8])}
	if ack.Bytes == 0 {
		return DeliveryAck{}, fmt.Errorf("%w: delivery ACK byte count is zero", ErrInvalidFrame)
	}
	copy(ack.SHA256[:], payload[8:])
	return ack, nil
}
