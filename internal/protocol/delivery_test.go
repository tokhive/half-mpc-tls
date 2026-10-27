package protocol

import (
	"crypto/sha256"
	"errors"
	"testing"
)

func TestDeliveryAckRoundTripAndStrictLength(t *testing.T) {
	digest := sha256.Sum256([]byte("TLS records"))
	expected := DeliveryAck{Bytes: 1234, SHA256: digest}
	payload, err := EncodeDeliveryAck(expected)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := DecodeDeliveryAck(payload)
	if err != nil {
		t.Fatal(err)
	}
	if actual != expected {
		t.Fatalf("ACK = %+v, want %+v", actual, expected)
	}
	for _, invalid := range [][]byte{nil, make([]byte, DeliveryAckPayloadSize-1), make([]byte, DeliveryAckPayloadSize)} {
		if _, err := DecodeDeliveryAck(invalid); !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("expected invalid ACK rejection, got %v", err)
		}
	}
}
