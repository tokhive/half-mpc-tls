package providerconn

import (
	"encoding/binary"
	"errors"
	"io"
)

const DefaultDataTunnels = 32
const MaxDataTunnels = 256

// WriteDataHello runs inside the already authenticated mTLS channel. Slots
// identify independent byte streams; they never establish Provider identity.
func WriteDataHello(w io.Writer, slot uint16) error {
	if slot >= MaxDataTunnels {
		return errors.New("invalid data tunnel slot")
	}
	packet := []byte{'T', 'H', 'D', '1', 0, 0}
	binary.BigEndian.PutUint16(packet[4:], slot)
	for len(packet) > 0 {
		n, err := w.Write(packet)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		packet = packet[n:]
	}
	return nil
}

func ReadDataHello(r io.Reader) (uint16, error) {
	var packet [6]byte
	if _, err := io.ReadFull(r, packet[:]); err != nil {
		return 0, err
	}
	slot := binary.BigEndian.Uint16(packet[4:])
	if string(packet[:4]) != "THD1" || slot >= MaxDataTunnels {
		return 0, errors.New("invalid data tunnel hello")
	}
	return slot, nil
}
