package tunnel

import (
	"context"
	"crypto/sha256"
	"io"
	"net"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/protocol"
)

// This isolates application ACK serialization using a synthetic 10ms delivery
// delay. It is not an MPC or Internet benchmark. Both paths wait for final ACK.
func BenchmarkDeliveryPipeline(b *testing.B) {
	for _, buffered := range []bool{false, true} {
		name := "per-write-ack"
		if buffered {
			name = "windowed-ack"
		}
		b.Run(name, func(b *testing.B) {
			hub, provider := net.Pipe()
			done := make(chan struct{})
			defer close(done)
			defer provider.Close()
			type queuedACK struct {
				id   uint64
				data []byte
				at   time.Time
			}
			queue := make(chan queuedACK, 32)
			codec := protocol.NewCodec(provider, provider)
			go func() {
				for {
					select {
					case item := <-queue:
						timer := time.NewTimer(max(time.Until(item.at), 0))
						select {
						case <-timer.C:
						case <-done:
							timer.Stop()
							return
						}
						if codec.WriteFrame(protocol.FrameDeliveryAck, 0, item.id, item.data) != nil {
							return
						}
					case <-done:
						return
					}
				}
			}()
			go func() {
				digest := sha256.New()
				var total uint64
				for {
					frame, err := codec.ReadFrame()
					if err != nil {
						return
					}
					switch frame.Type {
					case protocol.FrameOpen:
						if codec.WriteFrame(protocol.FrameOpened, 0, frame.SessionID, nil) != nil {
							return
						}
					case protocol.FrameData:
						total += uint64(len(frame.Payload))
						_, _ = digest.Write(frame.Payload)
						var sum [32]byte
						copy(sum[:], digest.Sum(nil))
						payload, _ := protocol.EncodeDeliveryAck(protocol.DeliveryAck{Bytes: total, SHA256: sum})
						select {
						case queue <- queuedACK{frame.SessionID, payload, time.Now().Add(10 * time.Millisecond)}:
						case <-done:
							return
						}
					}
				}
			}()
			client := NewClient(hub)
			defer client.Close()
			var conn net.Conn
			var err error
			if buffered {
				conn, err = client.OpenBuffered(context.Background(), protocol.Target{Host: "fixture", Port: 443})
			} else {
				conn, err = client.Open(context.Background(), protocol.Target{Host: "fixture", Port: 443})
			}
			if err != nil {
				b.Fatal(err)
			}
			_ = conn.SetDeadline(time.Now().Add(time.Minute))
			payload := make([]byte, 1024)
			b.SetBytes(32 * int64(len(payload)))
			b.ResetTimer()
			for range b.N {
				for range 32 {
					if n, err := conn.Write(payload); err != nil || n != len(payload) {
						if err == nil {
							err = io.ErrShortWrite
						}
						b.Fatal(err)
					}
				}
				if err := conn.(interface{ FlushDelivery() error }).FlushDelivery(); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
		})
	}
}
