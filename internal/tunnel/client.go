package tunnel

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"tokenhive.local/half-mpc-tls/internal/protocol"
)

type Client struct {
	conn  net.Conn
	codec *protocol.Codec

	nextSessionID atomic.Uint64
	mu            sync.Mutex
	sessions      map[uint64]*remoteConn
	done          chan struct{}
	closeOnce     sync.Once
	err           error
}

func NewClient(conn net.Conn) *Client {
	client := &Client{
		conn:     conn,
		codec:    protocol.NewCodec(conn, conn),
		sessions: make(map[uint64]*remoteConn),
		done:     make(chan struct{}),
	}
	go client.readLoop()
	return client
}

// Open retains upstream socket-delivery semantics for callers that require it.
func (c *Client) Open(ctx context.Context, target protocol.Target) (net.Conn, error) {
	return c.open(ctx, target, false)
}

// OpenBuffered pipelines sidecar/MPC writes. Protocol responses provide the
// application barrier; FlushDelivery can explicitly wait for remote delivery.
// Outstanding bytes and ACK metadata are bounded even across many small writes.
func (c *Client) OpenBuffered(ctx context.Context, target protocol.Target) (net.Conn, error) {
	return c.open(ctx, target, true)
}

const deliveryWindowBytes = 512 << 10
const deliveryWindowFrames = 8

func (c *Client) open(ctx context.Context, target protocol.Target, buffered bool) (net.Conn, error) {
	payload, err := protocol.EncodeTarget(target)
	if err != nil {
		return nil, err
	}

	sessionID := c.nextSessionID.Add(1)
	stream := newRemoteConn(c, sessionID, target.Address())
	stream.buffered = buffered
	c.mu.Lock()
	select {
	case <-c.done:
		err := c.err
		c.mu.Unlock()
		if err == nil {
			err = net.ErrClosed
		}
		return nil, err
	default:
		c.sessions[sessionID] = stream
		c.mu.Unlock()
	}

	if err := c.codec.WriteFrame(protocol.FrameOpen, 0, sessionID, payload); err != nil {
		c.remove(sessionID)
		stream.finish(err)
		return nil, err
	}

	select {
	case err := <-stream.opened:
		if err != nil {
			c.remove(sessionID)
			stream.finish(err)
			return nil, err
		}
		return stream, nil
	case <-ctx.Done():
		_ = stream.Close()
		return nil, ctx.Err()
	case <-c.done:
		return nil, c.connectionError()
	}
}

func (c *Client) Close() error {
	c.fail(net.ErrClosed)
	return c.conn.Close()
}

// Done closes when the reverse tunnel can no longer carry new sessions.
func (c *Client) Done() <-chan struct{} {
	if c == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return c.done
}

func (c *Client) readLoop() {
	for {
		frame, err := c.codec.ReadFrame()
		if err != nil {
			c.fail(err)
			return
		}

		if frame.Type == protocol.FramePing {
			if err := c.codec.WriteFrame(protocol.FramePong, 0, frame.SessionID, frame.Payload); err != nil {
				c.fail(err)
				return
			}
			continue
		}

		stream := c.get(frame.SessionID)
		if stream == nil {
			continue
		}
		switch frame.Type {
		case protocol.FrameOpened:
			stream.signalOpened(nil)
		case protocol.FrameData:
			if len(frame.Payload) == 0 || len(frame.Payload) > protocol.MaxDataFrameSize {
				c.fail(fmt.Errorf("invalid data frame size %d", len(frame.Payload)))
				return
			}
			if !stream.deliver(frame.Payload) {
				c.remove(frame.SessionID)
			}
		case protocol.FrameDeliveryAck:
			if frame.Flags != 0 {
				c.fail(fmt.Errorf("invalid delivery ACK flags"))
				return
			}
			if err := stream.acknowledge(frame.Payload); err != nil {
				c.fail(err)
				return
			}
		case protocol.FrameEOF:
			c.remove(frame.SessionID)
			stream.finish(io.EOF)
		case protocol.FrameClose:
			c.remove(frame.SessionID)
			stream.finish(net.ErrClosed)
		case protocol.FrameError:
			err := errors.New(string(frame.Payload))
			stream.signalOpened(err)
			c.remove(frame.SessionID)
			stream.finish(err)
		default:
			c.fail(fmt.Errorf("unexpected frame type %d from provider", frame.Type))
			return
		}
	}
}

func (c *Client) get(sessionID uint64) *remoteConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessions[sessionID]
}

func (c *Client) remove(sessionID uint64) {
	c.mu.Lock()
	delete(c.sessions, sessionID)
	c.mu.Unlock()
}

func (c *Client) fail(err error) {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.err = err
		streams := make([]*remoteConn, 0, len(c.sessions))
		for _, stream := range c.sessions {
			streams = append(streams, stream)
		}
		c.sessions = make(map[uint64]*remoteConn)
		close(c.done)
		c.mu.Unlock()
		for _, stream := range streams {
			stream.signalOpened(err)
			stream.finish(err)
		}
		_ = c.conn.Close()
	})
}

func (c *Client) connectionError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	return net.ErrClosed
}

type inbound struct {
	data []byte
}

type remoteConn struct {
	buffered   bool
	owner      *Client
	id         uint64
	remoteAddr net.Addr
	opened     chan error
	inbound    chan inbound
	done       chan struct{}
	closeOnce  sync.Once

	readMu         sync.Mutex
	readBuffer     []byte
	writeMu        sync.Mutex
	deliveryMu     sync.Mutex
	sentHash       hash.Hash
	sentBytes      uint64
	deliveredBytes uint64
	pendingAcks    []protocol.DeliveryAck
	deliveryReady  chan struct{}
	deadlineMu     sync.Mutex
	readDeadline   time.Time
	writeDeadline  time.Time
	finalErr       error
}

func newRemoteConn(owner *Client, id uint64, address string) *remoteConn {
	return &remoteConn{
		owner:         owner,
		id:            id,
		remoteAddr:    tunnelAddr(address),
		opened:        make(chan error, 1),
		inbound:       make(chan inbound, 16),
		done:          make(chan struct{}),
		sentHash:      sha256.New(),
		deliveryReady: make(chan struct{}, 1),
	}
}

func (c *remoteConn) Read(buffer []byte) (int, error) {
	if len(buffer) == 0 {
		return 0, nil
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuffer) == 0 {
		deadline := c.currentReadDeadline()
		timer, timeout := deadlineTimer(deadline)
		select {
		case item := <-c.inbound:
			stopTimer(timer)
			c.readBuffer = item.data
		case <-c.done:
			stopTimer(timer)
			// Data frames are queued before the terminal frame is handled.
			// Drain them before exposing EOF or the terminal error.
			select {
			case item := <-c.inbound:
				c.readBuffer = item.data
				continue
			default:
				return 0, c.readError()
			}
		case <-timeout:
			return 0, timeoutError{}
		}
	}

	n := copy(buffer, c.readBuffer)
	c.readBuffer = c.readBuffer[n:]
	return n, nil
}

func (c *remoteConn) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	select {
	case <-c.done:
		return 0, c.readError()
	default:
	}

	written := 0
	for len(data) > 0 {
		chunkSize := min(len(data), protocol.MaxDataFrameSize)
		deadline := c.currentWriteDeadline()
		if !deadline.IsZero() && time.Now().After(deadline) {
			err := timeoutError{}
			c.abort(err)
			return written, err
		}
		if err := c.waitForWindow(uint64(chunkSize)); err != nil {
			c.abort(err)
			return written, err
		}
		c.deliveryMu.Lock()
		if c.sentBytes > math.MaxUint64-uint64(chunkSize) {
			c.deliveryMu.Unlock()
			err := fmt.Errorf("tunnel delivery counter exhausted")
			c.abort(err)
			return written, err
		}
		c.sentBytes += uint64(chunkSize)
		_, _ = c.sentHash.Write(data[:chunkSize])
		var digest [sha256.Size]byte
		copy(digest[:], c.sentHash.Sum(nil))
		c.pendingAcks = append(c.pendingAcks, protocol.DeliveryAck{Bytes: c.sentBytes, SHA256: digest})
		c.deliveryMu.Unlock()
		// Publish the expected ACK before sending, but never hold deliveryMu
		// across network I/O: the read loop must be able to consume ACKs.
		if err := c.owner.codec.WriteFrame(protocol.FrameData, 0, c.id, data[:chunkSize]); err != nil {
			c.owner.fail(err)
			return written, err
		}
		written += chunkSize
		data = data[chunkSize:]
	}
	if !c.buffered {
		if err := c.flushDelivery(); err != nil {
			c.abort(err)
			return written, err
		}
	}
	return written, nil
}

// FlushDelivery is a barrier for all writes preceding this call.
func (c *remoteConn) FlushDelivery() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.flushDelivery()
}

func (c *remoteConn) flushDelivery() error {
	c.deliveryMu.Lock()
	target := c.sentBytes
	c.deliveryMu.Unlock()
	return c.waitForDelivery(target)
}

func (c *remoteConn) waitForWindow(size uint64) error {
	for {
		c.deliveryMu.Lock()
		if c.sentBytes-c.deliveredBytes+size <= deliveryWindowBytes && len(c.pendingAcks) < deliveryWindowFrames {
			c.deliveryMu.Unlock()
			return nil
		}
		target := c.pendingAcks[0].Bytes
		c.deliveryMu.Unlock()
		if err := c.waitForDelivery(target); err != nil {
			return err
		}
	}
}

func (c *remoteConn) acknowledge(payload []byte) error {
	ack, err := protocol.DecodeDeliveryAck(payload)
	if err != nil {
		return err
	}
	c.deliveryMu.Lock()
	if len(c.pendingAcks) == 0 || c.pendingAcks[0] != ack {
		c.deliveryMu.Unlock()
		return fmt.Errorf("%w: delivery ACK does not match sent bytes", protocol.ErrInvalidFrame)
	}
	c.deliveredBytes = ack.Bytes
	c.pendingAcks[0] = protocol.DeliveryAck{}
	c.pendingAcks = c.pendingAcks[1:]
	c.deliveryMu.Unlock()
	select {
	case c.deliveryReady <- struct{}{}:
	default:
	}
	return nil
}

func (c *remoteConn) waitForDelivery(target uint64) error {
	for {
		c.deliveryMu.Lock()
		delivered := c.deliveredBytes
		c.deliveryMu.Unlock()
		if delivered >= target {
			return nil
		}
		deadline := c.currentWriteDeadline()
		timer, timeout := deadlineTimer(deadline)
		select {
		case <-c.deliveryReady:
			stopTimer(timer)
		case <-c.done:
			stopTimer(timer)
			return c.readError()
		case <-timeout:
			return timeoutError{}
		}
	}
}

func (c *remoteConn) abort(err error) {
	c.owner.remove(c.id)
	_ = c.owner.codec.WriteFrame(protocol.FrameClose, 0, c.id, nil)
	c.finish(err)
}

func (c *remoteConn) Close() error {
	c.owner.remove(c.id)
	err := c.owner.codec.WriteFrame(protocol.FrameClose, 0, c.id, nil)
	c.finish(net.ErrClosed)
	return err
}

func (c *remoteConn) LocalAddr() net.Addr  { return tunnelAddr("hub") }
func (c *remoteConn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *remoteConn) SetDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *remoteConn) SetReadDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.readDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *remoteConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlineMu.Lock()
	c.writeDeadline = deadline
	c.deadlineMu.Unlock()
	return nil
}

func (c *remoteConn) signalOpened(err error) {
	select {
	case c.opened <- err:
	default:
	}
}

func (c *remoteConn) deliver(data []byte) bool {
	copyOfData := append([]byte(nil), data...)
	select {
	case c.inbound <- inbound{data: copyOfData}:
		return true
	case <-c.done:
		return false
	}
}

func (c *remoteConn) finish(err error) {
	c.closeOnce.Do(func() {
		c.deadlineMu.Lock()
		c.finalErr = err
		c.deadlineMu.Unlock()
		close(c.done)
	})
}

func (c *remoteConn) readError() error {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	if c.finalErr == nil {
		return net.ErrClosed
	}
	return c.finalErr
}

func (c *remoteConn) currentReadDeadline() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.readDeadline
}

func (c *remoteConn) currentWriteDeadline() time.Time {
	c.deadlineMu.Lock()
	defer c.deadlineMu.Unlock()
	return c.writeDeadline
}

type tunnelAddr string

func (a tunnelAddr) Network() string { return "tokenhive-tunnel" }
func (a tunnelAddr) String() string  { return string(a) }

type timeoutError struct{}

func (timeoutError) Error() string   { return "tunnel deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func deadlineTimer(deadline time.Time) (*time.Timer, <-chan time.Time) {
	if deadline.IsZero() {
		return nil, nil
	}
	duration := time.Until(deadline)
	if duration < 0 {
		duration = 0
	}
	timer := time.NewTimer(duration)
	return timer, timer.C
}

func stopTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}
