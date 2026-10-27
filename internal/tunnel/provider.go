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
	"time"

	"tokenhive.local/half-mpc-tls/internal/egress"
	"tokenhive.local/half-mpc-tls/internal/protocol"
)

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

type Provider struct {
	Policy      *egress.Policy
	Dialer      Dialer
	DialTimeout time.Duration

	codec    *protocol.Codec
	mu       sync.Mutex
	sessions map[uint64]*providerSession
}

func (p *Provider) Serve(ctx context.Context, control net.Conn) error {
	if p.Policy == nil {
		return fmt.Errorf("provider egress policy is required")
	}
	if p.Dialer == nil {
		p.Dialer = &net.Dialer{}
	}
	if p.DialTimeout <= 0 {
		p.DialTimeout = 10 * time.Second
	}
	p.codec = protocol.NewCodec(control, control)
	p.sessions = make(map[uint64]*providerSession)
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(ctx, func() { _ = control.Close() })
	var opening sync.WaitGroup
	defer func() {
		cancel()
		stop()
		_ = control.Close()
		// A pending dial must not install a session after closeAll has run.
		opening.Wait()
		p.closeAll()
	}()

	for {
		frame, err := p.codec.ReadFrame()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			return err
		}
		switch frame.Type {
		case protocol.FrameOpen:
			opening.Add(1)
			go func() {
				defer opening.Done()
				p.open(ctx, frame.SessionID, frame.Payload)
			}()
		case protocol.FrameData:
			if len(frame.Payload) == 0 || len(frame.Payload) > protocol.MaxDataFrameSize {
				return fmt.Errorf("invalid data frame size %d", len(frame.Payload))
			}
			if session := p.get(frame.SessionID); session != nil {
				session.deliver(frame.Payload)
			}
		case protocol.FrameEOF, protocol.FrameClose:
			p.closeSession(frame.SessionID)
		case protocol.FramePing:
			if err := p.codec.WriteFrame(protocol.FramePong, 0, frame.SessionID, frame.Payload); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected frame type %d from hub", frame.Type)
		}
	}
}

func (p *Provider) open(parent context.Context, sessionID uint64, payload []byte) {
	target, err := protocol.DecodeTarget(payload)
	if err != nil {
		p.sendError(sessionID, err)
		return
	}
	if err := p.Policy.Check(target); err != nil {
		p.sendError(sessionID, err)
		return
	}

	ctx, cancel := context.WithTimeout(parent, p.DialTimeout)
	defer cancel()
	conn, err := p.Dialer.DialContext(ctx, "tcp", target.Address())
	if err != nil {
		p.sendError(sessionID, fmt.Errorf("dial upstream: %w", err))
		return
	}

	session := &providerSession{
		id:           sessionID,
		conn:         conn,
		outbound:     make(chan []byte, 16),
		done:         make(chan struct{}),
		deliveryHash: sha256.New(),
	}
	if !p.add(session) {
		_ = conn.Close()
		p.sendError(sessionID, fmt.Errorf("duplicate session id"))
		return
	}
	if err := p.codec.WriteFrame(protocol.FrameOpened, 0, sessionID, nil); err != nil {
		p.closeSession(sessionID)
		return
	}
	go p.writeUpstream(session)
	go p.readUpstream(session)
}

func (p *Provider) readUpstream(session *providerSession) {
	buffer := make([]byte, protocol.MaxDataFrameSize)
	for {
		n, err := session.conn.Read(buffer)
		if n > 0 {
			session.deliveryMu.Lock()
			if writeErr := p.codec.WriteFrame(protocol.FrameData, 0, session.id, buffer[:n]); writeErr != nil {
				session.deliveryMu.Unlock()
				p.closeSession(session.id)
				return
			}
			session.deliveryMu.Unlock()
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				_ = p.codec.WriteFrame(protocol.FrameEOF, 0, session.id, nil)
			} else {
				p.sendError(session.id, fmt.Errorf("read upstream: %w", err))
			}
			p.closeSession(session.id)
			return
		}
	}
}

func (p *Provider) writeUpstream(session *providerSession) {
	for {
		select {
		case data := <-session.outbound:
			session.deliveryMu.Lock()
			if err := writeConn(session.conn, data); err != nil {
				session.deliveryMu.Unlock()
				p.sendError(session.id, fmt.Errorf("write upstream: %w", err))
				p.closeSession(session.id)
				return
			}
			if session.deliveredBytes > math.MaxUint64-uint64(len(data)) {
				session.deliveryMu.Unlock()
				p.sendError(session.id, fmt.Errorf("upstream delivery counter exhausted"))
				p.closeSession(session.id)
				return
			}
			session.deliveredBytes += uint64(len(data))
			_, _ = session.deliveryHash.Write(data)
			var digest [sha256.Size]byte
			copy(digest[:], session.deliveryHash.Sum(nil))
			payload, err := protocol.EncodeDeliveryAck(protocol.DeliveryAck{
				Bytes:  session.deliveredBytes,
				SHA256: digest,
			})
			if err == nil {
				err = p.codec.WriteFrame(protocol.FrameDeliveryAck, 0, session.id, payload)
			}
			session.deliveryMu.Unlock()
			if err != nil {
				p.closeSession(session.id)
				return
			}
		case <-session.done:
			return
		}
	}
}

func (p *Provider) add(session *providerSession) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, exists := p.sessions[session.id]; exists {
		return false
	}
	p.sessions[session.id] = session
	return true
}

func (p *Provider) get(sessionID uint64) *providerSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sessions[sessionID]
}

func (p *Provider) closeSession(sessionID uint64) {
	p.mu.Lock()
	session := p.sessions[sessionID]
	delete(p.sessions, sessionID)
	p.mu.Unlock()
	if session != nil {
		session.close()
	}
}

func (p *Provider) closeAll() {
	p.mu.Lock()
	sessions := make([]*providerSession, 0, len(p.sessions))
	for _, session := range p.sessions {
		sessions = append(sessions, session)
	}
	p.sessions = make(map[uint64]*providerSession)
	p.mu.Unlock()
	for _, session := range sessions {
		session.close()
	}
}

func (p *Provider) sendError(sessionID uint64, err error) {
	_ = p.codec.WriteFrame(protocol.FrameError, 0, sessionID, []byte(err.Error()))
}

type providerSession struct {
	id             uint64
	conn           net.Conn
	outbound       chan []byte
	done           chan struct{}
	closeOnce      sync.Once
	deliveryMu     sync.Mutex
	deliveredBytes uint64
	deliveryHash   hash.Hash
}

func (s *providerSession) deliver(data []byte) {
	copyOfData := append([]byte(nil), data...)
	select {
	case s.outbound <- copyOfData:
	case <-s.done:
	}
}

func (s *providerSession) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		_ = s.conn.Close()
	})
}

func writeConn(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
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
