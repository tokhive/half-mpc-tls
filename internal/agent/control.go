// Package agent implements the authenticated Provider Agent heartbeat control
// plane. Application requests and credentials never travel on this channel.
package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"tokenhive.local/half-mpc-tls/internal/precompute"
	"tokenhive.local/half-mpc-tls/internal/protocol"
)

const (
	ProtocolVersion   = 1
	maxControlPayload = protocol.MaxAgentControlPayload
)

var (
	ErrAuthentication  = errors.New("Provider Agent authentication failed")
	ErrProtocol        = errors.New("invalid Provider Agent control protocol")
	ErrDuplicate       = errors.New("Provider Agent is already connected")
	ErrUnknownProvider = errors.New("unknown Provider Agent")
)

// ProviderController is implemented by precompute.Autoscaler.
type ProviderController interface {
	Manage(precompute.Key, bool) error
	SetOnline(precompute.Key, bool) error
	Remove(precompute.Key) error
}

type Authorizer interface {
	Authorize(tls.ConnectionState, string) error
}

type AuthorizerFunc func(tls.ConnectionState, string) error

func (f AuthorizerFunc) Authorize(state tls.ConnectionState, providerID string) error {
	return f(state, providerID)
}

// SPIFFEAuthorizer binds provider_id to
// spiffe://<trust-domain>/provider/<provider-id> in the verified leaf cert.
type SPIFFEAuthorizer struct {
	TrustDomain string
}

func (a SPIFFEAuthorizer) Authorize(state tls.ConnectionState, providerID string) error {
	if !validID(providerID) || a.TrustDomain == "" || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return ErrAuthentication
	}
	expected := (&url.URL{
		Scheme: "spiffe",
		Host:   strings.ToLower(a.TrustDomain),
		Path:   "/provider/" + providerID,
	}).String()
	for _, identity := range state.VerifiedChains[0][0].URIs {
		if identity.String() == expected {
			return nil
		}
	}
	return ErrAuthentication
}

// ProviderID returns the single Provider identity in the verified leaf URI
// SAN. It is used by the separate authenticated reverse data listener.
func (a SPIFFEAuthorizer) ProviderID(state tls.ConnectionState) (string, error) {
	if a.TrustDomain == "" || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return "", ErrAuthentication
	}
	prefix := "/provider/"
	var providerID string
	for _, identity := range state.VerifiedChains[0][0].URIs {
		if identity.Scheme != "spiffe" || !strings.EqualFold(identity.Host, a.TrustDomain) ||
			!strings.HasPrefix(identity.Path, prefix) {
			continue
		}
		candidate := strings.TrimPrefix(identity.Path, prefix)
		if !validID(candidate) || strings.Contains(candidate, "/") || providerID != "" {
			return "", ErrAuthentication
		}
		providerID = candidate
	}
	if providerID == "" {
		return "", ErrAuthentication
	}
	return providerID, nil
}

type HubConfig struct {
	TLS              *tls.Config
	Authorizer       Authorizer
	HeartbeatTimeout time.Duration
}

type providerState struct {
	connected     bool
	accepting     bool
	instanceID    string
	generation    uint64
	lastHeartbeat time.Time
	lastCounter   uint64
}

type ProviderSnapshot struct {
	Connected     bool
	Accepting     bool
	InstanceID    string
	LastHeartbeat time.Time
	LastCounter   uint64
}

// Hub authenticates Provider connections and maps their liveness to pool keys.
type Hub struct {
	tlsConfig        *tls.Config
	authorizer       Authorizer
	heartbeatTimeout time.Duration
	controller       ProviderController

	mu         sync.Mutex
	providers  map[string]*providerState
	keys       map[string]map[precompute.Key]struct{}
	generation uint64
}

func NewHub(config HubConfig, controller ProviderController) (*Hub, error) {
	if controller == nil || config.TLS == nil || config.Authorizer == nil || config.HeartbeatTimeout <= 0 ||
		len(config.TLS.Certificates) == 0 || config.TLS.ClientCAs == nil {
		return nil, ErrProtocol
	}
	tlsConfig := config.TLS.Clone()
	tlsConfig.MinVersion = max(tlsConfig.MinVersion, uint16(tls.VersionTLS13))
	tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
	return &Hub{
		tlsConfig:        tlsConfig,
		authorizer:       config.Authorizer,
		heartbeatTimeout: config.HeartbeatTimeout,
		controller:       controller,
		providers:        make(map[string]*providerState),
		keys:             make(map[string]map[precompute.Key]struct{}),
	}, nil
}

// BindKey registers a Provider-specific pool key. The key is immediately
// managed with the Provider's current authenticated accepting state.
func (h *Hub) BindKey(providerID string, key precompute.Key) error {
	if !validID(providerID) || key.ProviderID != providerID {
		return ErrUnknownProvider
	}
	if err := key.Validate(); err != nil {
		return err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	state := h.providers[providerID]
	online := state != nil && state.connected && state.accepting
	if err := h.controller.Manage(key, online); err != nil {
		return err
	}
	if h.keys[providerID] == nil {
		h.keys[providerID] = make(map[precompute.Key]struct{})
	}
	h.keys[providerID][key] = struct{}{}
	return nil
}

func (h *Hub) UnbindKey(providerID string, key precompute.Key) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	keys := h.keys[providerID]
	if _, ok := keys[key]; !ok {
		return ErrUnknownProvider
	}
	if err := h.controller.Remove(key); err != nil {
		return err
	}
	delete(keys, key)
	return nil
}

func (h *Hub) Snapshot(providerID string) (ProviderSnapshot, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	state := h.providers[providerID]
	if state == nil {
		return ProviderSnapshot{}, false
	}
	return ProviderSnapshot{
		Connected:     state.connected,
		Accepting:     state.accepting,
		InstanceID:    state.instanceID,
		LastHeartbeat: state.lastHeartbeat,
		LastCounter:   state.lastCounter,
	}, true
}

// Serve authenticates and monitors one Provider-initiated connection.
func (h *Hub) Serve(ctx context.Context, connection net.Conn) (resultErr error) {
	if ctx == nil || connection == nil {
		return ErrProtocol
	}
	tlsConnection := tls.Server(connection, h.tlsConfig)
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	defer connection.Close()
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("%w: TLS handshake", ErrAuthentication)
	}
	codec := protocol.NewCodec(tlsConnection, tlsConnection)
	frame, err := codec.ReadFrame()
	if err != nil {
		return err
	}
	if frame.Type != protocol.FrameAgentHello || frame.Flags != 0 || frame.SessionID != 0 || len(frame.Payload) > maxControlPayload {
		return ErrProtocol
	}
	var hello helloMessage
	if err := decodeStrict(frame.Payload, &hello); err != nil || hello.ProtocolVersion != ProtocolVersion ||
		!validID(hello.ProviderID) || !validID(hello.InstanceID) {
		return ErrProtocol
	}
	if err := h.authorizer.Authorize(tlsConnection.ConnectionState(), hello.ProviderID); err != nil {
		_ = writeJSON(codec, protocol.FrameAgentHelloAck, helloAck{Accepted: false, ErrorCode: "unauthorized"})
		return ErrAuthentication
	}
	generation, err := h.connect(hello.ProviderID, hello.InstanceID)
	if err != nil {
		_ = writeJSON(codec, protocol.FrameAgentHelloAck, helloAck{Accepted: false, ErrorCode: "duplicate"})
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, h.disconnect(hello.ProviderID, generation))
	}()
	if err := writeJSON(codec, protocol.FrameAgentHelloAck, helloAck{Accepted: true}); err != nil {
		return err
	}

	var expectedCounter uint64 = 1
	for {
		if err := tlsConnection.SetReadDeadline(time.Now().Add(h.heartbeatTimeout)); err != nil {
			return err
		}
		frame, err := codec.ReadFrame()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if frame.Type != protocol.FrameAgentHeartbeat || frame.Flags != 0 || frame.SessionID != 0 || len(frame.Payload) > maxControlPayload {
			return ErrProtocol
		}
		var heartbeat heartbeatMessage
		if err := decodeStrict(frame.Payload, &heartbeat); err != nil || heartbeat.Counter != expectedCounter || heartbeat.SentAtUnixMilli <= 0 {
			return ErrProtocol
		}
		if err := h.heartbeat(hello.ProviderID, generation, heartbeat); err != nil {
			return err
		}
		if err := writeJSON(codec, protocol.FrameAgentHeartbeatAck, heartbeatAck{
			Counter:             heartbeat.Counter,
			ReceivedAtUnixMilli: time.Now().UnixMilli(),
		}); err != nil {
			return err
		}
		expectedCounter++
	}
}

func (h *Hub) connect(providerID, instanceID string) (uint64, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if existing := h.providers[providerID]; existing != nil && existing.connected {
		return 0, ErrDuplicate
	}
	h.generation++
	h.providers[providerID] = &providerState{
		connected:  true,
		instanceID: instanceID,
		generation: h.generation,
	}
	return h.generation, nil
}

func (h *Hub) heartbeat(providerID string, generation uint64, heartbeat heartbeatMessage) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	state := h.providers[providerID]
	if state == nil || !state.connected || state.generation != generation {
		return ErrUnknownProvider
	}
	state.lastHeartbeat = time.Now()
	state.lastCounter = heartbeat.Counter
	if state.accepting == heartbeat.Accepting {
		return nil
	}
	if err := h.setOnlineLocked(providerID, heartbeat.Accepting); err != nil {
		return err
	}
	state.accepting = heartbeat.Accepting
	return nil
}

func (h *Hub) disconnect(providerID string, generation uint64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	state := h.providers[providerID]
	if state == nil || state.generation != generation {
		return nil
	}
	state.connected = false
	if err := h.setOnlineLocked(providerID, false); err != nil {
		return err
	}
	state.accepting = false
	return nil
}

func (h *Hub) setOnlineLocked(providerID string, online bool) error {
	var updateErr error
	for key := range h.keys[providerID] {
		if err := h.controller.SetOnline(key, online); err != nil {
			updateErr = errors.Join(updateErr, err)
		}
	}
	return updateErr
}

type ClientConfig struct {
	TLS               *tls.Config
	ProviderID        string
	InstanceID        string
	HeartbeatInterval time.Duration
	AckTimeout        time.Duration
	ReconnectMin      time.Duration
	ReconnectMax      time.Duration
}

// Client sends Provider availability over an mTLS-authenticated connection.
type Client struct {
	tlsConfig         *tls.Config
	providerID        string
	instanceID        string
	heartbeatInterval time.Duration
	ackTimeout        time.Duration
	reconnectMin      time.Duration
	reconnectMax      time.Duration
}

func NewClient(config ClientConfig) (*Client, error) {
	if config.ReconnectMin == 0 {
		config.ReconnectMin = 250 * time.Millisecond
	}
	if config.ReconnectMax == 0 {
		config.ReconnectMax = 15 * time.Second
	}
	if config.TLS == nil || len(config.TLS.Certificates) == 0 || !validID(config.ProviderID) ||
		!validID(config.InstanceID) || config.HeartbeatInterval <= 0 || config.AckTimeout <= 0 ||
		config.TLS.InsecureSkipVerify || config.TLS.ServerName == "" || config.ReconnectMin <= 0 ||
		config.ReconnectMax < config.ReconnectMin {
		return nil, ErrProtocol
	}
	tlsConfig := config.TLS.Clone()
	tlsConfig.MinVersion = max(tlsConfig.MinVersion, uint16(tls.VersionTLS13))
	return &Client{
		tlsConfig:         tlsConfig,
		providerID:        config.ProviderID,
		instanceID:        config.InstanceID,
		heartbeatInterval: config.HeartbeatInterval,
		ackTimeout:        config.AckTimeout,
		reconnectMin:      config.ReconnectMin,
		reconnectMax:      config.ReconnectMax,
	}, nil
}

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

// RunWithReconnect maintains the Provider-initiated control connection.
// Authentication and protocol failures are terminal; transport loss and a
// short-lived duplicate instance response are retried with bounded backoff.
func (c *Client) RunWithReconnect(
	ctx context.Context,
	dialer Dialer,
	network, address string,
	status func() bool,
) error {
	if ctx == nil || dialer == nil || network == "" || address == "" || status == nil {
		return ErrProtocol
	}
	backoff := c.reconnectMin
	for {
		started := time.Now()
		connection, err := dialer.DialContext(ctx, network, address)
		if err == nil {
			err = c.Run(ctx, connection, status)
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if errors.Is(err, ErrAuthentication) || errors.Is(err, ErrProtocol) {
			return err
		}
		if time.Since(started) >= 2*c.heartbeatInterval {
			backoff = c.reconnectMin
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
		if backoff > c.reconnectMax/2 {
			backoff = c.reconnectMax
		} else {
			backoff = min(2*backoff, c.reconnectMax)
		}
	}
}

// Run serves one connection until cancellation or transport failure. status is
// sampled for every heartbeat so a Provider can drain without disconnecting.
func (c *Client) Run(ctx context.Context, connection net.Conn, status func() bool) error {
	if ctx == nil || connection == nil || status == nil {
		return ErrProtocol
	}
	tlsConnection := tls.Client(connection, c.tlsConfig)
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	defer connection.Close()
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("%w: TLS handshake", ErrAuthentication)
	}
	codec := protocol.NewCodec(tlsConnection, tlsConnection)
	if err := writeJSON(codec, protocol.FrameAgentHello, helloMessage{
		ProtocolVersion: ProtocolVersion,
		ProviderID:      c.providerID,
		InstanceID:      c.instanceID,
	}); err != nil {
		return err
	}
	frame, err := codec.ReadFrame()
	if err != nil {
		return err
	}
	var ack helloAck
	if frame.Type != protocol.FrameAgentHelloAck || frame.Flags != 0 || frame.SessionID != 0 ||
		len(frame.Payload) > maxControlPayload || decodeStrict(frame.Payload, &ack) != nil {
		return ErrProtocol
	}
	if !ack.Accepted {
		if ack.ErrorCode == "duplicate" {
			return ErrDuplicate
		}
		return ErrAuthentication
	}
	if ack.ErrorCode != "" {
		return ErrProtocol
	}

	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()
	var counter uint64
	for {
		counter++
		if err := c.sendHeartbeat(tlsConnection, codec, counter, status()); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (c *Client) sendHeartbeat(connection *tls.Conn, codec *protocol.Codec, counter uint64, accepting bool) error {
	deadline := time.Now().Add(c.ackTimeout)
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	if err := writeJSON(codec, protocol.FrameAgentHeartbeat, heartbeatMessage{
		Counter:         counter,
		SentAtUnixMilli: time.Now().UnixMilli(),
		Accepting:       accepting,
	}); err != nil {
		return err
	}
	frame, err := codec.ReadFrame()
	if err != nil {
		return err
	}
	var ack heartbeatAck
	if frame.Type != protocol.FrameAgentHeartbeatAck || frame.Flags != 0 || frame.SessionID != 0 ||
		len(frame.Payload) > maxControlPayload || decodeStrict(frame.Payload, &ack) != nil ||
		ack.Counter != counter || ack.ReceivedAtUnixMilli <= 0 {
		return ErrProtocol
	}
	return connection.SetDeadline(time.Time{})
}

type helloMessage struct {
	ProtocolVersion uint16 `json:"protocol_version"`
	ProviderID      string `json:"provider_id"`
	InstanceID      string `json:"instance_id"`
}

type helloAck struct {
	Accepted  bool   `json:"accepted"`
	ErrorCode string `json:"error_code,omitempty"`
}

type heartbeatMessage struct {
	Counter         uint64 `json:"counter"`
	SentAtUnixMilli int64  `json:"sent_at_unix_milli"`
	Accepting       bool   `json:"accepting"`
}

type heartbeatAck struct {
	Counter             uint64 `json:"counter"`
	ReceivedAtUnixMilli int64  `json:"received_at_unix_milli"`
}

func writeJSON(codec *protocol.Codec, frameType protocol.FrameType, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) > maxControlPayload {
		return ErrProtocol
	}
	return codec.WriteFrame(frameType, 0, 0, payload)
}

func decodeStrict(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return ErrProtocol
		}
		return err
	}
	return nil
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
}
