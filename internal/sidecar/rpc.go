package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"tokenhive.local/half-mpc-tls/internal/protocol"
)

const (
	MaxHelloSize        = 16 << 10
	MaxCommandSize      = 64 << 10
	MaxStreamSize       = 16 << 20
	MaxCancelReasonSize = 256
)

type Operation string

const (
	OperationCreateSession               Operation = "create_session"
	OperationRunHandshake                Operation = "run_handshake"
	OperationEncryptRequest              Operation = "encrypt_request"
	OperationFeedServerRecords           Operation = "feed_server_records"
	OperationCloseSession                Operation = "close_session"
	OperationBindCredential              Operation = "bind_credential"
	OperationContributeRequestEncryption Operation = "contribute_request_encryption"
	OperationDestroySession              Operation = "destroy_session"
	OperationAttachMPCChannel            Operation = "attach_mpc_channel"
	OperationAttachUpstreamChannel       Operation = "attach_upstream_channel"
	OperationAttachResponseChannel       Operation = "attach_response_channel"
)

type RPCHello struct {
	ProtocolVersion uint16 `json:"protocol_version"`
	ExpectedRole    string `json:"expected_role"`
}

type RPCHelloAck struct {
	Capabilities Capabilities `json:"capabilities"`
}

type RPCCommand struct {
	RequestID uint64          `json:"request_id"`
	Operation Operation       `json:"operation"`
	Params    json.RawMessage `json:"params"`
}

// SelectiveRequestParams binds both MPC participants to the same canonical
// public request. The credential layout is inferred from the fixed adapter and
// is never supplied by a Consumer.
type SelectiveRequestParams struct {
	TaskID            string `json:"task_id"`
	Adapter           string `json:"adapter"`
	CredentialLength  int    `json:"credential_length"`
	PublicRequestHash string `json:"public_request_hash"`
}

type RPCStatus string

const (
	RPCStatusOK    RPCStatus = "ok"
	RPCStatusError RPCStatus = "error"
)

type RPCResult struct {
	RequestID    uint64          `json:"request_id"`
	Status       RPCStatus       `json:"status"`
	Data         json.RawMessage `json:"data,omitempty"`
	ErrorCode    string          `json:"error_code,omitempty"`
	ErrorMessage string          `json:"error_message,omitempty"`
}

var (
	ErrRPCProtocol = errors.New("invalid sidecar RPC protocol")
	ErrRPCRole     = errors.New("unexpected sidecar role")
)

// RPCRemoteError reports a stable, redacted operation failure returned by a
// sidecar. It deliberately excludes arbitrary remote detail.
type RPCRemoteError struct {
	Code string
}

func (e *RPCRemoteError) Error() string {
	return fmt.Sprintf("sidecar operation failed: %s", e.Code)
}

// RPCClient performs the role-bound local handshake and emits typed commands.
// Exactly one goroutine should read results; writes are serialized by Codec.
type RPCClient struct {
	codec        *protocol.Codec
	expectedRole string
	capabilities Capabilities
	ready        bool
	closer       io.Closer
}

func NewRPCClient(codec *protocol.Codec, expectedRole string) (*RPCClient, error) {
	if codec == nil {
		return nil, fmt.Errorf("%w: codec is required", ErrRPCProtocol)
	}
	if expectedRole != RoleHub && expectedRole != RoleProvider {
		return nil, fmt.Errorf("%w: %q", ErrRPCRole, expectedRole)
	}
	return &RPCClient{codec: codec, expectedRole: expectedRole}, nil
}

// DialRPC connects to a protected local Unix socket and completes role-bound
// capability negotiation before returning the client.
func DialRPC(ctx context.Context, socketPath, expectedRole string) (*RPCClient, Capabilities, error) {
	if ctx == nil {
		return nil, Capabilities{}, fmt.Errorf("%w: context is required", ErrRPCProtocol)
	}
	if socketPath == "" {
		return nil, Capabilities{}, fmt.Errorf("%w: socket path is required", ErrRPCProtocol)
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, Capabilities{}, fmt.Errorf("dial sidecar Unix socket: %w", err)
	}
	return OpenRPC(ctx, connection, expectedRole)
}

// OpenRPC completes the role-bound sidecar handshake over an already
// authenticated transport, such as a Provider-initiated reverse tunnel.
func OpenRPC(ctx context.Context, connection net.Conn, expectedRole string) (*RPCClient, Capabilities, error) {
	if ctx == nil || connection == nil {
		if connection != nil {
			_ = connection.Close()
		}
		return nil, Capabilities{}, fmt.Errorf("%w: context and connection are required", ErrRPCProtocol)
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.Close()
	})
	client, err := NewRPCClient(protocol.NewCodec(connection, connection), expectedRole)
	if err != nil {
		stopCancellation()
		_ = connection.Close()
		return nil, Capabilities{}, err
	}
	client.closer = connection
	capabilities, err := client.Handshake()
	cancellationStopped := stopCancellation()
	if err != nil {
		_ = connection.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, Capabilities{}, ctxErr
		}
		return nil, Capabilities{}, err
	}
	if !cancellationStopped {
		_ = connection.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, Capabilities{}, ctxErr
		}
		return nil, Capabilities{}, fmt.Errorf("%w: connection cancelled during handshake", ErrRPCProtocol)
	}
	return client, capabilities, nil
}

// Close closes a client created by DialRPC. It is a no-op for clients built
// around an externally owned codec.
func (c *RPCClient) Close() error {
	if c == nil || c.closer == nil {
		return nil
	}
	return c.closer.Close()
}

// Attachment is a dedicated full-duplex byte channel carried in bounded
// sidecar stream frames after an attachment command succeeds.
type Attachment struct {
	codec     *protocol.Codec
	closer    io.Closer
	sessionID uint64
	operation Operation

	readMu        sync.Mutex
	readBuffer    []byte
	readEOF       bool
	writeMu       sync.Mutex
	writeClosed   bool
	writeCloseErr error
	deliveryBytes uint64
	closeOnce     sync.Once
	closeErr      error
}

// DialAttachment attaches a dedicated MPC or Provider upstream channel to a
// session. The returned stream can be bridged with io.Copy in both directions.
func DialAttachment(
	ctx context.Context,
	socketPath, expectedRole string,
	sessionID, requestID uint64,
	operation Operation,
	attachmentToken string,
) (*Attachment, error) {
	if operation != OperationAttachMPCChannel && operation != OperationAttachUpstreamChannel && operation != OperationAttachResponseChannel {
		return nil, fmt.Errorf("%w: invalid attachment operation %q", ErrRPCProtocol, operation)
	}
	if sessionID == 0 || requestID == 0 || !validAttachmentToken(attachmentToken) {
		return nil, fmt.Errorf("%w: invalid attachment identifiers or token", ErrRPCProtocol)
	}
	client, _, err := DialRPC(ctx, socketPath, expectedRole)
	if err != nil {
		return nil, err
	}
	return openAttachment(ctx, client, sessionID, requestID, operation, attachmentToken)
}

// OpenAttachment attaches a channel through an already authenticated
// transport. The connection is consumed and owned by the returned attachment.
func OpenAttachment(
	ctx context.Context,
	connection net.Conn,
	expectedRole string,
	sessionID, requestID uint64,
	operation Operation,
	attachmentToken string,
) (*Attachment, error) {
	client, _, err := OpenRPC(ctx, connection, expectedRole)
	if err != nil {
		return nil, err
	}
	return openAttachment(ctx, client, sessionID, requestID, operation, attachmentToken)
}

func openAttachment(
	ctx context.Context,
	client *RPCClient,
	sessionID, requestID uint64,
	operation Operation,
	attachmentToken string,
) (*Attachment, error) {
	if operation != OperationAttachMPCChannel && operation != OperationAttachUpstreamChannel && operation != OperationAttachResponseChannel {
		_ = client.Close()
		return nil, fmt.Errorf("%w: invalid attachment operation %q", ErrRPCProtocol, operation)
	}
	if sessionID == 0 || requestID == 0 || !validAttachmentToken(attachmentToken) {
		_ = client.Close()
		return nil, fmt.Errorf("%w: invalid attachment identifiers or token", ErrRPCProtocol)
	}
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = client.Close()
	})
	params, err := json.Marshal(struct {
		AttachmentToken string `json:"attachment_token"`
	}{AttachmentToken: attachmentToken})
	if err != nil {
		stopCancellation()
		_ = client.Close()
		return nil, err
	}
	if err := client.WriteCommand(sessionID, RPCCommand{
		RequestID: requestID,
		Operation: operation,
		Params:    params,
	}); err != nil {
		stopCancellation()
		_ = client.Close()
		return nil, err
	}
	result, err := client.ReadResult(sessionID, requestID)
	cancellationStopped := stopCancellation()
	if err != nil {
		_ = client.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	if !cancellationStopped {
		_ = client.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, fmt.Errorf("%w: connection cancelled during attachment", ErrRPCProtocol)
	}
	if result.Status != RPCStatusOK {
		_ = client.Close()
		return nil, &RPCRemoteError{Code: result.ErrorCode}
	}

	attachment := &Attachment{
		codec:     client.codec,
		closer:    client.closer,
		sessionID: sessionID,
		operation: operation,
	}
	client.closer = nil
	return attachment, nil
}

func validAttachmentToken(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range []byte(value) {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

// Read reads raw attachment bytes while validating every enclosing frame.
func (a *Attachment) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	a.readMu.Lock()
	defer a.readMu.Unlock()
	for len(a.readBuffer) == 0 {
		chunk, err := a.readChunkLocked()
		if err != nil {
			return 0, err
		}
		a.readBuffer = chunk
	}
	n := copy(destination, a.readBuffer)
	a.readBuffer = a.readBuffer[n:]
	return n, nil
}

// ReadChunk returns exactly one sidecar stream frame. Provider upstream
// bridges use frame boundaries to acknowledge matching cumulative prefixes.
func (a *Attachment) ReadChunk() ([]byte, error) {
	if a == nil {
		return nil, io.ErrClosedPipe
	}
	a.readMu.Lock()
	defer a.readMu.Unlock()
	if len(a.readBuffer) != 0 {
		chunk := a.readBuffer
		a.readBuffer = nil
		return chunk, nil
	}
	return a.readChunkLocked()
}

func (a *Attachment) readChunkLocked() ([]byte, error) {
	if a.readEOF {
		return nil, io.EOF
	}
	frame, err := a.codec.ReadFrame()
	if err != nil {
		return nil, err
	}
	if frame.Flags != 0 || frame.SessionID != a.sessionID {
		return nil, fmt.Errorf("%w: invalid attachment frame metadata", ErrRPCProtocol)
	}
	switch frame.Type {
	case protocol.FrameSidecarStream:
		if len(frame.Payload) == 0 {
			return nil, fmt.Errorf("%w: empty attachment stream frame", ErrRPCProtocol)
		}
		return frame.Payload, nil
	case protocol.FrameSidecarStreamEnd:
		if len(frame.Payload) != 0 {
			return nil, fmt.Errorf("%w: attachment end contains payload", ErrRPCProtocol)
		}
		a.readEOF = true
		return nil, io.EOF
	default:
		return nil, fmt.Errorf("%w: unexpected attachment frame %d", ErrRPCProtocol, frame.Type)
	}
}

// Write writes raw bytes as one or more bounded attachment frames.
func (a *Attachment) Write(source []byte) (int, error) {
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if a.writeClosed {
		return 0, io.ErrClosedPipe
	}
	written := 0
	for len(source) > 0 {
		chunkSize := min(len(source), protocol.MaxDataFrameSize)
		if err := a.codec.WriteFrame(
			protocol.FrameSidecarStream,
			0,
			a.sessionID,
			source[:chunkSize],
		); err != nil {
			return written, err
		}
		written += chunkSize
		source = source[chunkSize:]
	}
	return written, nil
}

// AcknowledgeDelivery confirms one cumulative Provider upstream write. It is
// valid only on the Provider upstream attachment.
func (a *Attachment) AcknowledgeDelivery(ack protocol.DeliveryAck) error {
	if a == nil || a.operation != OperationAttachUpstreamChannel {
		return fmt.Errorf("%w: delivery ACK requires an upstream attachment", ErrRPCProtocol)
	}
	payload, err := protocol.EncodeDeliveryAck(ack)
	if err != nil {
		return err
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if a.writeClosed {
		return io.ErrClosedPipe
	}
	if ack.Bytes <= a.deliveryBytes {
		return fmt.Errorf("%w: delivery ACK is not monotonic", ErrRPCProtocol)
	}
	if err := a.codec.WriteFrame(protocol.FrameDeliveryAck, 0, a.sessionID, payload); err != nil {
		return err
	}
	a.deliveryBytes = ack.Bytes
	return nil
}

// CloseWrite half-closes the attachment while keeping its read direction open.
func (a *Attachment) CloseWrite() error {
	if a == nil {
		return nil
	}
	a.writeMu.Lock()
	defer a.writeMu.Unlock()
	if !a.writeClosed {
		a.writeCloseErr = a.codec.WriteFrame(
			protocol.FrameSidecarStreamEnd,
			0,
			a.sessionID,
			nil,
		)
		a.writeClosed = true
	}
	return a.writeCloseErr
}

// Close sends the attachment end marker and closes its dedicated connection.
func (a *Attachment) Close() error {
	if a == nil {
		return nil
	}
	a.closeOnce.Do(func() {
		writeErr := a.CloseWrite()
		closeErr := a.closer.Close()
		a.closeErr = errors.Join(writeErr, closeErr)
	})
	return a.closeErr
}

// Abort immediately closes the attachment transport without attempting a
// framed half-close first. It is used when an MPC operation has timed out or
// failed and a concurrent writer may otherwise keep graceful Close blocked.
func (a *Attachment) Abort() error {
	if a == nil {
		return nil
	}
	a.closeOnce.Do(func() {
		a.closeErr = a.closer.Close()
		a.writeMu.Lock()
		a.writeClosed = true
		a.writeMu.Unlock()
	})
	return a.closeErr
}

func (c *RPCClient) Handshake() (Capabilities, error) {
	if c.ready {
		return Capabilities{}, fmt.Errorf("%w: handshake already completed", ErrRPCProtocol)
	}
	payload, err := json.Marshal(RPCHello{
		ProtocolVersion: ProtocolVersion,
		ExpectedRole:    c.expectedRole,
	})
	if err != nil {
		return Capabilities{}, fmt.Errorf("encode sidecar hello: %w", err)
	}
	if len(payload) > MaxHelloSize {
		return Capabilities{}, fmt.Errorf("%w: hello exceeds %d bytes", ErrRPCProtocol, MaxHelloSize)
	}
	if err := c.codec.WriteFrame(protocol.FrameSidecarHello, 0, 0, payload); err != nil {
		return Capabilities{}, err
	}

	frame, err := c.codec.ReadFrame()
	if err != nil {
		return Capabilities{}, err
	}
	if frame.Type != protocol.FrameSidecarHelloAck || frame.Flags != 0 || frame.SessionID != 0 {
		return Capabilities{}, fmt.Errorf("%w: invalid hello ack metadata", ErrRPCProtocol)
	}
	if len(frame.Payload) > MaxHelloSize {
		return Capabilities{}, fmt.Errorf("%w: hello ack exceeds %d bytes", ErrRPCProtocol, MaxHelloSize)
	}
	var ack RPCHelloAck
	if err := decodeStrictJSON(frame.Payload, &ack); err != nil {
		return Capabilities{}, fmt.Errorf("%w: decode hello ack: %v", ErrRPCProtocol, err)
	}
	if err := ValidateCapabilities(ack.Capabilities, c.expectedRole); err != nil {
		return Capabilities{}, err
	}
	c.capabilities = ack.Capabilities
	c.ready = true
	return ack.Capabilities, nil
}

func (c *RPCClient) WriteCommand(sessionID uint64, command RPCCommand) error {
	if !c.ready {
		return fmt.Errorf("%w: handshake is not complete", ErrRPCProtocol)
	}
	if sessionID == 0 || command.RequestID == 0 {
		return fmt.Errorf("%w: session_id and request_id must be non-zero", ErrRPCProtocol)
	}
	if !operationAllowed(c.expectedRole, command.Operation) {
		return fmt.Errorf("%w: operation %q is not allowed for role %s", ErrRPCRole, command.Operation, c.expectedRole)
	}
	if len(command.Params) == 0 || !json.Valid(command.Params) {
		return fmt.Errorf("%w: params must be valid JSON", ErrRPCProtocol)
	}
	payload, err := json.Marshal(command)
	if err != nil {
		return fmt.Errorf("encode sidecar command: %w", err)
	}
	if len(payload) > MaxCommandSize {
		return fmt.Errorf("%w: command exceeds %d bytes", ErrRPCProtocol, MaxCommandSize)
	}
	return c.codec.WriteFrame(protocol.FrameSidecarCommand, 0, sessionID, payload)
}

func (c *RPCClient) ReadResult(expectedSessionID, expectedRequestID uint64) (RPCResult, error) {
	if !c.ready {
		return RPCResult{}, fmt.Errorf("%w: handshake is not complete", ErrRPCProtocol)
	}
	frame, err := c.codec.ReadFrame()
	if err != nil {
		return RPCResult{}, err
	}
	if frame.Type != protocol.FrameSidecarResult || frame.Flags != 0 || frame.SessionID != expectedSessionID {
		return RPCResult{}, fmt.Errorf("%w: unexpected result frame", ErrRPCProtocol)
	}
	if len(frame.Payload) > MaxCommandSize {
		return RPCResult{}, fmt.Errorf("%w: result exceeds %d bytes", ErrRPCProtocol, MaxCommandSize)
	}
	var result RPCResult
	if err := decodeStrictJSON(frame.Payload, &result); err != nil {
		return RPCResult{}, fmt.Errorf("%w: decode result: %v", ErrRPCProtocol, err)
	}
	if result.RequestID == 0 || result.RequestID != expectedRequestID {
		return RPCResult{}, fmt.Errorf("%w: unexpected result request_id %d", ErrRPCProtocol, result.RequestID)
	}
	if result.Status != RPCStatusOK && result.Status != RPCStatusError {
		return RPCResult{}, fmt.Errorf("%w: invalid result status %q", ErrRPCProtocol, result.Status)
	}
	if result.Status == RPCStatusOK && (result.ErrorCode != "" || result.ErrorMessage != "") {
		return RPCResult{}, fmt.Errorf("%w: successful result contains error fields", ErrRPCProtocol)
	}
	if result.Status == RPCStatusError && (result.ErrorCode == "" || len(result.Data) != 0) {
		return RPCResult{}, fmt.Errorf("%w: error result is missing error_code or contains success data", ErrRPCProtocol)
	}
	return result, nil
}

// WriteStream sends one bounded byte stream and its explicit end marker.
func (c *RPCClient) WriteStream(sessionID uint64, source io.Reader) error {
	if !c.ready {
		return fmt.Errorf("%w: handshake is not complete", ErrRPCProtocol)
	}
	if sessionID == 0 || source == nil {
		return fmt.Errorf("%w: stream session_id and source are required", ErrRPCProtocol)
	}

	buffer := make([]byte, protocol.MaxDataFrameSize)
	total := 0
	for {
		n, err := source.Read(buffer)
		if n > 0 {
			total += n
			if total > MaxStreamSize {
				_ = c.WriteCancel(sessionID, "input_too_large")
				return fmt.Errorf("%w: stream exceeds %d bytes", ErrRPCProtocol, MaxStreamSize)
			}
			if writeErr := c.codec.WriteFrame(protocol.FrameSidecarStream, 0, sessionID, buffer[:n]); writeErr != nil {
				return writeErr
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read sidecar stream: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("%w: stream source made no progress", ErrRPCProtocol)
		}
	}
	return c.codec.WriteFrame(protocol.FrameSidecarStreamEnd, 0, sessionID, nil)
}

// WriteCancel cancels the current session operation with a stable reason code.
func (c *RPCClient) WriteCancel(sessionID uint64, reason string) error {
	if !c.ready {
		return fmt.Errorf("%w: handshake is not complete", ErrRPCProtocol)
	}
	if sessionID == 0 || len(reason) > MaxCancelReasonSize || (reason != "" && !stableCode(reason)) {
		return fmt.Errorf("%w: invalid cancellation reason", ErrRPCProtocol)
	}
	return c.codec.WriteFrame(protocol.FrameSidecarCancel, 0, sessionID, []byte(reason))
}

func stableCode(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range []byte(value) {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func ValidateCapabilities(capabilities Capabilities, expectedRole string) error {
	if capabilities.Role != expectedRole {
		return fmt.Errorf("%w: got %q, want %q", ErrRPCRole, capabilities.Role, expectedRole)
	}
	version, suites, features, err := engineRequirements(capabilities.EngineMode)
	if err != nil || capabilities.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: unsupported version or engine mode", ErrRPCProtocol)
	}
	if len(capabilities.TLSVersions) != 1 || capabilities.TLSVersions[0] != version {
		return fmt.Errorf("%w: TLS version does not match engine mode", ErrRPCProtocol)
	}
	if !IsSupportedMPCCapacity(capabilities.MPCCapacity) {
		return fmt.Errorf("%w: unsupported MPC capacity profile", ErrRPCProtocol)
	}
	for _, feature := range features {
		if !contains(capabilities.Features, feature) {
			return fmt.Errorf("%w: missing feature %s", ErrRPCProtocol, feature)
		}
	}
	for _, suite := range capabilities.CipherSuites {
		if contains(suites, suite) {
			return nil
		}
	}
	return fmt.Errorf("%w: no supported cipher suite", ErrRPCProtocol)
}

func operationAllowed(role string, operation Operation) bool {
	if role == RoleHub {
		switch operation {
		case OperationCreateSession, OperationRunHandshake, OperationEncryptRequest,
			OperationFeedServerRecords, OperationCloseSession, OperationAttachMPCChannel,
			OperationAttachResponseChannel:
			return true
		}
	}
	if role == RoleProvider {
		switch operation {
		case OperationBindCredential, OperationRunHandshake,
			OperationContributeRequestEncryption, OperationDestroySession,
			OperationAttachMPCChannel, OperationAttachUpstreamChannel:
			return true
		}
	}
	return false
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}
