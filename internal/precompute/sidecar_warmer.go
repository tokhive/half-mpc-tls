package precompute

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"tokenhive.local/half-mpc-tls/internal/protocol"
	"tokenhive.local/half-mpc-tls/internal/response"
	"tokenhive.local/half-mpc-tls/internal/sidecar"
)

// UpstreamOpener must open the connection through the Provider's network and
// enforce its egress policy. tunnel.Client satisfies this interface.
type UpstreamOpener interface {
	Open(context.Context, protocol.Target) (net.Conn, error)
}

// ProviderUpstreamOpener selects the Provider-owned reverse tunnel identified
// by the pool key. It is used by split-machine deployments.
type ProviderUpstreamOpener interface {
	OpenProvider(context.Context, string, protocol.Target) (net.Conn, error)
}

// ProviderSidecarDialer opens a new byte stream to the Provider-local sidecar
// through a Provider-initiated authenticated tunnel.
type ProviderSidecarDialer interface {
	DialProviderSidecar(context.Context, string) (net.Conn, error)
}

// ProviderTransportReserver isolates the complete lifetime of a session.
type ProviderTransportReserver interface {
	ReserveProvider(context.Context, string) (context.Context, func(), error)
}

type ProviderCapacitySidecarDialer interface {
	DialProviderSidecarForCapacity(context.Context, string, sidecar.MPCCapacity) (net.Conn, error)
}

// ProviderLocalBridger owns the upstream transport at the Provider. The
// returned control connection carries no TLS bytes and is closed with the lease.
type ProviderLocalBridger interface {
	StartProviderBridge(context.Context, string, uint64, protocol.Target, string, sidecar.MPCCapacity) (net.Conn, error)
}

// SidecarWarmerConfig identifies the two role-fixed sidecars participating in
// a session. ProviderSocket must resolve to the Provider-local agent endpoint;
// it must not turn the upstream connection into a Hub-originated dial.
type SidecarWarmerConfig struct {
	HubSocket        string
	HubSockets       map[string]string
	ProviderSocket   string
	Upstream         UpstreamOpener
	ProviderUpstream ProviderUpstreamOpener
	ProviderDialer   ProviderSidecarDialer
	ProviderBridge   ProviderLocalBridger
}

// SidecarWarmer creates a complete live MPC TLS session. Preprocessing is
// and the authenticated handshake complete before a session becomes ready.
type SidecarWarmer struct {
	config SidecarWarmerConfig
	nextID atomic.Uint64
}

func NewSidecarWarmer(config SidecarWarmerConfig) (*SidecarWarmer, error) {
	if (config.HubSocket == "" && len(config.HubSockets) == 0) || (config.ProviderSocket == "" && config.ProviderDialer == nil) ||
		(config.Upstream == nil && config.ProviderUpstream == nil && config.ProviderBridge == nil) {
		return nil, fmt.Errorf("%w: sidecar sockets and Provider upstream opener are required", ErrInvalidConfig)
	}
	for profile, socket := range config.HubSockets {
		if _, err := sidecar.CapacityProfile(profile); err != nil || socket == "" {
			return nil, fmt.Errorf("%w: invalid Hub capacity socket", ErrInvalidConfig)
		}
	}
	return &SidecarWarmer{config: config}, nil
}

// SidecarSession is a ready pair of sidecar sessions and its authenticated
// response stream. It supports one in-flight request at a time.
type SidecarSession struct {
	id       uint64
	key      Key
	hub      *sidecar.RPCClient
	provider *sidecar.RPCClient

	hubMPC       *sidecar.Attachment
	providerMPC  *sidecar.Attachment
	providerWire *sidecar.Attachment
	responseWire *sidecar.Attachment
	upstream     net.Conn
	localBridge  net.Conn
	responses    *response.Stream

	ctx    context.Context
	cancel context.CancelFunc
	tasks  sync.WaitGroup

	requestMu        sync.Mutex
	nextRPC          atomic.Uint64
	healthy          atomic.Bool
	closeOnce        sync.Once
	closeErr         error
	releaseTransport func()
}

func (w *SidecarWarmer) Warm(ctx context.Context, key Key) (_ Resource, resultErr error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalidKey)
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	if !sidecar.IsSupportedMPCCapacity(key.Capacity) {
		return nil, fmt.Errorf("%w: unsupported MPC capacity", ErrInvalidKey)
	}

	profile, _ := sidecar.CapacityName(key.Capacity)
	hubSocket := w.config.HubSockets[profile]
	if hubSocket == "" {
		hubSocket = w.config.HubSocket
	}
	if hubSocket == "" {
		return nil, errors.New("Hub capacity socket is not configured")
	}
	sessionCtx, cancel := context.WithCancel(context.Background())
	session := &SidecarSession{
		id:     w.nextID.Add(1),
		key:    key,
		ctx:    sessionCtx,
		cancel: cancel,
	}
	session.healthy.Store(true)
	defer func() {
		if resultErr != nil {
			_ = session.Close()
		}
	}()

	var err error
	if reserver, ok := w.config.ProviderDialer.(ProviderTransportReserver); ok {
		ctx, session.releaseTransport, err = reserver.ReserveProvider(ctx, key.ProviderID)
		if err != nil {
			return nil, fmt.Errorf("reserve Provider transport: %w", err)
		}
	}
	var hubCapabilities sidecar.Capabilities
	session.hub, hubCapabilities, err = sidecar.DialRPC(ctx, hubSocket, sidecar.RoleHub)
	if err != nil {
		return nil, fmt.Errorf("dial Hub sidecar: %w", err)
	}

	var providerCapabilities sidecar.Capabilities
	session.provider, providerCapabilities, err = w.dialProviderRPC(ctx, key.ProviderID, key.Capacity)
	if err != nil {
		return nil, fmt.Errorf("dial Provider sidecar: %w", err)
	}
	negotiated, err := sidecar.Negotiate(hubCapabilities, providerCapabilities)
	if err != nil {
		return nil, fmt.Errorf("negotiate sidecars: %w", err)
	}
	if negotiated.TLSVersion != key.Version() {
		return nil, fmt.Errorf("%w: route TLS version does not match sidecars", ErrInvalidKey)
	}
	if negotiated.MPCCapacity != key.Capacity {
		return nil, fmt.Errorf("%w: route capacity does not match sidecars", ErrInvalidKey)
	}

	policy := upstreamPolicy{
		Host:       key.Host,
		Port:       key.Port,
		ServerName: key.ServerName,
	}
	hubToken, err := createHubSession(ctx, session.hub, session.id, policy)
	if err != nil {
		return nil, err
	}
	providerToken, err := createProviderSession(ctx, session.provider, session.id, key.CredentialID, policy)
	if err != nil {
		return nil, err
	}

	session.hubMPC, err = sidecar.DialAttachment(
		ctx, hubSocket, sidecar.RoleHub, session.id, 1,
		sidecar.OperationAttachMPCChannel, hubToken,
	)
	if err != nil {
		return nil, fmt.Errorf("attach Hub MPC channel: %w", err)
	}
	session.providerMPC, err = w.dialProviderAttachment(
		ctx, key.ProviderID, session.id, 1,
		sidecar.OperationAttachMPCChannel, providerToken, key.Capacity,
	)
	if err != nil {
		return nil, fmt.Errorf("attach Provider MPC channel: %w", err)
	}
	session.responseWire, err = sidecar.DialAttachment(
		ctx, hubSocket, sidecar.RoleHub, session.id, 1,
		sidecar.OperationAttachResponseChannel, hubToken,
	)
	if err != nil {
		return nil, fmt.Errorf("attach Hub response channel: %w", err)
	}
	session.responses, err = response.NewStream(session.responseWire)
	if err != nil {
		return nil, fmt.Errorf("create authenticated response stream: %w", err)
	}

	if w.config.ProviderBridge != nil {
		session.localBridge, err = w.config.ProviderBridge.StartProviderBridge(ctx,
			key.ProviderID, session.id, protocol.Target{Host: key.Host, Port: key.Port}, providerToken, key.Capacity)
		if err != nil {
			return nil, fmt.Errorf("start Provider-local upstream bridge: %w", err)
		}
	} else {
		if w.config.ProviderUpstream != nil {
			session.upstream, err = w.config.ProviderUpstream.OpenProvider(ctx, key.ProviderID, protocol.Target{Host: key.Host, Port: key.Port})
		} else {
			session.upstream, err = w.config.Upstream.Open(ctx, protocol.Target{Host: key.Host, Port: key.Port})
		}
		if err != nil {
			return nil, fmt.Errorf("open Provider upstream connection: %w", err)
		}
		session.providerWire, err = w.dialProviderAttachment(
			ctx, key.ProviderID, session.id, 1,
			sidecar.OperationAttachUpstreamChannel, providerToken, key.Capacity,
		)
		if err != nil {
			return nil, fmt.Errorf("attach Provider upstream channel: %w", err)
		}

	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	session.startTransportTasks()
	stopCancellation := context.AfterFunc(ctx, func() { _ = session.Close() })
	defer stopCancellation()
	if err := session.runHandshake(ctx); err != nil {
		return nil, err
	}
	if !stopCancellation() {
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !session.Healthy() {
		return nil, errors.New("warmed sidecar session transport closed during handshake")
	}
	return session, nil
}

func (w *SidecarWarmer) dialProviderRPC(ctx context.Context, providerID string, capacity sidecar.MPCCapacity) (*sidecar.RPCClient, sidecar.Capabilities, error) {
	if w.config.ProviderDialer == nil {
		return sidecar.DialRPC(ctx, w.config.ProviderSocket, sidecar.RoleProvider)
	}
	connection, err := w.dialProviderConnection(ctx, providerID, capacity)
	if err != nil {
		return nil, sidecar.Capabilities{}, err
	}
	return sidecar.OpenRPC(ctx, connection, sidecar.RoleProvider)
}

func (w *SidecarWarmer) dialProviderAttachment(
	ctx context.Context,
	providerID string,
	sessionID, requestID uint64,
	operation sidecar.Operation,
	token string,
	capacity sidecar.MPCCapacity,
) (*sidecar.Attachment, error) {
	if w.config.ProviderDialer == nil {
		return sidecar.DialAttachment(ctx, w.config.ProviderSocket, sidecar.RoleProvider, sessionID, requestID, operation, token)
	}
	connection, err := w.dialProviderConnection(ctx, providerID, capacity)
	if err != nil {
		return nil, err
	}
	return sidecar.OpenAttachment(ctx, connection, sidecar.RoleProvider, sessionID, requestID, operation, token)
}

func (w *SidecarWarmer) dialProviderConnection(ctx context.Context, providerID string, capacity sidecar.MPCCapacity) (net.Conn, error) {
	if dialer, ok := w.config.ProviderDialer.(ProviderCapacitySidecarDialer); ok {
		return dialer.DialProviderSidecarForCapacity(ctx, providerID, capacity)
	}
	return w.config.ProviderDialer.DialProviderSidecar(ctx, providerID)
}

type upstreamPolicy struct {
	Host       string `json:"host"`
	Port       uint16 `json:"port"`
	ServerName string `json:"server_name"`
}

type createParams struct {
	UpstreamPolicy upstreamPolicy `json:"upstream_policy"`
}

type bindParams struct {
	CredentialID   string         `json:"credential_id"`
	UpstreamPolicy upstreamPolicy `json:"upstream_policy"`
}

type attachmentResult struct {
	State           string `json:"state"`
	AttachmentToken string `json:"attachment_token"`
}

func createHubSession(ctx context.Context, client *sidecar.RPCClient, sessionID uint64, policy upstreamPolicy) (string, error) {
	params, err := json.Marshal(createParams{UpstreamPolicy: policy})
	if err != nil {
		return "", err
	}
	result, err := invokeContext(ctx, client, sessionID, 1, sidecar.OperationCreateSession, params, nil)
	if err != nil {
		return "", fmt.Errorf("create Hub session: %w", err)
	}
	var data attachmentResult
	if err := decodeResult(result.Data, &data); err != nil || data.State != "created" || !validToken(data.AttachmentToken) {
		return "", errors.New("create Hub session returned invalid data")
	}
	return data.AttachmentToken, nil
}

func createProviderSession(ctx context.Context, client *sidecar.RPCClient, sessionID uint64, credentialID string, policy upstreamPolicy) (string, error) {
	params, err := json.Marshal(bindParams{CredentialID: credentialID, UpstreamPolicy: policy})
	if err != nil {
		return "", err
	}
	result, err := invokeContext(ctx, client, sessionID, 1, sidecar.OperationBindCredential, params, nil)
	if err != nil {
		return "", fmt.Errorf("bind Provider credential: %w", err)
	}
	var data attachmentResult
	if err := decodeResult(result.Data, &data); err != nil || data.State != "credential_bound" || !validToken(data.AttachmentToken) {
		return "", errors.New("bind Provider credential returned invalid data")
	}
	return data.AttachmentToken, nil
}

func (s *SidecarSession) runHandshake(ctx context.Context) error {
	type outcome struct {
		role   string
		result sidecar.RPCResult
		err    error
	}
	results := make(chan outcome, 2)
	for _, participant := range []struct {
		role   string
		client *sidecar.RPCClient
	}{
		{role: sidecar.RoleHub, client: s.hub},
		{role: sidecar.RoleProvider, client: s.provider},
	} {
		participant := participant
		go func() {
			result, err := invokeContext(
				ctx,
				participant.client, s.id, 2, sidecar.OperationRunHandshake,
				json.RawMessage(`{}`), nil,
			)
			results <- outcome{role: participant.role, result: result, err: err}
		}()
	}

	var hub, provider sidecar.RPCResult
	for range 2 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result := <-results:
			if result.err != nil {
				return fmt.Errorf("%s sidecar handshake: %w", result.role, result.err)
			}
			if result.role == sidecar.RoleHub {
				hub = result.result
			} else {
				provider = result.result
			}
		}
	}

	var hubData struct {
		State                 string `json:"state"`
		TLSVersion            string `json:"tls_version"`
		UpstreamAuthenticated bool   `json:"upstream_authenticated"`
	}
	if err := decodeResult(hub.Data, &hubData); err != nil || hubData.State != "ready" ||
		hubData.TLSVersion != s.key.Version() || !hubData.UpstreamAuthenticated {
		return errors.New("Hub sidecar did not authenticate a ready session of the configured TLS version")
	}
	var providerData struct {
		State      string `json:"state"`
		TLSVersion string `json:"tls_version"`
	}
	if err := decodeResult(provider.Data, &providerData); err != nil ||
		providerData.State != "handshake_running" || providerData.TLSVersion != s.key.Version() {
		return errors.New("Provider sidecar did not retain the configured TLS session")
	}
	return nil
}

func (s *SidecarSession) startTransportTasks() {
	// Keep the task count nonzero until every relay has been registered. An
	// immediately failed first relay may concurrently start Close/Wait.
	s.tasks.Add(1)
	defer s.tasks.Done()
	s.startTask(func() error {
		return relayMPC(s.ctx, s.hubMPC, s.providerMPC)
	})
	if s.localBridge != nil {
		s.startTask(func() error {
			var unexpected [1]byte
			_, err := s.localBridge.Read(unexpected[:])
			return err
		})
	} else {
		s.startTask(func() error {
			return sidecar.BridgeProviderUpstream(s.ctx, s.providerWire, s.upstream)
		})
	}
}

func (s *SidecarSession) startTask(run func() error) {
	s.tasks.Add(1)
	go func() {
		defer s.tasks.Done()
		_ = run()
		if s.ctx.Err() == nil {
			s.healthy.Store(false)
			s.cancel()
		}
		// Cancelling relay tasks alone leaves the authenticated response reader
		// blocked. Close every attachment as well. Close waits for tasks, so it
		// must run outside this task to avoid waiting for itself.
		go func() { _ = s.Close() }()
	}()
}

func relayMPC(ctx context.Context, hub, provider *sidecar.Attachment) error {
	if ctx == nil || hub == nil || provider == nil {
		return errors.New("MPC relay requires both attachments")
	}
	abort := func() {
		_ = hub.Abort()
		_ = provider.Abort()
	}
	stop := context.AfterFunc(ctx, abort)
	defer stop()
	results := make(chan error, 2)
	copyDirection := func(destination, source *sidecar.Attachment) {
		_, err := io.CopyBuffer(destination, source, make([]byte, protocol.MaxDataFrameSize))
		if closeErr := destination.CloseWrite(); err == nil {
			err = closeErr
		}
		results <- err
	}
	go copyDirection(provider, hub)
	go copyDirection(hub, provider)
	first := <-results
	abort()
	second := <-results
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	return errors.Join(first, second)
}

// RequestResult is the sidecars' independently bound request metadata and the
// Provider's cumulative socket-delivery acknowledgement.
type RequestResult struct {
	TaskID            string
	RequestedModel    string
	Streaming         bool
	PublicRequestHash string
	CumulativeBytes   uint64
	RequestBytes      uint64
	CiphertextSHA256  string
}

// EncryptAndDeliver installs the Hub plan, contributes the Provider-local
// credential, and waits for an unambiguous complete upstream socket write.
func (s *SidecarSession) EncryptAndDeliver(
	ctx context.Context,
	params sidecar.SelectiveRequestParams,
	canonicalRequest []byte,
) (RequestResult, error) {
	if ctx == nil {
		return RequestResult{}, errors.New("request context is required")
	}
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	if !s.Healthy() {
		return RequestResult{}, errors.New("sidecar session is not healthy")
	}
	if len(canonicalRequest) == 0 || len(canonicalRequest) > int(s.key.Capacity.MaxRequestBytes) {
		return RequestResult{}, errors.New("canonical request exceeds the session capacity")
	}
	encodedParams, err := json.Marshal(params)
	if err != nil {
		return RequestResult{}, err
	}
	stop := context.AfterFunc(ctx, func() { _ = s.Close() })
	defer stop()
	requestID := s.nextRPC.Add(1) + 2

	hubResult, err := invoke(
		s.hub, s.id, requestID, sidecar.OperationEncryptRequest,
		encodedParams, canonicalRequest,
	)
	if err != nil {
		s.fail()
		return RequestResult{}, fmt.Errorf("prepare Hub request: %w", err)
	}
	providerResult, err := invoke(
		s.provider, s.id, requestID, sidecar.OperationContributeRequestEncryption,
		encodedParams, canonicalRequest,
	)
	if err != nil {
		s.fail()
		return RequestResult{}, fmt.Errorf("deliver Provider request: %w", err)
	}

	var hubData struct {
		State             string `json:"state"`
		TaskID            string `json:"task_id"`
		RequestedModel    string `json:"requested_model"`
		Streaming         bool   `json:"streaming"`
		PublicRequestHash string `json:"public_request_hash"`
	}
	if err := decodeResult(hubResult.Data, &hubData); err != nil || hubData.State != "request_prepared" {
		s.fail()
		return RequestResult{}, errors.New("Hub sidecar returned invalid request binding")
	}
	var providerData struct {
		State             string `json:"state"`
		TaskID            string `json:"task_id"`
		RequestedModel    string `json:"requested_model"`
		Streaming         bool   `json:"streaming"`
		PublicRequestHash string `json:"public_request_hash"`
		UpstreamDelivery  struct {
			CumulativeBytes uint64 `json:"cumulative_bytes"`
			RequestBytes    uint64 `json:"request_bytes"`
			SHA256          string `json:"sha256"`
		} `json:"upstream_delivery"`
	}
	if err := decodeResult(providerResult.Data, &providerData); err != nil ||
		providerData.State != "request_delivered" || providerData.UpstreamDelivery.RequestBytes == 0 ||
		providerData.UpstreamDelivery.CumulativeBytes < providerData.UpstreamDelivery.RequestBytes ||
		!validSHA256(providerData.UpstreamDelivery.SHA256) {
		s.fail()
		return RequestResult{}, errors.New("Provider sidecar returned invalid delivery evidence")
	}
	if hubData.TaskID != providerData.TaskID || hubData.RequestedModel != providerData.RequestedModel ||
		hubData.Streaming != providerData.Streaming || hubData.PublicRequestHash != providerData.PublicRequestHash {
		s.fail()
		return RequestResult{}, errors.New("Hub and Provider request bindings do not match")
	}
	if !stop() {
		s.fail()
		return RequestResult{}, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		s.fail()
		return RequestResult{}, err
	}
	return RequestResult{
		TaskID:            hubData.TaskID,
		RequestedModel:    hubData.RequestedModel,
		Streaming:         hubData.Streaming,
		PublicRequestHash: hubData.PublicRequestHash,
		CumulativeBytes:   providerData.UpstreamDelivery.CumulativeBytes,
		RequestBytes:      providerData.UpstreamDelivery.RequestBytes,
		CiphertextSHA256:  providerData.UpstreamDelivery.SHA256,
	}, nil
}

func (s *SidecarSession) ID() uint64 { return s.id }

func (s *SidecarSession) Key() Key { return s.key }

// Responses returns the single authenticated HTTP/1.1 parser bound to the
// live Hub response attachment. Callers must fully consume each response.
func (s *SidecarSession) Responses() *response.Stream { return s.responses }

func (s *SidecarSession) Healthy() bool {
	return s != nil && s.healthy.Load() && s.ctx.Err() == nil
}

func (s *SidecarSession) fail() {
	s.healthy.Store(false)
	s.cancel()
}

func (s *SidecarSession) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.healthy.Store(false)
		s.cancel()
		// Closing the physical connection first also unblocks stalled stream writes.
		if s.releaseTransport != nil {
			s.releaseTransport()
		}
		var errs []error
		if s.responseWire != nil {
			errs = append(errs, s.responseWire.Abort())
		}
		if s.responses != nil {
			errs = append(errs, s.responses.Close())
		}
		for _, attachment := range []*sidecar.Attachment{s.hubMPC, s.providerMPC, s.providerWire} {
			if attachment != nil {
				errs = append(errs, attachment.Abort())
			}
		}
		if s.localBridge != nil {
			errs = append(errs, s.localBridge.Close())
		}
		if s.upstream != nil {
			errs = append(errs, s.upstream.Close())
		}
		if s.hub != nil {
			errs = append(errs, s.hub.Close())
		}
		if s.provider != nil {
			errs = append(errs, s.provider.Close())
		}
		s.tasks.Wait()
		s.closeErr = errors.Join(errs...)
	})
	return s.closeErr
}

func invoke(
	client *sidecar.RPCClient,
	sessionID, requestID uint64,
	operation sidecar.Operation,
	params json.RawMessage,
	stream []byte,
) (sidecar.RPCResult, error) {
	if err := client.WriteCommand(sessionID, sidecar.RPCCommand{
		RequestID: requestID,
		Operation: operation,
		Params:    params,
	}); err != nil {
		return sidecar.RPCResult{}, err
	}
	if stream != nil {
		if err := client.WriteStream(sessionID, bytes.NewReader(stream)); err != nil {
			return sidecar.RPCResult{}, err
		}
	}
	result, err := client.ReadResult(sessionID, requestID)
	if err != nil {
		return sidecar.RPCResult{}, err
	}
	if result.Status != sidecar.RPCStatusOK {
		return sidecar.RPCResult{}, &sidecar.RPCRemoteError{Code: result.ErrorCode}
	}
	return result, nil
}

func invokeContext(
	ctx context.Context,
	client *sidecar.RPCClient,
	sessionID, requestID uint64,
	operation sidecar.Operation,
	params json.RawMessage,
	stream []byte,
) (sidecar.RPCResult, error) {
	if ctx == nil {
		return sidecar.RPCResult{}, errors.New("sidecar operation context is required")
	}
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	result, err := invoke(client, sessionID, requestID, operation, params, stream)
	if !stop() {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return sidecar.RPCResult{}, ctxErr
		}
	}
	return result, err
}

func decodeResult(data json.RawMessage, destination any) error {
	if len(data) == 0 {
		return errors.New("missing sidecar result data")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple sidecar result values")
		}
		return err
	}
	return nil
}

func validToken(value string) bool {
	return len(value) == 64 && validLowerHex(value)
}

func validSHA256(value string) bool {
	return len(value) == 64 && validLowerHex(value)
}

func validLowerHex(value string) bool {
	for _, character := range []byte(value) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
