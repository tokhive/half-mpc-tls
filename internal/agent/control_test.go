package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/precompute"
	"tokenhive.local/half-mpc-tls/internal/protocol"
	"tokenhive.local/half-mpc-tls/internal/sidecar"
)

type testPoolResource struct {
	closed atomic.Bool
}

type flakyControlDialer struct {
	hub      *Hub
	failures int32
	calls    atomic.Int32
	hubDone  chan error
}

func (d *flakyControlDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	call := d.calls.Add(1)
	if call <= d.failures {
		return nil, errors.New("injected dial failure")
	}
	hubConnection, providerConnection := net.Pipe()
	go func() { d.hubDone <- d.hub.Serve(ctx, hubConnection) }()
	return providerConnection, nil
}

func (r *testPoolResource) Close() error {
	r.closed.Store(true)
	return nil
}

type controlHarness struct {
	pool       *precompute.Pool
	autoscaler *precompute.Autoscaler
	hub        *Hub
	serverTLS  *tls.Config
	clientTLS  map[string]*tls.Config
	key        precompute.Key
}

func newControlHarness(t *testing.T, heartbeatTimeout time.Duration) *controlHarness {
	t.Helper()
	serverTLS, clients := testTLSConfigs(t)
	poolConfig := precompute.ConservativeConfig(1)
	poolConfig.WarmTimeout = time.Second
	poolConfig.RetryMin = time.Millisecond
	poolConfig.RetryMax = 5 * time.Millisecond
	poolConfig.MaxIdle = time.Minute
	poolConfig.MaxLifetime = time.Minute
	poolConfig.HealthCheckInterval = 5 * time.Millisecond
	pool, err := precompute.NewPool(context.Background(), precompute.WarmerFunc(
		func(context.Context, precompute.Key) (precompute.Resource, error) {
			return &testPoolResource{}, nil
		},
	), poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	autoscalerConfig := precompute.DefaultAutoscalerConfig()
	autoscalerConfig.SampleInterval = time.Hour
	autoscalerConfig.MinReady = 1
	autoscalerConfig.MaxReady = 4
	autoscalerConfig.SessionHeadroom = 1
	autoscaler, err := precompute.NewAutoscaler(context.Background(), pool, autoscalerConfig)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	hub, err := NewHub(HubConfig{
		TLS:              serverTLS,
		Authorizer:       SPIFFEAuthorizer{TrustDomain: "tokenhive.test"},
		HeartbeatTimeout: heartbeatTimeout,
	}, autoscaler)
	if err != nil {
		autoscaler.Close()
		pool.Close()
		t.Fatal(err)
	}
	harness := &controlHarness{
		pool:       pool,
		autoscaler: autoscaler,
		hub:        hub,
		serverTLS:  serverTLS,
		clientTLS:  clients,
		key: precompute.Key{
			ProviderID:   "provider-1",
			CredentialID: "credential-1",
			Host:         "api.example.com",
			Port:         443,
			ServerName:   "api.example.com",
			Capacity:     sidecar.BaselineMPCCapacity(),
		},
	}
	if err := hub.BindKey("provider-1", harness.key); err != nil {
		autoscaler.Close()
		pool.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = autoscaler.Close()
		_ = pool.Close()
	})
	return harness
}

func TestMTLSHeartbeatDrivesAutoscalerAndDrain(t *testing.T) {
	harness := newControlHarness(t, 100*time.Millisecond)
	client, err := NewClient(ClientConfig{
		TLS:               harness.clientTLS["provider-1"],
		ProviderID:        "provider-1",
		InstanceID:        "instance-1",
		HeartbeatInterval: 5 * time.Millisecond,
		AckTimeout:        time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	hubConnection, providerConnection := net.Pipe()
	hubDone := make(chan error, 1)
	clientDone := make(chan error, 1)
	go func() { hubDone <- harness.hub.Serve(ctx, hubConnection) }()
	var accepting atomic.Bool
	accepting.Store(true)
	go func() { clientDone <- client.Run(ctx, providerConnection, accepting.Load) }()

	waitFor(t, func() bool {
		snapshot, _ := harness.hub.Snapshot("provider-1")
		stats, _ := harness.pool.Stats(harness.key)
		return snapshot.Connected && snapshot.Accepting && snapshot.LastCounter > 0 && stats.TargetReady == 1
	})
	accepting.Store(false)
	waitFor(t, func() bool {
		snapshot, _ := harness.hub.Snapshot("provider-1")
		stats, _ := harness.pool.Stats(harness.key)
		return snapshot.Connected && !snapshot.Accepting && stats.TargetReady == 0 && stats.MaxSessions == 0
	})
	accepting.Store(true)
	waitFor(t, func() bool {
		stats, _ := harness.pool.Stats(harness.key)
		return stats.TargetReady == 1
	})

	cancel()
	waitDone(t, hubDone)
	waitDone(t, clientDone)
	waitFor(t, func() bool {
		snapshot, _ := harness.hub.Snapshot("provider-1")
		stats, _ := harness.pool.Stats(harness.key)
		return !snapshot.Connected && !snapshot.Accepting && stats.TargetReady == 0
	})
}

func TestSPIFFEIdentityCannotClaimAnotherProvider(t *testing.T) {
	harness := newControlHarness(t, 100*time.Millisecond)
	client, err := NewClient(ClientConfig{
		TLS:               harness.clientTLS["provider-2"],
		ProviderID:        "provider-1",
		InstanceID:        "instance-2",
		HeartbeatInterval: 5 * time.Millisecond,
		AckTimeout:        time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	hubConnection, providerConnection := net.Pipe()
	hubDone := make(chan error, 1)
	go func() { hubDone <- harness.hub.Serve(context.Background(), hubConnection) }()
	err = client.Run(context.Background(), providerConnection, func() bool { return true })
	if !errors.Is(err, ErrAuthentication) {
		t.Fatalf("client error = %v", err)
	}
	if err := <-hubDone; !errors.Is(err, ErrAuthentication) {
		t.Fatalf("Hub error = %v", err)
	}
	stats, _ := harness.pool.Stats(harness.key)
	if stats.TargetReady != 0 {
		t.Fatal("unauthorized Provider activated warm inventory")
	}
}

func TestHeartbeatTimeoutMarksProviderOffline(t *testing.T) {
	harness := newControlHarness(t, 25*time.Millisecond)
	hubConnection, providerConnection := net.Pipe()
	hubDone := make(chan error, 1)
	go func() { hubDone <- harness.hub.Serve(context.Background(), hubConnection) }()
	tlsConnection := tls.Client(providerConnection, harness.clientTLS["provider-1"])
	defer tlsConnection.Close()
	if err := tlsConnection.Handshake(); err != nil {
		t.Fatal(err)
	}
	codec := protocol.NewCodec(tlsConnection, tlsConnection)
	if err := writeJSON(codec, protocol.FrameAgentHello, helloMessage{
		ProtocolVersion: ProtocolVersion,
		ProviderID:      "provider-1",
		InstanceID:      "manual-instance",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := codec.ReadFrame(); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(codec, protocol.FrameAgentHeartbeat, heartbeatMessage{
		Counter:         1,
		SentAtUnixMilli: time.Now().UnixMilli(),
		Accepting:       true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := codec.ReadFrame(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		stats, _ := harness.pool.Stats(harness.key)
		return stats.TargetReady == 1
	})
	select {
	case err := <-hubDone:
		if err == nil {
			t.Fatal("heartbeat timeout unexpectedly returned nil")
		}
	case <-time.After(time.Second):
		t.Fatal("Hub did not enforce heartbeat timeout")
	}
	waitFor(t, func() bool {
		snapshot, _ := harness.hub.Snapshot("provider-1")
		stats, _ := harness.pool.Stats(harness.key)
		return !snapshot.Connected && stats.TargetReady == 0
	})
}

func TestHeartbeatCounterReplayFailsClosed(t *testing.T) {
	harness := newControlHarness(t, 100*time.Millisecond)
	hubConnection, providerConnection := net.Pipe()
	hubDone := make(chan error, 1)
	go func() { hubDone <- harness.hub.Serve(context.Background(), hubConnection) }()
	tlsConnection := tls.Client(providerConnection, harness.clientTLS["provider-1"])
	defer tlsConnection.Close()
	if err := tlsConnection.Handshake(); err != nil {
		t.Fatal(err)
	}
	codec := protocol.NewCodec(tlsConnection, tlsConnection)
	if err := writeJSON(codec, protocol.FrameAgentHello, helloMessage{
		ProtocolVersion: ProtocolVersion,
		ProviderID:      "provider-1",
		InstanceID:      "replay-instance",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := codec.ReadFrame(); err != nil {
		t.Fatal(err)
	}
	heartbeat := heartbeatMessage{Counter: 1, SentAtUnixMilli: time.Now().UnixMilli(), Accepting: true}
	if err := writeJSON(codec, protocol.FrameAgentHeartbeat, heartbeat); err != nil {
		t.Fatal(err)
	}
	if _, err := codec.ReadFrame(); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(codec, protocol.FrameAgentHeartbeat, heartbeat); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-hubDone:
		if !errors.Is(err, ErrProtocol) {
			t.Fatalf("Hub replay error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Hub did not reject replayed heartbeat counter")
	}
	waitFor(t, func() bool {
		stats, _ := harness.pool.Stats(harness.key)
		return stats.TargetReady == 0
	})
}

func TestClientReconnectsAfterTransportFailures(t *testing.T) {
	harness := newControlHarness(t, 100*time.Millisecond)
	client, err := NewClient(ClientConfig{
		TLS:               harness.clientTLS["provider-1"],
		ProviderID:        "provider-1",
		InstanceID:        "reconnect-instance",
		HeartbeatInterval: 5 * time.Millisecond,
		AckTimeout:        time.Second,
		ReconnectMin:      time.Millisecond,
		ReconnectMax:      2 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	dialer := &flakyControlDialer{hub: harness.hub, failures: 2, hubDone: make(chan error, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	clientDone := make(chan error, 1)
	go func() {
		clientDone <- client.RunWithReconnect(ctx, dialer, "tcp", "hub.test:443", func() bool { return true })
	}()
	waitFor(t, func() bool {
		stats, _ := harness.pool.Stats(harness.key)
		return dialer.calls.Load() >= 3 && stats.TargetReady == 1
	})
	cancel()
	if err := <-clientDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("reconnecting client error = %v", err)
	}
	waitDone(t, dialer.hubDone)
}

func TestClientRejectsDisabledServerVerification(t *testing.T) {
	_, clients := testTLSConfigs(t)
	config := clients["provider-1"].Clone()
	config.InsecureSkipVerify = true
	if _, err := NewClient(ClientConfig{
		TLS:               config,
		ProviderID:        "provider-1",
		InstanceID:        "instance-1",
		HeartbeatInterval: time.Second,
		AckTimeout:        time.Second,
	}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("NewClient error = %v", err)
	}
}

func testTLSConfigs(t *testing.T) (*tls.Config, map[string]*tls.Config) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "TokenHive test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)

	issue := func(serial int64, dnsName, providerID string, usage x509.ExtKeyUsage) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: dnsName},
			NotBefore:    now.Add(-time.Hour),
			NotAfter:     now.Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		}
		if dnsName != "" {
			template.DNSNames = []string{dnsName}
		}
		if providerID != "" {
			template.URIs = []*url.URL{{
				Scheme: "spiffe",
				Host:   "tokenhive.test",
				Path:   "/provider/" + providerID,
			}}
		}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	}

	serverCertificate := issue(2, "hub.test", "", x509.ExtKeyUsageServerAuth)
	clients := make(map[string]*tls.Config)
	for index, providerID := range []string{"provider-1", "provider-2"} {
		clients[providerID] = &tls.Config{
			MinVersion:   tls.VersionTLS13,
			ServerName:   "hub.test",
			RootCAs:      roots,
			Certificates: []tls.Certificate{issue(int64(index+3), "", providerID, x509.ExtKeyUsageClientAuth)},
		}
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{serverCertificate},
		ClientCAs:    roots,
	}, clients
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition was not met before deadline")
		}
		time.Sleep(time.Millisecond)
	}
}

func waitDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("control connection did not stop")
	}
}
