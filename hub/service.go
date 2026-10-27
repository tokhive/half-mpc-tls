// Package hub embeds the TokenHive service in a Go application.
package hub

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"tokenhive.local/half-mpc-tls/internal/agent"
	apihttp "tokenhive.local/half-mpc-tls/internal/api"
	"tokenhive.local/half-mpc-tls/internal/coordinator"
	"tokenhive.local/half-mpc-tls/internal/precompute"
	"tokenhive.local/half-mpc-tls/internal/providerconn"
	"tokenhive.local/half-mpc-tls/internal/providerhealth"
	"tokenhive.local/half-mpc-tls/internal/settlement"
	"tokenhive.local/half-mpc-tls/internal/sidecar"
)

// Route describes an allowed upstream, model, capacity and billing policy.
type Route = coordinator.Route

// PriceSnapshot fixes billing units at admission time.
type PriceSnapshot = settlement.PriceSnapshot

// Capacity is the exact negotiated MPC request/response allocation.
type Capacity = sidecar.MPCCapacity

// FundingConfig credits an account once per unique TransactionID.
type FundingConfig struct {
	TransactionID string `json:"transaction_id"`
	ConsumerID    string `json:"consumer_id"`
	Currency      string `json:"currency"`
	AmountMicros  int64  `json:"amount_micros"`
}

// APILimits bounds request rate and active requests per Consumer account.
type APILimits struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	Burst             int     `json:"burst"`
	MaxConcurrent     int     `json:"max_concurrent"`
}

// Config owns one Hub instance. Treat maps and slices as immutable during Run.
type Config struct {
	// Queue limits apply per Provider/credential/target/capacity/TLS pool.
	// Zero selects 64 waiters and 10 seconds. RequestTimeout may be shorter.
	MaxWaiters            int               `json:"max_waiters,omitempty"`
	QueueWaitTimeoutMS    int               `json:"queue_wait_timeout_ms,omitempty"`
	APILimits             *APILimits        `json:"api_limits,omitempty"`
	BodyReadTimeout       int               `json:"body_read_timeout_seconds,omitempty"`
	GlobalWarmConcurrency int               `json:"global_warm_concurrency,omitempty"`
	APIAddress            string            `json:"api_address"`
	ControlAddress        string            `json:"control_address"`
	DataAddress           string            `json:"data_address"`
	TrustDomain           string            `json:"trust_domain"`
	CertificateFile       string            `json:"certificate_file"`
	PrivateKeyFile        string            `json:"private_key_file"`
	ProviderCAFile        string            `json:"provider_ca_file"`
	HubSidecarSockets     map[string]string `json:"hub_sidecar_sockets,omitempty"`
	HubSidecarSocket      string            `json:"hub_sidecar_socket"`
	StateDirectory        string            `json:"state_directory"`
	PlatformAccount       string            `json:"platform_account"`
	APIKeys               map[string]string `json:"api_keys"`
	Routes                []Route           `json:"routes"`
	Fundings              []FundingConfig   `json:"fundings,omitempty"`
	TargetReady           int               `json:"target_ready"`
	WarmConcurrency       int               `json:"warm_concurrency,omitempty"`
	MaxReady              int               `json:"max_ready,omitempty"`
	MaxLeased             int               `json:"max_leased,omitempty"`
	RequestTimeout        int               `json:"request_timeout_seconds"`
	HeartbeatTimeout      int               `json:"heartbeat_timeout_seconds"`
}

// CapacityProfile returns baseline, 16k, 64k, 256k, 1m or 5m limits.
// Both sidecars must be launched with the same exact profile.
func CapacityProfile(name string) (Capacity, error) { return sidecar.CapacityProfile(name) }

// RunFile loads a protected JSON configuration and serves until ctx is canceled.
func RunFile(ctx context.Context, path string) error {
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	return Run(ctx, cfg)
}

// Run starts the Consumer HTTPS API and Provider control/data listeners.
// It owns its pools, state journals and listeners, and closes them before returning.
// Each instance requires its own state directory and listener addresses.
func Run(ctx context.Context, cfg Config) error {
	if ctx == nil {
		return errors.New("nil Hub context")
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	serverTLS, providerTLS, err := tlsConfigs(cfg)
	if err != nil {
		return err
	}
	if err := ensurePrivateDirectory(cfg.StateDirectory); err != nil {
		return err
	}
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	registry := providerconn.NewRegistry()
	defer registry.Close()
	warmer, err := precompute.NewSidecarWarmer(precompute.SidecarWarmerConfig{
		HubSocket: cfg.HubSidecarSocket, HubSockets: cfg.HubSidecarSockets, ProviderDialer: registry, ProviderBridge: registry,
	})
	if err != nil {
		return err
	}
	poolConfig := precompute.ConservativeConfig(max(cfg.TargetReady, 1))
	if cfg.WarmConcurrency > 0 {
		poolConfig.WarmConcurrency = cfg.WarmConcurrency
	}
	if cfg.GlobalWarmConcurrency < 0 {
		return errors.New("global_warm_concurrency cannot be negative")
	}
	if cfg.GlobalWarmConcurrency > 0 {
		poolConfig.GlobalWarmConcurrency = cfg.GlobalWarmConcurrency
	}
	poolConfig.MaxWaiters = cfg.MaxWaiters
	poolConfig.AcquireTimeout = time.Duration(cfg.QueueWaitTimeoutMS) * time.Millisecond
	pool, err := precompute.NewPool(ctx, warmer, poolConfig)
	if err != nil {
		return err
	}
	defer pool.Close()
	autoscalerConfig := precompute.DefaultAutoscalerConfig()
	autoscalerConfig.MinReady = max(cfg.TargetReady, 1)
	autoscalerConfig.MaxReady = max(autoscalerConfig.MaxReady, autoscalerConfig.MinReady)
	if cfg.MaxReady > 0 {
		autoscalerConfig.MaxReady = cfg.MaxReady
	}
	if cfg.MaxLeased > 0 {
		autoscalerConfig.MaxLeased = cfg.MaxLeased
	}
	autoscaler, err := precompute.NewAutoscaler(ctx, pool, autoscalerConfig)
	if err != nil {
		return err
	}
	defer autoscaler.Close()
	controlHub, err := agent.NewHub(agent.HubConfig{
		TLS: providerTLS, Authorizer: agent.SPIFFEAuthorizer{TrustDomain: cfg.TrustDomain},
		HeartbeatTimeout: duration(cfg.HeartbeatTimeout, 15*time.Second),
	}, autoscaler)
	if err != nil {
		return err
	}
	allowedProviders := make(map[string]struct{})
	for _, route := range cfg.Routes {
		allowedProviders[route.ProviderID] = struct{}{}
		if err := controlHub.BindKey(route.ProviderID, route.Key()); err != nil {
			return err
		}
	}
	ledger, err := settlement.OpenDurableLedger(filepath.Join(cfg.StateDirectory, "accounts.jsonl"), cfg.PlatformAccount)
	if err != nil {
		return err
	}
	defer ledger.Close()
	for _, funding := range cfg.Fundings {
		if _, err := ledger.FundConsumer(funding.TransactionID, funding.ConsumerID, funding.Currency, funding.AmountMicros); err != nil {
			return err
		}
	}
	receipts, err := settlement.OpenJournal(filepath.Join(cfg.StateDirectory, "receipts.jsonl"))
	if err != nil {
		return err
	}
	defer receipts.Close()
	processor, err := settlement.NewProcessor(receipts, ledger)
	if err != nil {
		return err
	}
	if err := processor.ReplayPending(); err != nil {
		return err
	}
	// A receipt may have been synced just before the old Hub died. Replay it
	// first; only remaining, unverifiable work may have its reservation refunded.
	if _, err := ledger.CancelPending("hub_restarted"); err != nil {
		return err
	}
	health, err := providerhealth.Open(filepath.Join(cfg.StateDirectory, "provider-health.json"), providerhealth.DefaultConfig())
	if err != nil {
		return err
	}
	defer health.Close()
	coordinatorService, err := coordinator.New(coordinator.Config{
		Pool: pool, Ledger: ledger, Receipts: processor, Health: health, Routes: cfg.Routes,
	})
	if err != nil {
		return err
	}
	keys, err := apihttp.NewAPIKeys(cfg.APIKeys)
	if err != nil {
		return err
	}
	rateConfig := apihttp.DefaultRateLimitConfig()
	if cfg.APILimits != nil {
		rateConfig.RequestsPerSecond = cfg.APILimits.RequestsPerSecond
		rateConfig.Burst = cfg.APILimits.Burst
		rateConfig.MaxConcurrent = cfg.APILimits.MaxConcurrent
	}
	limiter, err := apihttp.NewLimiter(rateConfig)
	if err != nil {
		return err
	}
	handler, err := apihttp.NewHandler(apihttp.Config{
		Keys: keys, Limiter: limiter, Executor: coordinatorService, Info: coordinatorService, Tasks: ledger,
		BodyReadTimeout: duration(cfg.BodyReadTimeout, 30*time.Second),
		RequestTimeout:  duration(cfg.RequestTimeout, 5*time.Minute),
	})
	if err != nil {
		return err
	}

	controlListener, err := net.Listen("tcp", cfg.ControlAddress)
	if err != nil {
		return err
	}
	defer controlListener.Close()
	dataListener, err := net.Listen("tcp", cfg.DataAddress)
	if err != nil {
		return err
	}
	defer dataListener.Close()
	apiListener, err := net.Listen("tcp", cfg.APIAddress)
	if err != nil {
		return err
	}
	defer apiListener.Close()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	errorsSeen := make(chan error, 3)
	go serveControl(ctx, controlListener, controlHub, errorsSeen)
	go serveData(ctx, dataListener, providerTLS, cfg.TrustDomain, allowedProviders, registry, errorsSeen)
	go func() { errorsSeen <- server.Serve(tls.NewListener(apiListener, serverTLS)) }()
	select {
	case <-ctx.Done():
	case err = <-errorsSeen:
		stop()
	}
	_ = controlListener.Close()
	_ = dataListener.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	return err
}

func serveControl(ctx context.Context, listener net.Listener, hub *agent.Hub, output chan<- error) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				output <- err
			}
			return
		}
		go func() { _ = hub.Serve(ctx, connection) }()
	}
}

func serveData(ctx context.Context, listener net.Listener, tlsConfig *tls.Config, trustDomain string, allowed map[string]struct{}, registry *providerconn.Registry, output chan<- error) {
	authorizer := agent.SPIFFEAuthorizer{TrustDomain: trustDomain}
	for {
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() == nil {
				output <- err
			}
			return
		}
		go func() {
			tlsConnection := tls.Server(connection, tlsConfig)
			_ = tlsConnection.SetDeadline(time.Now().Add(10 * time.Second))
			if tlsConnection.HandshakeContext(ctx) != nil {
				_ = connection.Close()
				return
			}
			providerID, err := authorizer.ProviderID(tlsConnection.ConnectionState())
			if err != nil {
				_ = connection.Close()
				return
			}
			if _, ok := allowed[providerID]; !ok {
				_ = connection.Close()
				return
			}
			slot, err := providerconn.ReadDataHello(tlsConnection)
			if err != nil {
				_ = connection.Close()
				return
			}
			_ = tlsConnection.SetDeadline(time.Time{})
			generation, err := registry.AttachSlot(providerID, slot, tlsConnection)
			if err != nil {
				_ = connection.Close()
				return
			}
			select {
			case <-ctx.Done():
			case <-registry.DoneSlot(providerID, slot, generation):
			}
			registry.DetachSlot(providerID, slot, generation)
		}()
	}
}

// LoadConfig reads a mode-0600 JSON configuration with strict field checking.
func LoadConfig(path string) (Config, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return Config{}, errors.New("Hub config must be a mode-0600 regular file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return Config{}, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Config{}, errors.New("Hub config contains trailing data")
	}
	if err := validateConfig(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validateConfig(cfg Config) error {
	if cfg.APIAddress == "" || cfg.ControlAddress == "" || cfg.DataAddress == "" || cfg.StateDirectory == "" ||
		cfg.TrustDomain == "" || (cfg.HubSidecarSocket == "" && len(cfg.HubSidecarSockets) == 0) || len(cfg.Routes) == 0 {
		return errors.New("Hub listener, state, and route configuration is required")
	}
	if cfg.RequestTimeout < 0 || cfg.HeartbeatTimeout < 0 || cfg.BodyReadTimeout < 0 || cfg.WarmConcurrency < 0 ||
		cfg.GlobalWarmConcurrency < 0 || cfg.TargetReady < 0 || cfg.MaxReady < 0 || cfg.MaxLeased < 0 || cfg.MaxWaiters < 0 || cfg.QueueWaitTimeoutMS < 0 ||
		uint64(cfg.QueueWaitTimeoutMS) > uint64((1<<63-1)/int64(time.Millisecond)) {
		return errors.New("Hub timeouts and capacity limits cannot be negative")
	}
	return nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("Hub state directory must be a mode-0700 real directory")
	}
	return nil
}

func tlsConfigs(cfg Config) (*tls.Config, *tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.PrivateKeyFile)
	if err != nil {
		return nil, nil, err
	}
	ca, err := os.ReadFile(cfg.ProviderCAFile)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, nil, errors.New("Provider CA file contains no certificates")
	}
	public := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	provider := public.Clone()
	provider.ClientCAs = pool
	provider.ClientAuth = tls.RequireAndVerifyClientCert
	return public, provider, nil
}

func duration(seconds int, fallback time.Duration) time.Duration {
	if seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}
