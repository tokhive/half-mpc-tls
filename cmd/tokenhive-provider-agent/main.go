package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"tokenhive.local/half-mpc-tls/internal/agent"
	"tokenhive.local/half-mpc-tls/internal/egress"
	"tokenhive.local/half-mpc-tls/internal/providerconn"
	"tokenhive.local/half-mpc-tls/internal/sidecar"
	"tokenhive.local/half-mpc-tls/internal/tunnel"
)

type config struct {
	DataTunnels      int               `json:"data_tunnels,omitempty"`
	ProviderID       string            `json:"provider_id"`
	InstanceID       string            `json:"instance_id"`
	ControlAddress   string            `json:"control_address"`
	DataAddress      string            `json:"data_address"`
	HubServerName    string            `json:"hub_server_name"`
	CAFile           string            `json:"ca_file"`
	CertificateFile  string            `json:"certificate_file"`
	PrivateKeyFile   string            `json:"private_key_file"`
	SidecarSockets   map[string]string `json:"sidecar_sockets,omitempty"`
	SidecarSocket    string            `json:"sidecar_socket"`
	AllowedHosts     []string          `json:"allowed_hosts"`
	AllowedPorts     []uint16          `json:"allowed_ports"`
	DrainFile        string            `json:"drain_file,omitempty"`
	HeartbeatSeconds int               `json:"heartbeat_seconds"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: tokenhive-provider-agent CONFIG.json")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintf(os.Stderr, "tokenhive-provider-agent: %v\n", err)
		os.Exit(1)
	}
}

func run(path string) error {
	var cfg config
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytesReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("Provider config contains trailing data")
	}
	if (cfg.SidecarSocket == "" && len(cfg.SidecarSockets) == 0) || len(cfg.AllowedHosts) == 0 || len(cfg.AllowedPorts) == 0 {
		return errors.New("Provider sidecar and egress allowlist are required")
	}
	if cfg.DataTunnels == 0 {
		cfg.DataTunnels = providerconn.DefaultDataTunnels
	}
	if cfg.DataTunnels < 1 || cfg.DataTunnels > providerconn.MaxDataTunnels {
		return errors.New("data_tunnels must be between 1 and 256")
	}
	tlsConfig, err := clientTLS(cfg)
	if err != nil {
		return err
	}
	interval := time.Duration(cfg.HeartbeatSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	control, err := agent.NewClient(agent.ClientConfig{
		TLS: tlsConfig, ProviderID: cfg.ProviderID, InstanceID: cfg.InstanceID,
		HeartbeatInterval: interval, AckTimeout: interval,
	})
	if err != nil {
		return err
	}
	for profile, socket := range cfg.SidecarSockets {
		if _, err := sidecar.CapacityProfile(profile); err != nil || socket == "" {
			return errors.New("invalid Provider capacity socket")
		}
	}
	upstreamPolicy, err := egress.NewPolicy(cfg.AllowedHosts, cfg.AllowedPorts)
	if err != nil {
		return err
	}
	hosts := append([]string(nil), cfg.AllowedHosts...)
	hosts = append(hosts, providerconn.SidecarHost, providerconn.BridgeHost)
	ports := append([]uint16(nil), cfg.AllowedPorts...)
	ports = append(ports, providerconn.SidecarPorts()...)
	policy, err := egress.NewPolicy(hosts, ports)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	dialer := &tls.Dialer{Config: tlsConfig}
	status := func() bool {
		if cfg.DrainFile == "" {
			return true
		}
		_, err := os.Stat(cfg.DrainFile)
		return errors.Is(err, os.ErrNotExist)
	}
	errorsSeen := make(chan error, cfg.DataTunnels+1)
	go func() {
		errorsSeen <- control.RunWithReconnect(ctx, &netDialer{}, "tcp", cfg.ControlAddress, status)
	}()
	for slot := 0; slot < cfg.DataTunnels; slot++ {
		go func(slot uint16) {
			errorsSeen <- runDataTunnel(ctx, dialer, cfg.DataAddress, policy, upstreamPolicy, cfg.SidecarSocket, cfg.SidecarSockets, slot)
		}(uint16(slot))
	}
	err = <-errorsSeen
	stop()
	for range cfg.DataTunnels {
		<-errorsSeen
	}
	return err
}

func runDataTunnel(ctx context.Context, dialer *tls.Dialer, address string, policy, upstreamPolicy *egress.Policy, sidecarSocket string, sockets map[string]string, slot uint16) error {
	backoff := 250 * time.Millisecond
	for {
		connection, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			_ = connection.SetWriteDeadline(time.Now().Add(10 * time.Second))
			err = providerconn.WriteDataHello(connection, slot)
			_ = connection.SetWriteDeadline(time.Time{})
			if err == nil {
				backoff = 250 * time.Millisecond
				err = (&tunnel.Provider{
					Policy: policy, Dialer: providerconn.AgentDialer{SidecarSocket: sidecarSocket, SidecarSockets: sockets, Policy: upstreamPolicy},
				}).Serve(ctx, connection)
			}
			_ = connection.Close()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		backoff = min(backoff*2, 15*time.Second)
	}
}

func clientTLS(cfg config) (*tls.Config, error) {
	certificate, err := tls.LoadX509KeyPair(cfg.CertificateFile, cfg.PrivateKeyFile)
	if err != nil {
		return nil, err
	}
	ca, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) || cfg.HubServerName == "" || cfg.ControlAddress == "" || cfg.DataAddress == "" {
		return nil, errors.New("invalid Provider TLS configuration")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13, ServerName: cfg.HubServerName,
		RootCAs: roots, Certificates: []tls.Certificate{certificate},
	}, nil
}

type netDialer struct{}

func (*netDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func bytesReader(data []byte) *bytes.Reader { return bytes.NewReader(data) }
