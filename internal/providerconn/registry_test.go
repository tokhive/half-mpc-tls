package providerconn

import (
	"context"
	"net"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/egress"
	"tokenhive.local/half-mpc-tls/internal/protocol"
	"tokenhive.local/half-mpc-tls/internal/tunnel"
)

type routingDialer struct {
	connections chan net.Conn
}

func (d routingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return <-d.connections, nil
}

func TestRegistryRoutesSidecarAndUpstreamThroughProviderTunnel(t *testing.T) {
	hub, provider := net.Pipe()
	policy, err := egress.NewPolicy([]string{SidecarHost, "api.openai.com"}, []uint16{SidecarPort, 443})
	if err != nil {
		t.Fatal(err)
	}
	dials := make(chan net.Conn, 2)
	serveCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = (&tunnel.Provider{Policy: policy, Dialer: routingDialer{connections: dials}}).Serve(serveCtx, provider)
	}()
	registry := NewRegistry()
	defer registry.Close()
	generation, err := registry.Attach("provider-1", hub)
	if err != nil {
		t.Fatal(err)
	}

	remoteSidecar, localSidecar := net.Pipe()
	dials <- localSidecar
	ctx, cancelOpen := context.WithTimeout(context.Background(), time.Second)
	defer cancelOpen()
	connection, err := registry.DialProviderSidecar(ctx, "provider-1")
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	go func() { _, _ = remoteSidecar.Write([]byte("sidecar")) }()
	buffer := make([]byte, 7)
	if _, err := connection.Read(buffer); err != nil || string(buffer) != "sidecar" {
		t.Fatalf("sidecar tunnel: %q err=%v", buffer, err)
	}
	_ = remoteSidecar.Close()

	remoteUpstream, localUpstream := net.Pipe()
	dials <- localUpstream
	upstream, err := registry.OpenProvider(ctx, "provider-1", protocol.Target{Host: "api.openai.com", Port: 443})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() { _, _ = remoteUpstream.Write([]byte("upstream")) }()
	buffer = make([]byte, 8)
	if _, err := upstream.Read(buffer); err != nil || string(buffer) != "upstream" {
		t.Fatalf("upstream tunnel: %q err=%v", buffer, err)
	}
	_ = remoteUpstream.Close()

	registry.Detach("provider-1", generation-1)
	remoteCheck, localCheck := net.Pipe()
	dials <- localCheck
	check, err := registry.OpenProvider(ctx, "provider-1", protocol.Target{Host: "api.openai.com", Port: 443})
	if err != nil {
		t.Fatalf("stale detach removed current generation: %v", err)
	}
	_ = check.Close()
	_ = remoteCheck.Close()
	registry.Detach("provider-1", generation)
	if _, err := registry.DialProviderSidecar(ctx, "provider-1"); err == nil {
		t.Fatal("detached Provider remained available")
	}
}
