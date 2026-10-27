// Package providerconn owns Provider-initiated reverse data tunnels.
package providerconn

import (
	"context"
	"errors"
	"net"
	"sync"

	"tokenhive.local/half-mpc-tls/internal/protocol"
	"tokenhive.local/half-mpc-tls/internal/tunnel"
)

const (
	SidecarHost = "provider-sidecar.tokenhive.internal"
	SidecarPort = uint16(1)
)

var ErrProviderUnavailable = errors.New("Provider reverse tunnel is unavailable")

type tunnelKey struct {
	provider string
	slot     uint16
}

type reservationKey struct{}

type reservation struct {
	registry   *Registry
	key        tunnelKey
	generation uint64
}

type entry struct {
	reserved   bool
	generation uint64
	client     *tunnel.Client
}

type Registry struct {
	mu      sync.RWMutex
	next    uint64
	clients map[tunnelKey]entry
	closed  bool
}

func NewRegistry() *Registry {
	return &Registry{clients: make(map[tunnelKey]entry)}
}

// Attach atomically replaces a stale Provider data tunnel. The returned
// generation must be supplied to Detach so old disconnect cleanup cannot
// remove a newer connection.
func (r *Registry) Attach(providerID string, connection net.Conn) (uint64, error) {
	return r.AttachSlot(providerID, 0, connection)
}

// AttachSlot replaces only this authenticated Provider's numbered connection.
func (r *Registry) AttachSlot(providerID string, slot uint16, connection net.Conn) (uint64, error) {
	if r == nil || !validID(providerID) || slot >= MaxDataTunnels || connection == nil {
		return 0, ErrProviderUnavailable
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return 0, ErrProviderUnavailable
	}
	client := tunnel.NewClient(connection)
	r.next++
	generation := r.next
	key := tunnelKey{providerID, slot}
	previous := r.clients[key]
	r.clients[key] = entry{generation: generation, client: client}
	r.mu.Unlock()
	if previous.client != nil {
		_ = previous.client.Close()
	}
	return generation, nil
}

func (r *Registry) Detach(providerID string, generation uint64) {
	r.DetachSlot(providerID, 0, generation)
}

func (r *Registry) DetachSlot(providerID string, slot uint16, generation uint64) {
	if r == nil {
		return
	}
	r.mu.Lock()
	current := r.clients[tunnelKey{providerID, slot}]
	if current.generation == generation {
		delete(r.clients, tunnelKey{providerID, slot})
	}
	r.mu.Unlock()
	if current.generation == generation && current.client != nil {
		_ = current.client.Close()
	}
}

func (r *Registry) Done(providerID string, generation uint64) <-chan struct{} {
	return r.DoneSlot(providerID, 0, generation)
}

func (r *Registry) DoneSlot(providerID string, slot uint16, generation uint64) <-chan struct{} {
	r.mu.RLock()
	current := r.clients[tunnelKey{providerID, slot}]
	r.mu.RUnlock()
	if current.generation == generation && current.client != nil {
		return current.client.Done()
	}
	closed := make(chan struct{})
	close(closed)
	return closed
}

func (r *Registry) OpenProvider(ctx context.Context, providerID string, target protocol.Target) (net.Conn, error) {
	client := r.client(ctx, providerID)
	if client == nil {
		return nil, ErrProviderUnavailable
	}
	connection, err := client.Open(ctx, target)
	if err != nil {
		return nil, errors.Join(ErrProviderUnavailable, err)
	}
	return connection, nil
}

func (r *Registry) DialProviderSidecar(ctx context.Context, providerID string) (net.Conn, error) {
	client := r.client(ctx, providerID)
	if client == nil {
		return nil, ErrProviderUnavailable
	}
	return client.OpenBuffered(ctx, protocol.Target{Host: SidecarHost, Port: SidecarPort})
}

func (r *Registry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	clients := make([]*tunnel.Client, 0, len(r.clients))
	r.closed = true
	for key, value := range r.clients {
		clients = append(clients, value.client)
		delete(r.clients, key)
	}
	r.mu.Unlock()
	var errs []error
	for _, client := range clients {
		errs = append(errs, client.Close())
	}
	return errors.Join(errs...)
}

// ReserveProvider pins all streams of one session to one physical connection.
// Exhaustion fails promptly so the pool can back off without holding a global
// warm permit indefinitely. A consumed connection is closed, never reassigned.
func (r *Registry) ReserveProvider(ctx context.Context, providerID string) (context.Context, func(), error) {
	if r == nil || ctx == nil || !validID(providerID) {
		return nil, nil, ErrProviderUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for slot := uint16(0); slot < MaxDataTunnels; slot++ {
		key := tunnelKey{providerID, slot}
		current := r.clients[key]
		if current.client == nil || current.reserved {
			continue
		}
		select {
		case <-current.client.Done():
			continue
		default:
		}
		current.reserved = true
		r.clients[key] = current
		pinned := reservation{r, key, current.generation}
		var once sync.Once
		release := func() { once.Do(func() { r.DetachSlot(providerID, slot, pinned.generation) }) }
		return context.WithValue(ctx, reservationKey{}, pinned), release, nil
	}
	return nil, nil, ErrProviderUnavailable
}

func (r *Registry) client(ctx context.Context, providerID string) *tunnel.Client {
	if r == nil || ctx == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if pinned, ok := ctx.Value(reservationKey{}).(reservation); ok {
		if pinned.registry != r || pinned.key.provider != providerID {
			return nil
		}
		current := r.clients[pinned.key]
		if current.generation != pinned.generation || !current.reserved {
			return nil
		}
		return current.client
	}
	// Compatibility for direct library calls, never borrow a pinned session.
	current := r.clients[tunnelKey{providerID, 0}]
	if current.reserved {
		return nil
	}
	return current.client
}

func validID(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_') {
			return false
		}
	}
	return true
}
