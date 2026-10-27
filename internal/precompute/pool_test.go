package precompute

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/sidecar"
)

type testResource struct {
	healthy    atomic.Bool
	closeCalls atomic.Int32
	closeOnce  sync.Once
}

func newTestResource() *testResource {
	resource := &testResource{}
	resource.healthy.Store(true)
	return resource
}

func (r *testResource) Healthy() bool { return r.healthy.Load() }

func (r *testResource) Close() error {
	r.closeOnce.Do(func() {
		r.healthy.Store(false)
		r.closeCalls.Add(1)
	})
	return nil
}

type testWarmer struct {
	mu        sync.Mutex
	calls     int
	failures  int
	gate      <-chan struct{}
	resources []*testResource
}

func (w *testWarmer) Warm(ctx context.Context, _ Key) (Resource, error) {
	if w.gate != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-w.gate:
		}
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls++
	if w.calls <= w.failures {
		return nil, errors.New("injected warm failure")
	}
	resource := newTestResource()
	w.resources = append(w.resources, resource)
	return resource, nil
}

func (w *testWarmer) snapshot() (int, []*testResource) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.calls, append([]*testResource(nil), w.resources...)
}

func testKey() Key {
	return Key{
		ProviderID:   "provider-1",
		CredentialID: "credential-1",
		Host:         "api.example.com",
		Port:         443,
		ServerName:   "api.example.com",
		Capacity:     sidecar.BaselineMPCCapacity(),
	}
}

func testConfig() Config {
	return Config{
		TargetReady:         1,
		MaxSessions:         2,
		WarmConcurrency:     1,
		WarmTimeout:         time.Second,
		RetryMin:            5 * time.Millisecond,
		RetryMax:            20 * time.Millisecond,
		MaxIdle:             time.Second,
		MaxLifetime:         5 * time.Second,
		HealthCheckInterval: 5 * time.Millisecond,
		MaxUses:             1,
	}
}

func TestPoolPrewarmsAndRefillsAfterAcquire(t *testing.T) {
	warmer := &testWarmer{}
	config := testConfig()
	config.TargetReady = 2
	config.MaxSessions = 3
	config.WarmConcurrency = 2
	pool, err := NewPool(context.Background(), warmer, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key := testKey()
	if err := pool.Register(key); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		stats, _ := pool.Stats(key)
		return stats.Ready == 2 && stats.Warming == 0
	})

	lease, err := pool.Acquire(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	resource := lease.Resource().(*testResource)
	if stats, _ := pool.Stats(key); stats.AcquireHits != 1 || stats.AcquireMisses != 0 {
		t.Fatalf("ready acquire was not recorded as a hit: %+v", stats)
	}
	waitFor(t, func() bool {
		stats, _ := pool.Stats(key)
		return stats.Ready == 2 && stats.Leased == 1
	})
	lease.Discard()
	if resource.closeCalls.Load() != 1 {
		t.Fatalf("discard closed resource %d times", resource.closeCalls.Load())
	}
	waitFor(t, func() bool {
		stats, _ := pool.Stats(key)
		return stats.Ready == 2 && stats.Leased == 0
	})
}

func TestConservativeLeaseIsOneShot(t *testing.T) {
	warmer := &testWarmer{}
	pool, err := NewPool(context.Background(), warmer, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key := testKey()
	if err := pool.Register(key); err != nil {
		t.Fatal(err)
	}
	lease, err := pool.Acquire(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	resource := lease.Resource().(*testResource)
	lease.ReleaseReusable()
	if resource.closeCalls.Load() != 1 {
		t.Fatal("MaxUses=1 must destroy the session even when released as reusable")
	}
	waitFor(t, func() bool {
		calls, _ := warmer.snapshot()
		stats, _ := pool.Stats(key)
		return calls >= 2 && stats.Ready == 1
	})
}

func TestPoolRetriesWarmFailureWithBackoff(t *testing.T) {
	warmer := &testWarmer{failures: 2}
	pool, err := NewPool(context.Background(), warmer, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key := testKey()
	if err := pool.Register(key); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		calls, _ := warmer.snapshot()
		stats, _ := pool.Stats(key)
		return calls == 3 && stats.Ready == 1 && stats.Failures == 0 &&
			stats.WarmAttempts == 3 && stats.WarmFailures == 2 && stats.WarmSuccesses == 1
	})
}

func TestPoolReplacesUnhealthyIdleSession(t *testing.T) {
	warmer := &testWarmer{}
	config := testConfig()
	config.MaxUses = 2
	config.MaxSessions = 1
	pool, err := NewPool(context.Background(), warmer, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key := testKey()
	if err := pool.Register(key); err != nil {
		t.Fatal(err)
	}
	lease, err := pool.Acquire(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	first := lease.Resource().(*testResource)
	lease.ReleaseReusable()
	first.healthy.Store(false)
	waitFor(t, func() bool {
		calls, resources := warmer.snapshot()
		stats, _ := pool.Stats(key)
		return calls >= 2 && len(resources) >= 2 && stats.Ready == 1 &&
			stats.EvictedUnhealthy == 1 && first.closeCalls.Load() == 1
	})
}

func TestPoolExpiresIdleSession(t *testing.T) {
	warmer := &testWarmer{}
	config := testConfig()
	config.MaxIdle = 15 * time.Millisecond
	config.HealthCheckInterval = 2 * time.Millisecond
	pool, err := NewPool(context.Background(), warmer, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key := testKey()
	if err := pool.Register(key); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		calls, resources := warmer.snapshot()
		stats, _ := pool.Stats(key)
		return calls >= 2 && len(resources) >= 2 && resources[0].closeCalls.Load() == 1 && stats.EvictedIdle >= 1
	})
}

func TestPoolDynamicallyScalesInventory(t *testing.T) {
	warmer := &testWarmer{}
	config := testConfig()
	config.WarmConcurrency = 3
	pool, err := NewPool(context.Background(), warmer, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key := testKey()
	if err := pool.RegisterWithLimits(key, 3, 3); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		stats, _ := pool.Stats(key)
		return stats.Ready == 3 && stats.Warming == 0
	})
	if err := pool.SetTarget(key, 1, 1); err != nil {
		t.Fatal(err)
	}
	stats, _ := pool.Stats(key)
	if stats.TargetReady != 1 || stats.MaxSessions != 1 || stats.Ready != 1 || stats.EvictedScaleDown != 2 {
		t.Fatalf("unexpected scaled-down stats: %+v", stats)
	}
	if err := pool.SetTarget(key, 2, 2); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		stats, _ := pool.Stats(key)
		return stats.TargetReady == 2 && stats.MaxSessions == 2 && stats.Ready == 2
	})
}

func TestScaleToZeroDrainsWithoutInterruptingLease(t *testing.T) {
	warmer := &testWarmer{}
	config := testConfig()
	config.MaxUses = 2
	config.MaxSessions = 1
	pool, err := NewPool(context.Background(), warmer, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key := testKey()
	if err := pool.Register(key); err != nil {
		t.Fatal(err)
	}
	lease, err := pool.Acquire(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	resource := lease.Resource().(*testResource)
	if err := pool.SetTarget(key, 0, 0); err != nil {
		t.Fatal(err)
	}
	if resource.closeCalls.Load() != 0 {
		t.Fatal("scale-to-zero interrupted an active lease")
	}
	stats, _ := pool.Stats(key)
	if stats.TargetReady != 0 || stats.MaxSessions != 0 || stats.Ready != 0 || stats.Leased != 1 {
		t.Fatalf("unexpected draining stats: %+v", stats)
	}
	lease.ReleaseReusable()
	if resource.closeCalls.Load() != 1 {
		t.Fatal("drained lease was not destroyed on release")
	}
	time.Sleep(15 * time.Millisecond)
	calls, _ := warmer.snapshot()
	if calls != 1 {
		t.Fatalf("scale-to-zero unexpectedly warmed %d sessions", calls)
	}
}

func TestPoolRecordsAcquireHitMissWaitAndCancellation(t *testing.T) {
	gate := make(chan struct{})
	warmer := &testWarmer{gate: gate}
	pool, err := NewPool(context.Background(), warmer, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key := testKey()
	if err := pool.Register(key); err != nil {
		t.Fatal(err)
	}
	leaseResult := make(chan *Lease, 1)
	go func() {
		lease, _ := pool.Acquire(context.Background(), key)
		leaseResult <- lease
	}()
	waitFor(t, func() bool {
		stats, _ := pool.Stats(key)
		return stats.AcquireMisses == 1 && stats.Warming == 1
	})
	time.Sleep(5 * time.Millisecond)
	close(gate)
	lease := <-leaseResult
	if lease == nil {
		t.Fatal("missed acquire did not receive warmed session")
	}
	lease.Discard()
	waitFor(t, func() bool {
		stats, _ := pool.Stats(key)
		return stats.AcquireWait > 0 && stats.ReleasedDiscarded == 1
	})

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	if _, err := pool.Acquire(ctx, key); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled Acquire error = %v", err)
	}
	waitFor(t, func() bool {
		stats, _ := pool.Stats(key)
		return stats.AcquireCancelled == 1
	})
}

func TestCloseCancelsWarmAndClosesOutstandingLease(t *testing.T) {
	warmer := &testWarmer{}
	pool, err := NewPool(context.Background(), warmer, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	key := testKey()
	if err := pool.Register(key); err != nil {
		t.Fatal(err)
	}
	lease, err := pool.Acquire(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	resource := lease.Resource().(*testResource)
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	if resource.closeCalls.Load() != 1 {
		t.Fatal("pool close did not destroy outstanding lease")
	}
	if _, err := pool.Acquire(context.Background(), key); !errors.Is(err, ErrClosed) {
		t.Fatalf("Acquire after Close error = %v", err)
	}
	lease.Discard()
	if resource.closeCalls.Load() != 1 {
		t.Fatal("late lease discard closed resource twice")
	}
}

func TestAcquireHonorsContextWhileWarmIsBlocked(t *testing.T) {
	gate := make(chan struct{})
	warmer := &testWarmer{gate: gate}
	config := testConfig()
	config.WarmTimeout = time.Second
	pool, err := NewPool(context.Background(), warmer, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key := testKey()
	if err := pool.Register(key); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := pool.Acquire(ctx, key); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Acquire error = %v", err)
	}
	close(gate)
}

func TestParentCancellationStopsPool(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	gate := make(chan struct{})
	pool, err := NewPool(parent, &testWarmer{gate: gate}, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key := testKey()
	if err := pool.Register(key); err != nil {
		t.Fatal(err)
	}
	cancel()
	if _, err := pool.Acquire(context.Background(), key); !errors.Is(err, ErrClosed) {
		t.Fatalf("Acquire after parent cancellation error = %v", err)
	}
	if err := pool.Register(Key{
		ProviderID:   "provider-2",
		CredentialID: "credential-2",
		Host:         "api.example.com",
		Port:         443,
		ServerName:   "api.example.com",
		Capacity:     sidecar.BaselineMPCCapacity(),
	}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Register after parent cancellation error = %v", err)
	}
}

func TestRejectsInvalidRegistrationAndConfiguration(t *testing.T) {
	if _, err := NewPool(context.Background(), &testWarmer{}, Config{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewPool error = %v", err)
	}
	pool, err := NewPool(context.Background(), &testWarmer{}, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := pool.Register(Key{}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Register error = %v", err)
	}
	if _, err := pool.Acquire(context.Background(), testKey()); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Acquire unregistered error = %v", err)
	}
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

func TestGlobalWarmConcurrencyBoundsWorkAcrossKeys(t *testing.T) {
	cfg := testConfig()
	cfg.GlobalWarmConcurrency = 2
	cfg.WarmConcurrency = 2
	started := make(chan Key, 8)
	gate := make(chan struct{})
	var active, peak atomic.Int32
	warmer := WarmerFunc(func(ctx context.Context, key Key) (Resource, error) {
		count := active.Add(1)
		defer active.Add(-1)
		for previous := peak.Load(); count > previous; previous = peak.Load() {
			if peak.CompareAndSwap(previous, count) {
				break
			}
		}
		started <- key
		select {
		case <-gate:
			return newTestResource(), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	pool, err := NewPool(context.Background(), warmer, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	keys := make([]Key, 4)
	for index := range keys {
		keys[index] = testKey()
		keys[index].CredentialID = string(rune('a' + index))
		if err := pool.Register(keys[index]); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for range 2 {
		select {
		case <-started:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	select {
	case <-started:
		t.Fatal("global warm limit exceeded")
	case <-time.After(30 * time.Millisecond):
	}
	close(gate)
	for _, key := range keys {
		lease, err := pool.Acquire(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Discard()
	}
	if peak.Load() > 2 {
		t.Fatalf("peak active warms = %d", peak.Load())
	}
}

func TestPoolCloseCancelsGlobalWarmWaiters(t *testing.T) {
	cfg := testConfig()
	cfg.GlobalWarmConcurrency = 1
	started := make(chan struct{}, 1)
	pool, err := NewPool(context.Background(), WarmerFunc(func(ctx context.Context, _ Key) (Resource, error) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, credential := range []string{"a", "b", "c"} {
		key := testKey()
		key.CredentialID = credential
		if err := pool.Register(key); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("warm did not start")
	}
	closed := make(chan struct{})
	go func() { _ = pool.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("global permit waiters blocked shutdown")
	}
}

func TestPoolTLSVersionIsolation(t *testing.T) {
	warmer := &testWarmer{}
	pool, err := NewPool(context.Background(), warmer, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	legacy := testKey()
	modern := legacy
	modern.TLSVersion = sidecar.TLS13
	if legacy.Version() != sidecar.TLS12 {
		t.Fatal("legacy default changed")
	}
	for _, key := range []Key{legacy, modern} {
		if err := pool.Register(key); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	a, err := pool.Acquire(ctx, legacy)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Discard()
	b, err := pool.Acquire(ctx, modern)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Discard()
	if a.Resource() == b.Resource() {
		t.Fatal("TLS versions shared a session")
	}
	for _, key := range []Key{legacy, modern} {
		stats, _ := pool.Stats(key)
		if stats.Leased != 1 {
			t.Fatalf("pool version isolation failed: %+v", stats)
		}
	}
	modern.TLSVersion = "auto"
	if err := pool.Register(modern); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("automatic version accepted: %v", err)
	}
}

// Waiting for inventory must not itself announce an inventory change. Otherwise
// multiple waiters wake each other indefinitely and compete with preprocessing.
func TestEmptyPoolWaitersDoNotWakeEachOther(t *testing.T) {
	gate := make(chan struct{})
	warmer := &testWarmer{gate: gate}
	cfg := testConfig()
	cfg.HealthCheckInterval = time.Hour
	pool, err := NewPool(context.Background(), warmer, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key := testKey()
	if err := pool.Register(key); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { s, _ := pool.Stats(key); return s.Warming == 1 })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	const waiters = 8
	results := make(chan error, waiters)
	for range waiters {
		go func() {
			lease, err := pool.Acquire(ctx, key)
			if err == nil {
				lease.Discard()
			}
			results <- err
		}()
	}
	waitFor(t, func() bool { s, _ := pool.Stats(key); return s.AcquireMisses == waiters })
	pool.mu.Lock()
	changed := pool.buckets[key].changed
	pool.mu.Unlock()
	select {
	case <-changed:
		t.Fatal("empty-pool waiters signaled a change without any new inventory")
	case <-time.After(50 * time.Millisecond):
	}
	close(gate)
	for range waiters {
		if err := <-results; err != nil {
			t.Fatalf("waiter did not receive replenished inventory: %v", err)
		}
	}
}
