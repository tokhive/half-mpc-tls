// Package precompute maintains request-independent, fully warmed MPC-TLS
// sessions. Preprocessing material is one-time and remains owned by the live
// session which produced it; the pool never serializes or clones it.
package precompute

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"tokenhive.local/half-mpc-tls/internal/sidecar"
)

var (
	ErrClosed        = errors.New("precompute pool is closed")
	ErrKeyNotFound   = errors.New("precompute pool key is not registered")
	ErrInvalidConfig = errors.New("invalid precompute pool configuration")
	ErrInvalidKey    = errors.New("invalid precompute pool key")
	ErrQueueFull     = errors.New("precompute wait queue is full")
	ErrWaitTimeout   = errors.New("precompute wait deadline exceeded")
)

// Key isolates sessions which cannot safely be exchanged. CredentialID is a
// Provider-local reference, never credential material.
type Key struct {
	TLSVersion   string
	ProviderID   string
	CredentialID string
	Host         string
	Port         uint16
	ServerName   string
	Capacity     sidecar.MPCCapacity
}

// Version preserves the TLS 1.2 default for existing integrations.
func (k Key) Version() string {
	if k.TLSVersion == "" {
		return sidecar.TLS12
	}
	return k.TLSVersion
}

func (k Key) Validate() error {
	if k.Version() != sidecar.TLS12 && k.Version() != sidecar.TLS13 {
		return ErrInvalidKey
	}
	if k.ProviderID == "" || k.CredentialID == "" || k.Host == "" || k.Port == 0 || k.ServerName == "" {
		return ErrInvalidKey
	}
	if k.Capacity.MaxRequestBytes == 0 || k.Capacity.MaxRequestRecords == 0 ||
		k.Capacity.MaxResponseBytes == 0 || k.Capacity.MaxResponseRecordsOnline == 0 {
		return ErrInvalidKey
	}
	return nil
}

// Resource is a live MPC-TLS session whose preprocessing and upstream TLS
// handshake have completed. Close must be safe to call more than once.
type Resource interface {
	Close() error
}

// HealthChecker lets the pool discard a session whose MPC channel or upstream
// connection failed while it was idle.
type HealthChecker interface {
	Healthy() bool
}

// Warmer creates one request-independent live session for key. Implementations
// must honor ctx and close partially-created state on every error path.
type Warmer interface {
	Warm(context.Context, Key) (Resource, error)
}

type WarmerFunc func(context.Context, Key) (Resource, error)

func (f WarmerFunc) Warm(ctx context.Context, key Key) (Resource, error) {
	return f(ctx, key)
}

// Config controls the inventory for every registered key. TargetReady is the
// number of idle sessions maintained even while other sessions are leased.
type Config struct {
	// Zero selects defaults of 64 waiters per key and 10 seconds of queue wait.
	// An earlier caller deadline always wins. Neither limit bounds execution.
	MaxWaiters            int
	AcquireTimeout        time.Duration
	TargetReady           int
	MaxSessions           int
	WarmConcurrency       int
	GlobalWarmConcurrency int
	WarmTimeout           time.Duration
	RetryMin              time.Duration
	RetryMax              time.Duration
	MaxIdle               time.Duration
	MaxLifetime           time.Duration
	HealthCheckInterval   time.Duration
	MaxUses               uint32
}

func (c Config) validate() error {
	if c.TargetReady <= 0 || c.MaxSessions < c.TargetReady || c.WarmConcurrency <= 0 ||
		c.GlobalWarmConcurrency < 0 || c.MaxWaiters < 0 || c.AcquireTimeout < 0 || c.WarmTimeout <= 0 || c.RetryMin <= 0 || c.RetryMax < c.RetryMin ||
		c.MaxIdle <= 0 || c.MaxLifetime <= 0 || c.HealthCheckInterval <= 0 || c.MaxUses == 0 {
		return ErrInvalidConfig
	}
	return nil
}

// ConservativeConfig creates one-shot sessions. It shifts preprocessing and
// the upstream TLS handshake out of request latency without assuming that
// unused MPC capacity can be safely reused.
func ConservativeConfig(targetReady int) Config {
	return Config{
		MaxWaiters:            64,
		AcquireTimeout:        10 * time.Second,
		TargetReady:           targetReady,
		MaxSessions:           targetReady + 1,
		WarmConcurrency:       1,
		GlobalWarmConcurrency: 2,
		WarmTimeout:           25 * time.Minute,
		RetryMin:              250 * time.Millisecond,
		RetryMax:              15 * time.Second,
		MaxIdle:               2 * time.Minute,
		MaxLifetime:           30 * time.Minute,
		HealthCheckInterval:   5 * time.Second,
		MaxUses:               1,
	}
}

type item struct {
	resource  Resource
	createdAt time.Time
	idleSince time.Time
	uses      uint32
	closeOnce sync.Once
}

func (i *item) close() {
	i.closeOnce.Do(func() { _ = i.resource.Close() })
}

type bucket struct {
	waiters     list.List // FIFO of *waiter; guarded by Pool.mu
	registered  bool
	targetReady int
	maxSessions int
	ready       []*item
	leased      map[*item]struct{}
	warming     int
	failures    uint32
	nextAttempt time.Time
	changed     chan struct{}

	warmAttempts        uint64
	warmSuccesses       uint64
	warmFailures        uint64
	warmDiscarded       uint64
	warmDuration        time.Duration
	warmSuccessDuration time.Duration
	lastWarmDuration    time.Duration
	acquireHits         uint64
	acquireMisses       uint64
	acquireCancelled    uint64
	acquireRejected     uint64
	acquireTimedOut     uint64
	acquireWait         time.Duration
	evictedUnhealthy    uint64
	evictedIdle         uint64
	evictedLifetime     uint64
	evictedScaleDown    uint64
	releasedReusable    uint64
	releasedDiscarded   uint64
}

type waiter struct {
	notify chan struct{}
}

// Stats is an instantaneous per-key inventory snapshot.
type Stats struct {
	Waiting             int
	MaxWaiters          int
	TargetReady         int
	MaxSessions         int
	Ready               int
	Leased              int
	Warming             int
	Failures            uint32
	NextAttempt         time.Time
	WarmAttempts        uint64
	WarmSuccesses       uint64
	WarmFailures        uint64
	WarmDiscarded       uint64
	WarmDuration        time.Duration
	WarmSuccessDuration time.Duration
	LastWarmDuration    time.Duration
	AcquireHits         uint64
	AcquireMisses       uint64
	AcquireCancelled    uint64
	AcquireRejected     uint64
	AcquireTimedOut     uint64
	AcquireWait         time.Duration
	EvictedUnhealthy    uint64
	EvictedIdle         uint64
	EvictedLifetime     uint64
	EvictedScaleDown    uint64
	ReleasedReusable    uint64
	ReleasedDiscarded   uint64
}

// Pool owns all idle and leased resources until Close. A caller must finish a
// lease with ReleaseReusable or Discard.
type Pool struct {
	warmer      Warmer
	warmPermits chan struct{}
	config      Config
	now         func() time.Time

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	buckets map[Key]*bucket
	closed  bool
	wg      sync.WaitGroup
}

func NewPool(parent context.Context, warmer Warmer, config Config) (*Pool, error) {
	if parent == nil || warmer == nil {
		return nil, ErrInvalidConfig
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	if config.GlobalWarmConcurrency == 0 {
		config.GlobalWarmConcurrency = 2
	}
	if config.MaxWaiters == 0 {
		config.MaxWaiters = 64
	}
	if config.AcquireTimeout == 0 {
		config.AcquireTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithCancel(parent)
	return &Pool{
		warmer:      warmer,
		warmPermits: make(chan struct{}, config.GlobalWarmConcurrency),
		config:      config,
		now:         time.Now,
		ctx:         ctx,
		cancel:      cancel,
		buckets:     make(map[Key]*bucket),
	}, nil
}

// Register begins maintaining the configured idle inventory for key.
func (p *Pool) Register(key Key) error {
	return p.RegisterWithLimits(key, p.config.TargetReady, p.config.MaxSessions)
}

// RegisterWithLimits begins maintaining a key with its own inventory limits.
// Re-registering an existing key updates its limits atomically.
func (p *Pool) RegisterWithLimits(key Key, targetReady, maxSessions int) error {
	if err := key.Validate(); err != nil {
		return err
	}
	if err := validateInventoryLimits(targetReady, maxSessions); err != nil {
		return err
	}
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return ErrClosed
	}
	if existing := p.buckets[key]; existing != nil && existing.registered {
		discard := p.resizeLocked(existing, targetReady, maxSessions)
		p.mu.Unlock()
		closeItems(discard)
		return nil
	}
	b := &bucket{
		registered:  true,
		targetReady: targetReady,
		maxSessions: maxSessions,
		leased:      make(map[*item]struct{}),
		changed:     make(chan struct{}),
	}
	p.buckets[key] = b
	p.wg.Add(p.config.WarmConcurrency)
	for range p.config.WarmConcurrency {
		go p.worker(key, b)
	}
	p.signalLocked(b)
	p.mu.Unlock()
	return nil
}

// SetTarget changes a registered key's desired idle inventory. A zero target
// and zero maximum drain idle sessions and cause outstanding leases to be
// destroyed when returned, without interrupting active requests.
func (p *Pool) SetTarget(key Key, targetReady, maxSessions int) error {
	if err := validateInventoryLimits(targetReady, maxSessions); err != nil {
		return err
	}
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return ErrClosed
	}
	b := p.buckets[key]
	if b == nil || !b.registered {
		p.mu.Unlock()
		return ErrKeyNotFound
	}
	discard := p.resizeLocked(b, targetReady, maxSessions)
	p.mu.Unlock()
	closeItems(discard)
	return nil
}

func validateInventoryLimits(targetReady, maxSessions int) error {
	if targetReady < 0 || maxSessions < targetReady {
		return ErrInvalidConfig
	}
	return nil
}

func (p *Pool) resizeLocked(b *bucket, targetReady, maxSessions int) []*item {
	b.targetReady = targetReady
	b.maxSessions = maxSessions
	keep := min(len(b.ready), targetReady)
	available := max(maxSessions-len(b.leased), 0)
	keep = min(keep, available)
	discardCount := len(b.ready) - keep
	discard := append([]*item(nil), b.ready[:discardCount]...)
	b.ready = b.ready[discardCount:]
	b.evictedScaleDown += uint64(len(discard))
	p.signalLocked(b)
	return discard
}

// Unregister destroys the key's idle and leased sessions and stops refill.
func (p *Pool) Unregister(key Key) error {
	p.mu.Lock()
	b := p.buckets[key]
	if b == nil || !b.registered {
		p.mu.Unlock()
		return ErrKeyNotFound
	}
	b.registered = false
	delete(p.buckets, key)
	items := bucketItems(b)
	b.ready = nil
	clear(b.leased)
	p.signalLocked(b)
	p.mu.Unlock()
	closeItems(items)
	return nil
}

// Acquire takes ready inventory immediately only when no older caller is queued.
// Otherwise it waits FIFO within this key, bounded by MaxWaiters, AcquireTimeout
// and the caller context. Only the head is notified when inventory is available.
func (p *Pool) Acquire(ctx context.Context, key Key) (*Lease, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrInvalidKey)
	}
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil {
		p.mu.Unlock()
		return nil, ErrClosed
	}
	b := p.buckets[key]
	if b == nil || !b.registered {
		p.mu.Unlock()
		return nil, ErrKeyNotFound
	}
	var queued *list.Element
	var waitStarted time.Time
	var deadline time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		// The bucket pointer stays fixed: unregister/re-register must not move
		// existing callers into a different inventory generation.
		var err error
		switch {
		case p.closed || p.ctx.Err() != nil:
			err = ErrClosed
		case !b.registered:
			err = ErrKeyNotFound
		case ctx.Err() != nil:
			err = ctx.Err()
		case queued != nil && !time.Now().Before(deadline):
			err = ErrWaitTimeout
		}
		if err != nil {
			if queued != nil {
				b.waiters.Remove(queued)
				b.acquireWait += p.now().Sub(waitStarted)
				p.notifyHeadLocked(b)
			}
			if errors.Is(err, ErrWaitTimeout) {
				b.acquireTimedOut++
			} else {
				b.acquireCancelled++
			}
			p.mu.Unlock()
			return nil, err
		}
		expired := p.pruneReadyLocked(b, p.now())
		if len(b.ready) > 0 && (b.waiters.Len() == 0 || queued != nil && b.waiters.Front() == queued) {
			entry := b.ready[0]
			b.ready[0] = nil
			b.ready = b.ready[1:]
			b.leased[entry] = struct{}{}
			if queued != nil {
				b.waiters.Remove(queued)
				b.acquireWait += p.now().Sub(waitStarted)
			} else {
				b.acquireHits++
			}
			p.signalLocked(b)
			p.mu.Unlock()
			closeItems(expired)
			return &Lease{pool: p, key: key, item: entry}, nil
		}
		if queued == nil {
			if b.waiters.Len() >= p.config.MaxWaiters {
				b.acquireRejected++
				p.mu.Unlock()
				closeItems(expired)
				return nil, ErrQueueFull
			}
			waitStarted = p.now()
			deadline = time.Now().Add(p.config.AcquireTimeout)
			timer = time.NewTimer(p.config.AcquireTimeout)
			queued = b.waiters.PushBack(&waiter{notify: make(chan struct{}, 1)})
			b.acquireMisses++
		}
		notify := queued.Value.(*waiter).notify
		p.mu.Unlock()
		closeItems(expired)
		select {
		case <-ctx.Done():
		case <-p.ctx.Done():
		case <-timer.C:
		case <-notify:
		}
		p.mu.Lock()
	}
}

func (p *Pool) Stats(key Key) (Stats, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	b := p.buckets[key]
	if b == nil || !b.registered {
		return Stats{}, false
	}
	return Stats{
		Waiting:             b.waiters.Len(),
		MaxWaiters:          p.config.MaxWaiters,
		TargetReady:         b.targetReady,
		MaxSessions:         b.maxSessions,
		Ready:               len(b.ready),
		Leased:              len(b.leased),
		Warming:             b.warming,
		Failures:            b.failures,
		NextAttempt:         b.nextAttempt,
		WarmAttempts:        b.warmAttempts,
		WarmSuccesses:       b.warmSuccesses,
		WarmFailures:        b.warmFailures,
		WarmDiscarded:       b.warmDiscarded,
		WarmDuration:        b.warmDuration,
		WarmSuccessDuration: b.warmSuccessDuration,
		LastWarmDuration:    b.lastWarmDuration,
		AcquireHits:         b.acquireHits,
		AcquireMisses:       b.acquireMisses,
		AcquireCancelled:    b.acquireCancelled,
		AcquireRejected:     b.acquireRejected,
		AcquireTimedOut:     b.acquireTimedOut,
		AcquireWait:         b.acquireWait,
		EvictedUnhealthy:    b.evictedUnhealthy,
		EvictedIdle:         b.evictedIdle,
		EvictedLifetime:     b.evictedLifetime,
		EvictedScaleDown:    b.evictedScaleDown,
		ReleasedReusable:    b.releasedReusable,
		ReleasedDiscarded:   b.releasedDiscarded,
	}, true
}

// Close cancels warmers and destroys all resources, including outstanding
// leases. It waits for warmer goroutines to observe cancellation.
func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.cancel()
	var items []*item
	for key, b := range p.buckets {
		b.registered = false
		items = append(items, bucketItems(b)...)
		b.ready = nil
		clear(b.leased)
		p.signalLocked(b)
		delete(p.buckets, key)
	}
	p.mu.Unlock()
	closeItems(items)
	p.wg.Wait()
	return nil
}

func (p *Pool) worker(key Key, b *bucket) {
	defer p.wg.Done()
	for {
		wait, changed, stop := p.reserveWarmSlot(b)
		if stop {
			return
		}
		if wait > 0 {
			timer := time.NewTimer(wait)
			select {
			case <-timer.C:
			case <-p.ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-changed:
				if !timer.Stop() {
					<-timer.C
				}
			}
			continue
		}

		// Bound expensive preprocessing across all providers and capacities.
		// Waiting for the shared permit is not part of the per-attempt timeout.
		select {
		case p.warmPermits <- struct{}{}:
		case <-p.ctx.Done():
			p.finishWarm(b, nil, p.ctx.Err(), 0)
			return
		}
		p.mu.Lock()
		needed := !p.closed && b.registered && len(b.ready) < b.targetReady && len(b.ready)+len(b.leased) < b.maxSessions
		if !needed {
			b.warming--
			b.warmDiscarded++
			p.signalLocked(b)
		}
		p.mu.Unlock()
		if !needed {
			<-p.warmPermits
			continue
		}
		started := p.now()
		ctx, cancel := context.WithTimeout(p.ctx, p.config.WarmTimeout)
		resource, err := p.warmer.Warm(ctx, key)
		cancel()
		<-p.warmPermits
		if resource == nil && err == nil {
			err = errors.New("precompute warmer returned a nil resource")
		}
		p.finishWarm(b, resource, err, p.now().Sub(started))
	}
}

// reserveWarmSlot captures the notification under the same lock as the inventory
// check. Subscribing later could miss an Acquire and stall refill until the timer.
func (p *Pool) reserveWarmSlot(b *bucket) (time.Duration, <-chan struct{}, bool) {
	p.mu.Lock()
	if p.closed || p.ctx.Err() != nil || !b.registered {
		p.mu.Unlock()
		return 0, nil, true
	}
	now := p.now()
	expired := p.pruneReadyLocked(b, now)
	total := len(b.ready) + len(b.leased) + b.warming
	need := len(b.ready)+b.warming < b.targetReady && total < b.maxSessions
	if need && !now.Before(b.nextAttempt) {
		b.warming++
		b.warmAttempts++
		p.signalLocked(b)
		p.mu.Unlock()
		closeItems(expired)
		return 0, nil, false
	}
	changed := b.changed
	wait := p.config.HealthCheckInterval
	if need && now.Before(b.nextAttempt) {
		wait = b.nextAttempt.Sub(now)
	} else if expiry := p.nextExpiryLocked(b); !expiry.IsZero() {
		wait = min(wait, max(expiry.Sub(now), time.Millisecond))
	}
	p.mu.Unlock()
	closeItems(expired)
	return wait, changed, false
}

func (p *Pool) finishWarm(b *bucket, resource Resource, err error, duration time.Duration) {
	var discard Resource
	p.mu.Lock()
	b.warming--
	b.lastWarmDuration = duration
	b.warmDuration += duration
	now := p.now()
	if err != nil {
		b.failures++
		b.warmFailures++
		b.nextAttempt = now.Add(p.retryDelay(b.failures))
		discard = resource
	} else {
		b.warmSuccesses++
		b.warmSuccessDuration += duration
		b.failures = 0
		b.nextAttempt = time.Time{}
		if p.closed || !b.registered || len(b.ready) >= b.targetReady || len(b.ready)+len(b.leased) >= b.maxSessions {
			b.warmDiscarded++
			discard = resource
		} else {
			b.ready = append(b.ready, &item{resource: resource, createdAt: now, idleSince: now})
		}
	}
	p.signalLocked(b)
	p.mu.Unlock()
	if discard != nil {
		_ = discard.Close()
	}
}

func (p *Pool) retryDelay(failures uint32) time.Duration {
	delay := p.config.RetryMin
	for count := uint32(1); count < failures && delay < p.config.RetryMax; count++ {
		if delay > p.config.RetryMax/2 {
			return p.config.RetryMax
		}
		delay *= 2
	}
	return min(delay, p.config.RetryMax)
}

func (p *Pool) pruneReadyLocked(b *bucket, now time.Time) []*item {
	kept := b.ready[:0]
	var expired []*item
	for _, entry := range b.ready {
		healthy := true
		if checker, ok := entry.resource.(HealthChecker); ok {
			healthy = checker.Healthy()
		}
		if !healthy {
			b.evictedUnhealthy++
			expired = append(expired, entry)
			continue
		}
		if now.Sub(entry.createdAt) >= p.config.MaxLifetime {
			b.evictedLifetime++
			expired = append(expired, entry)
			continue
		}
		if now.Sub(entry.idleSince) >= p.config.MaxIdle {
			b.evictedIdle++
			expired = append(expired, entry)
			continue
		}
		kept = append(kept, entry)
	}
	b.ready = kept
	if len(expired) > 0 {
		p.signalLocked(b)
	}
	return expired
}

func (p *Pool) nextExpiryLocked(b *bucket) time.Time {
	var next time.Time
	for _, entry := range b.ready {
		idle := entry.idleSince.Add(p.config.MaxIdle)
		lifetime := entry.createdAt.Add(p.config.MaxLifetime)
		expires := idle
		if lifetime.Before(expires) {
			expires = lifetime
		}
		if next.IsZero() || expires.Before(next) {
			next = expires
		}
	}
	return next
}

func (p *Pool) release(key Key, entry *item, reusable bool) {
	closeEntry := false
	p.mu.Lock()
	b := p.buckets[key]
	if b == nil {
		closeEntry = true
	} else if _, exists := b.leased[entry]; !exists {
		p.mu.Unlock()
		return
	} else {
		delete(b.leased, entry)
		entry.uses++
		now := p.now()
		if !reusable || p.closed || !b.registered || entry.uses >= p.config.MaxUses ||
			now.Sub(entry.createdAt) >= p.config.MaxLifetime || len(b.ready)+len(b.leased) >= b.maxSessions ||
			len(b.ready) >= b.targetReady {
			closeEntry = true
			b.releasedDiscarded++
		} else {
			entry.idleSince = now
			b.ready = append(b.ready, entry)
			b.releasedReusable++
		}
		p.signalLocked(b)
	}
	p.mu.Unlock()
	if closeEntry {
		entry.close()
	}
}

func (p *Pool) signalLocked(b *bucket) {
	close(b.changed)
	b.changed = make(chan struct{})
	if !b.registered {
		for e := b.waiters.Front(); e != nil; e = e.Next() {
			notifyWaiter(e)
		}
		return
	}
	p.notifyHeadLocked(b)
}

func (p *Pool) notifyHeadLocked(b *bucket) {
	if len(b.ready) > 0 && b.waiters.Len() > 0 {
		notifyWaiter(b.waiters.Front())
	}
}

func notifyWaiter(e *list.Element) {
	select {
	case e.Value.(*waiter).notify <- struct{}{}:
	default:
	}
}

func bucketItems(b *bucket) []*item {
	items := append([]*item(nil), b.ready...)
	for entry := range b.leased {
		items = append(items, entry)
	}
	return items
}

func closeItems(items []*item) {
	for _, entry := range items {
		entry.close()
	}
}

// Lease grants exclusive access to one warmed session.
type Lease struct {
	pool *Pool
	key  Key
	item *item
	once sync.Once
}

func (l *Lease) Resource() Resource {
	if l == nil || l.item == nil {
		return nil
	}
	return l.item.resource
}

// ReleaseReusable returns a healthy session to the pool when MaxUses permits.
// ConservativeConfig intentionally closes it after its first use.
func (l *Lease) ReleaseReusable() {
	if l == nil {
		return
	}
	l.once.Do(func() { l.pool.release(l.key, l.item, true) })
}

// Discard permanently closes a session after any ambiguous write, protocol
// error, timeout, truncated response, or capacity exhaustion.
func (l *Lease) Discard() {
	if l == nil {
		return
	}
	l.once.Do(func() { l.pool.release(l.key, l.item, false) })
}
