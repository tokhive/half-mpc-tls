package precompute

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"
)

// AutoscalerConfig controls per-key warm inventory adaptation.
type AutoscalerConfig struct {
	SampleInterval  time.Duration
	MinReady        int
	MaxReady        int
	SessionHeadroom int
	// MaxLeased bounds additional capacity reserved for long-running responses.
	MaxLeased           int
	SafetyFactor        float64
	ScaleUpStep         int
	ScaleDownStep       int
	ScaleDownAfter      int
	InitialWarmDuration time.Duration
	WarmDurationAlpha   float64
}

func DefaultAutoscalerConfig() AutoscalerConfig {
	return AutoscalerConfig{
		SampleInterval:      5 * time.Second,
		MinReady:            1,
		MaxReady:            8,
		SessionHeadroom:     2,
		MaxLeased:           64,
		SafetyFactor:        2,
		ScaleUpStep:         2,
		ScaleDownStep:       1,
		ScaleDownAfter:      6,
		InitialWarmDuration: time.Second,
		WarmDurationAlpha:   0.25,
	}
}

func (c AutoscalerConfig) validate() error {
	if c.SampleInterval <= 0 || c.MinReady < 0 || c.MaxReady < c.MinReady ||
		c.SessionHeadroom <= 0 || c.MaxLeased < 0 || c.SafetyFactor < 1 || math.IsNaN(c.SafetyFactor) || math.IsInf(c.SafetyFactor, 0) ||
		c.ScaleUpStep <= 0 || c.ScaleDownStep <= 0 || c.ScaleDownAfter <= 0 ||
		c.InitialWarmDuration <= 0 || c.WarmDurationAlpha <= 0 || c.WarmDurationAlpha > 1 ||
		math.IsNaN(c.WarmDurationAlpha) {
		return ErrInvalidConfig
	}
	return nil
}

// AutoscalerStats describes the last completed sample for one managed key.
type AutoscalerStats struct {
	Online                  bool
	TargetReady             int
	MaxSessions             int
	RequestsPerSecond       float64
	MissRatio               float64
	EstimatedWarmDuration   time.Duration
	RequiredWarmConcurrency int
	WarmConcurrency         int
	Saturated               bool
	LastSample              time.Time
}

type autoscalerState struct {
	online          bool
	target          int
	leasedAllowance int

	lastSample        time.Time
	lastHits          uint64
	lastMisses        uint64
	lastWarmSuccesses uint64
	lastWarmDuration  time.Duration
	warmEstimate      time.Duration
	lowSamples        int
	snapshot          AutoscalerStats
}

// Autoscaler adjusts Pool targets from observed acquisition rate, misses and
// actual warm duration. It never logs or exports Key values.
type Autoscaler struct {
	pool   *Pool
	config AutoscalerConfig

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu     sync.Mutex
	states map[Key]*autoscalerState
	closed bool
}

func NewAutoscaler(parent context.Context, pool *Pool, config AutoscalerConfig) (*Autoscaler, error) {
	if parent == nil || pool == nil {
		return nil, ErrInvalidConfig
	}
	if err := config.validate(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(parent)
	autoscaler := &Autoscaler{
		pool:   pool,
		config: config,
		ctx:    ctx,
		cancel: cancel,
		states: make(map[Key]*autoscalerState),
	}
	autoscaler.wg.Add(1)
	go autoscaler.run()
	return autoscaler, nil
}

// Manage registers a pool key and starts it online or drained. Repeated calls
// update the online state without resetting an active key unnecessarily.
func (a *Autoscaler) Manage(key Key, online bool) error {
	if err := key.Validate(); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.ctx.Err() != nil {
		return ErrClosed
	}
	if state := a.states[key]; state != nil {
		return a.setOnlineLocked(key, state, online)
	}
	target := 0
	if online {
		target = a.config.MinReady
	}
	if err := a.pool.RegisterWithLimits(key, target, target+a.headroom(target)); err != nil {
		return err
	}
	stats, _ := a.pool.Stats(key)
	now := time.Now()
	state := &autoscalerState{
		online:            online,
		target:            target,
		lastSample:        now,
		lastHits:          stats.AcquireHits,
		lastMisses:        stats.AcquireMisses,
		lastWarmSuccesses: stats.WarmSuccesses,
		lastWarmDuration:  stats.WarmSuccessDuration,
		warmEstimate:      a.config.InitialWarmDuration,
	}
	state.snapshot = a.snapshot(state, now, 0, 0)
	a.states[key] = state
	return nil
}

// SetOnline immediately drains an offline Provider or restores the minimum
// warm inventory when it comes back online.
func (a *Autoscaler) SetOnline(key Key, online bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.ctx.Err() != nil {
		return ErrClosed
	}
	state := a.states[key]
	if state == nil {
		return ErrKeyNotFound
	}
	return a.setOnlineLocked(key, state, online)
}

func (a *Autoscaler) setOnlineLocked(key Key, state *autoscalerState, online bool) error {
	if state.online == online {
		return nil
	}
	target := 0
	if online {
		target = a.config.MinReady
	}
	if err := a.pool.SetTarget(key, target, target+a.headroom(target)); err != nil {
		return err
	}
	stats, ok := a.pool.Stats(key)
	if !ok {
		return ErrKeyNotFound
	}
	now := time.Now()
	state.online = online
	state.leasedAllowance = 0
	state.target = target
	state.lowSamples = 0
	state.lastSample = now
	state.lastHits = stats.AcquireHits
	state.lastMisses = stats.AcquireMisses
	state.lastWarmSuccesses = stats.WarmSuccesses
	state.lastWarmDuration = stats.WarmSuccessDuration
	state.snapshot = a.snapshot(state, now, 0, 0)
	return nil
}

// Unmanage stops adapting key but leaves its current Pool target unchanged.
func (a *Autoscaler) Unmanage(key Key) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.ctx.Err() != nil {
		return ErrClosed
	}
	if _, ok := a.states[key]; !ok {
		return ErrKeyNotFound
	}
	delete(a.states, key)
	return nil
}

// Remove stops adaptation and destroys the Pool key. Active leases are closed,
// so callers should use SetOnline(false) first when graceful draining is needed.
func (a *Autoscaler) Remove(key Key) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.ctx.Err() != nil {
		return ErrClosed
	}
	if _, ok := a.states[key]; !ok {
		return ErrKeyNotFound
	}
	if err := a.pool.Unregister(key); err != nil {
		return err
	}
	delete(a.states, key)
	return nil
}

func (a *Autoscaler) Stats(key Key) (AutoscalerStats, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	state := a.states[key]
	if state == nil {
		return AutoscalerStats{}, false
	}
	return state.snapshot, true
}

// Reconcile samples all managed keys immediately. The background loop invokes
// the same operation at SampleInterval; exposing it also makes control-plane
// event handling and deterministic tests possible.
func (a *Autoscaler) Reconcile() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed || a.ctx.Err() != nil {
		return ErrClosed
	}
	now := time.Now()
	var reconcileErr error
	for key, state := range a.states {
		if err := a.reconcileKeyLocked(key, state, now); err != nil {
			reconcileErr = errors.Join(reconcileErr, err)
		}
	}
	return reconcileErr
}

func (a *Autoscaler) reconcileKeyLocked(key Key, state *autoscalerState, now time.Time) error {
	stats, ok := a.pool.Stats(key)
	if !ok {
		return ErrKeyNotFound
	}
	if !state.online {
		state.snapshot = a.snapshot(state, now, 0, 0)
		state.lastSample = now
		return nil
	}
	elapsed := now.Sub(state.lastSample)
	if elapsed <= 0 {
		return nil
	}
	hits := counterDelta(stats.AcquireHits, state.lastHits)
	misses := counterDelta(stats.AcquireMisses, state.lastMisses)
	requests := hits + misses
	qps := float64(requests) / elapsed.Seconds()
	missRatio := 0.0
	if requests != 0 {
		missRatio = float64(misses) / float64(requests)
	}

	warmSuccesses := counterDelta(stats.WarmSuccesses, state.lastWarmSuccesses)
	warmDuration := durationDelta(stats.WarmSuccessDuration, state.lastWarmDuration)
	if warmSuccesses != 0 {
		sample := time.Duration(int64(warmDuration) / int64(warmSuccesses))
		state.warmEstimate = ewmaDuration(state.warmEstimate, sample, a.config.WarmDurationAlpha)
	}

	desired := clampTarget(
		int(math.Ceil(qps*state.warmEstimate.Seconds()*a.config.SafetyFactor)),
		a.config.MinReady,
		a.config.MaxReady,
	)
	if misses != 0 {
		desired = max(desired, min(state.target+a.config.ScaleUpStep, a.config.MaxReady))
	}
	newTarget := state.target
	if desired > state.target {
		newTarget = desired
		state.lowSamples = 0
	} else if desired < state.target && misses == 0 {
		state.lowSamples++
		if state.lowSamples >= a.config.ScaleDownAfter {
			newTarget = max(desired, state.target-a.config.ScaleDownStep)
			state.lowSamples = 0
		}
	} else {
		state.lowSamples = 0
	}
	leasedAllowance := min(stats.Leased, a.config.MaxLeased)
	if newTarget != state.target || leasedAllowance != state.leasedAllowance {
		if err := a.pool.SetTarget(key, newTarget, newTarget+a.headroom(newTarget)+leasedAllowance); err != nil {
			return err
		}
		state.target = newTarget
		state.leasedAllowance = leasedAllowance
	}

	state.lastSample = now
	state.lastHits = stats.AcquireHits
	state.lastMisses = stats.AcquireMisses
	state.lastWarmSuccesses = stats.WarmSuccesses
	state.lastWarmDuration = stats.WarmSuccessDuration
	state.snapshot = a.snapshot(state, now, qps, missRatio)
	return nil
}

func (a *Autoscaler) snapshot(state *autoscalerState, now time.Time, qps, missRatio float64) AutoscalerStats {
	requiredConcurrency := int(math.Ceil(qps * state.warmEstimate.Seconds()))
	return AutoscalerStats{
		Online:                  state.online,
		TargetReady:             state.target,
		MaxSessions:             state.target + a.headroom(state.target) + state.leasedAllowance,
		RequestsPerSecond:       qps,
		MissRatio:               missRatio,
		EstimatedWarmDuration:   state.warmEstimate,
		RequiredWarmConcurrency: requiredConcurrency,
		WarmConcurrency:         a.pool.config.WarmConcurrency,
		Saturated:               requiredConcurrency > a.pool.config.WarmConcurrency,
		LastSample:              now,
	}
}

func (a *Autoscaler) headroom(target int) int {
	if target == 0 {
		return 0
	}
	return a.config.SessionHeadroom
}

func (a *Autoscaler) run() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.config.SampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			_ = a.Reconcile()
		}
	}
}

func (a *Autoscaler) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	a.cancel()
	a.mu.Unlock()
	a.wg.Wait()
	return nil
}

func counterDelta(current, previous uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	return current
}

func durationDelta(current, previous time.Duration) time.Duration {
	if current >= previous {
		return current - previous
	}
	return current
}

func ewmaDuration(previous, sample time.Duration, alpha float64) time.Duration {
	if sample <= 0 {
		return previous
	}
	if previous <= 0 {
		return sample
	}
	return time.Duration((1-alpha)*float64(previous) + alpha*float64(sample))
}

func clampTarget(value, minimum, maximum int) int {
	return min(max(value, minimum), maximum)
}
