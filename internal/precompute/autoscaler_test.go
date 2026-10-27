package precompute

import (
	"context"
	"errors"
	"testing"
	"time"
)

func testAutoscalerConfig() AutoscalerConfig {
	return AutoscalerConfig{
		SampleInterval:      time.Hour,
		MinReady:            1,
		MaxReady:            6,
		SessionHeadroom:     2,
		SafetyFactor:        2,
		ScaleUpStep:         2,
		ScaleDownStep:       1,
		ScaleDownAfter:      2,
		InitialWarmDuration: time.Second,
		WarmDurationAlpha:   1,
	}
}

func TestAutoscalerProviderOnlineLifecycle(t *testing.T) {
	warmer := &testWarmer{}
	pool, err := NewPool(context.Background(), warmer, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	autoscaler, err := NewAutoscaler(context.Background(), pool, testAutoscalerConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer autoscaler.Close()
	key := testKey()
	if err := autoscaler.Manage(key, true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		stats, _ := pool.Stats(key)
		return stats.TargetReady == 1 && stats.MaxSessions == 3 && stats.Ready == 1
	})
	lease, err := pool.Acquire(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	resource := lease.Resource().(*testResource)
	if err := autoscaler.SetOnline(key, false); err != nil {
		t.Fatal(err)
	}
	stats, _ := pool.Stats(key)
	if stats.TargetReady != 0 || stats.MaxSessions != 0 || stats.Leased != 1 || resource.closeCalls.Load() != 0 {
		t.Fatalf("offline transition interrupted active lease: %+v", stats)
	}
	lease.ReleaseReusable()
	if resource.closeCalls.Load() != 1 {
		t.Fatal("offline Provider lease was not destroyed on release")
	}
	if err := autoscaler.SetOnline(key, true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		stats, _ := pool.Stats(key)
		return stats.TargetReady == 1 && stats.MaxSessions == 3 && stats.Ready == 1
	})
	autoStats, ok := autoscaler.Stats(key)
	if !ok || !autoStats.Online || autoStats.TargetReady != 1 {
		t.Fatalf("unexpected autoscaler stats: %+v", autoStats)
	}
}

func TestAutoscalerScalesFromObservedDemandAndReportsSaturation(t *testing.T) {
	warmer := &testWarmer{}
	poolConfig := testConfig()
	poolConfig.WarmConcurrency = 1
	pool, err := NewPool(context.Background(), warmer, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	config := testAutoscalerConfig()
	config.MaxReady = 6
	autoscaler, err := NewAutoscaler(context.Background(), pool, config)
	if err != nil {
		t.Fatal(err)
	}
	defer autoscaler.Close()
	key := testKey()
	if err := autoscaler.Manage(key, true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		stats, _ := pool.Stats(key)
		return stats.Ready == 1
	})

	baseline, _ := pool.Stats(key)
	autoscaler.mu.Lock()
	state := autoscaler.states[key]
	state.lastHits = baseline.AcquireHits
	state.lastMisses = baseline.AcquireMisses
	state.lastWarmSuccesses = baseline.WarmSuccesses
	state.lastWarmDuration = baseline.WarmSuccessDuration
	state.lastSample = time.Now().Add(-time.Second)
	autoscaler.mu.Unlock()
	pool.mu.Lock()
	b := pool.buckets[key]
	b.acquireHits += 10
	b.warmSuccesses++
	b.warmSuccessDuration += 2 * time.Second
	pool.mu.Unlock()

	if err := autoscaler.Reconcile(); err != nil {
		t.Fatal(err)
	}
	autoStats, _ := autoscaler.Stats(key)
	if autoStats.TargetReady != config.MaxReady || autoStats.RequestsPerSecond < 9 ||
		autoStats.EstimatedWarmDuration < 1900*time.Millisecond ||
		autoStats.RequiredWarmConcurrency < 18 || !autoStats.Saturated {
		t.Fatalf("unexpected demand estimate: %+v", autoStats)
	}
	poolStats, _ := pool.Stats(key)
	if poolStats.TargetReady != config.MaxReady || poolStats.MaxSessions != config.MaxReady+config.SessionHeadroom {
		t.Fatalf("pool did not receive autoscaled target: %+v", poolStats)
	}
}

func TestAutoscalerMissScalesImmediatelyAndQuietSamplesScaleGradually(t *testing.T) {
	warmer := &testWarmer{}
	pool, err := NewPool(context.Background(), warmer, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	config := testAutoscalerConfig()
	config.MaxReady = 5
	autoscaler, err := NewAutoscaler(context.Background(), pool, config)
	if err != nil {
		t.Fatal(err)
	}
	defer autoscaler.Close()
	key := testKey()
	if err := autoscaler.Manage(key, true); err != nil {
		t.Fatal(err)
	}

	pool.mu.Lock()
	pool.buckets[key].acquireMisses++
	pool.mu.Unlock()
	autoscaler.mu.Lock()
	autoscaler.states[key].lastSample = time.Now().Add(-time.Second)
	autoscaler.mu.Unlock()
	if err := autoscaler.Reconcile(); err != nil {
		t.Fatal(err)
	}
	stats, _ := autoscaler.Stats(key)
	if stats.TargetReady < 3 {
		t.Fatalf("miss did not trigger immediate scale-up: %+v", stats)
	}
	scaledTarget := stats.TargetReady

	autoscaler.mu.Lock()
	autoscaler.states[key].lastSample = time.Now().Add(-time.Second)
	autoscaler.mu.Unlock()
	if err := autoscaler.Reconcile(); err != nil {
		t.Fatal(err)
	}
	stats, _ = autoscaler.Stats(key)
	if stats.TargetReady != scaledTarget {
		t.Fatal("autoscaler scaled down before the quiet-sample threshold")
	}
	autoscaler.mu.Lock()
	autoscaler.states[key].lastSample = time.Now().Add(-time.Second)
	autoscaler.mu.Unlock()
	if err := autoscaler.Reconcile(); err != nil {
		t.Fatal(err)
	}
	stats, _ = autoscaler.Stats(key)
	if stats.TargetReady != scaledTarget-1 {
		t.Fatalf("autoscaler did not scale down gradually: %+v", stats)
	}
}

func TestAutoscalerRejectsInvalidConfigurationAndUnknownKeys(t *testing.T) {
	pool, err := NewPool(context.Background(), &testWarmer{}, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := NewAutoscaler(context.Background(), pool, AutoscalerConfig{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewAutoscaler error = %v", err)
	}
	autoscaler, err := NewAutoscaler(context.Background(), pool, testAutoscalerConfig())
	if err != nil {
		t.Fatal(err)
	}
	key := testKey()
	if err := autoscaler.SetOnline(key, true); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("SetOnline unknown key error = %v", err)
	}
	if err := autoscaler.Close(); err != nil {
		t.Fatal(err)
	}
	if err := autoscaler.Manage(key, true); !errors.Is(err, ErrClosed) {
		t.Fatalf("Manage after Close error = %v", err)
	}
}

func TestAutoscalerReservesBoundedSpaceForStreamingLeases(t *testing.T) {
	pool, err := NewPool(context.Background(), &testWarmer{}, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	config := testAutoscalerConfig()
	config.MaxLeased = 3
	autoscaler, err := NewAutoscaler(context.Background(), pool, config)
	if err != nil {
		t.Fatal(err)
	}
	defer autoscaler.Close()
	key := testKey()
	if err := autoscaler.Manage(key, true); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { stats, _ := pool.Stats(key); return stats.Ready == 1 })
	lease, err := pool.Acquire(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Discard()
	if err := autoscaler.Reconcile(); err != nil {
		t.Fatal(err)
	}
	stats, _ := pool.Stats(key)
	if stats.MaxSessions != stats.TargetReady+config.SessionHeadroom+1 {
		t.Fatalf("lease starved warm inventory: %+v", stats)
	}
	if err := autoscaler.SetOnline(key, false); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := autoscaler.Stats(key)
	if snapshot.MaxSessions != 0 {
		t.Fatalf("drained pool kept lease allowance: %+v", snapshot)
	}
}
