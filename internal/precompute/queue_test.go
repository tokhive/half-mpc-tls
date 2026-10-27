package precompute

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Feed one session at a time so the receiver, rather than goroutine completion
// order, identifies who got the next piece of one-shot material.
func TestAcquireFIFOWithCancellationAndNewArrivals(t *testing.T) {
	feed := make(chan Resource)
	cfg := testConfig()
	cfg.MaxWaiters = 8
	pool, err := NewPool(context.Background(), WarmerFunc(func(ctx context.Context, _ Key) (Resource, error) {
		select {
		case r := <-feed:
			return r, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key := testKey()
	if err := pool.Register(key); err != nil {
		t.Fatal(err)
	}
	type result struct {
		lease *Lease
		err   error
	}
	results := make([]chan result, 9)
	contexts := make([]context.CancelFunc, 9)
	enqueue := func(i, waiting int) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		contexts[i] = cancel
		t.Cleanup(cancel)
		results[i] = make(chan result, 1)
		go func() { l, e := pool.Acquire(ctx, key); results[i] <- result{l, e} }()
		waitFor(t, func() bool { s, _ := pool.Stats(key); return s.Waiting == waiting })
	}
	for i := 0; i < 8; i++ {
		enqueue(i, i+1)
	}
	if _, err := pool.Acquire(context.Background(), key); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("full queue: %v", err)
	}
	// Cancel both the head and a middle waiter. The rest keep their positions.
	for _, i := range []int{0, 3} {
		contexts[i]()
		if got := <-results[i]; !errors.Is(got.err, context.Canceled) {
			t.Fatalf("cancel %d: %v", i, got.err)
		}
	}
	enqueue(8, 7)
	for _, i := range []int{1, 2, 4, 5, 6, 7, 8} {
		resource := newTestResource()
		select {
		case feed <- resource:
		case <-time.After(time.Second):
			t.Fatal("warmer did not refill")
		}
		select {
		case got := <-results[i]:
			if got.err != nil {
				t.Fatalf("waiter %d: %v", i, got.err)
			}
			if got.lease.Resource() != resource {
				t.Fatalf("waiter %d got the wrong session", i)
			}
			got.lease.Discard()
			if resource.closeCalls.Load() != 1 {
				t.Fatal("session not destroyed exactly once")
			}
		case <-time.After(time.Second):
			t.Fatalf("FIFO violated: waiter %d did not get next session", i)
		}
	}
	s, _ := pool.Stats(key)
	if s.Waiting != 0 || s.AcquireCancelled != 2 || s.AcquireRejected != 1 || s.Leased != 0 {
		t.Fatalf("queue stats: %+v", s)
	}
}

func TestQueueTimeoutDoesNotConsumeInventoryOrBlockNextCaller(t *testing.T) {
	gate := make(chan struct{})
	cfg := testConfig()
	cfg.AcquireTimeout = 30 * time.Millisecond
	pool, err := NewPool(context.Background(), &testWarmer{gate: gate}, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key := testKey()
	if err := pool.Register(key); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Acquire(context.Background(), key); !errors.Is(err, ErrWaitTimeout) {
		t.Fatalf("queue timeout: %v", err)
	}
	s, _ := pool.Stats(key)
	if s.Waiting != 0 || s.Leased != 0 || s.AcquireTimedOut != 1 || s.AcquireCancelled != 0 {
		t.Fatalf("timeout stats: %+v", s)
	}
	close(gate)
	waitFor(t, func() bool { s, _ := pool.Stats(key); return s.Ready > 0 })
	lease, err := pool.Acquire(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	lease.Discard()
}

func TestQueueWaitersLeaveOnShutdownOrUnregister(t *testing.T) {
	for _, mode := range []string{"close", "parent", "unregister"} {
		t.Run(mode, func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			pool, err := NewPool(parent, &testWarmer{gate: make(chan struct{})}, testConfig())
			if err != nil {
				t.Fatal(err)
			}
			defer pool.Close()
			key := testKey()
			if err := pool.Register(key); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 4)
			for range 4 {
				go func() { _, err := pool.Acquire(context.Background(), key); result <- err }()
			}
			waitFor(t, func() bool { s, _ := pool.Stats(key); return s.Waiting == 4 })
			want := ErrClosed
			switch mode {
			case "close":
				_ = pool.Close()
			case "parent":
				cancel()
			case "unregister":
				if err := pool.Unregister(key); err != nil {
					t.Fatal(err)
				}
				if err := pool.Register(key); err != nil {
					t.Fatal(err)
				}
				want = ErrKeyNotFound
			}
			for range 4 {
				select {
				case err := <-result:
					if !errors.Is(err, want) {
						t.Fatalf("got %v want %v", err, want)
					}
				case <-time.After(time.Second):
					t.Fatal("waiter stuck")
				}
			}
		})
	}
}

func TestRefillNotificationSurvivesChangeBeforeWorkerWait(t *testing.T) {
	pool, err := NewPool(context.Background(), &testWarmer{}, testConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	key := testKey()
	now := time.Now()
	b := &bucket{registered: true, targetReady: 1, maxSessions: 2, leased: make(map[*item]struct{}), changed: make(chan struct{}), ready: []*item{{resource: newTestResource(), createdAt: now, idleSince: now}}}
	// No worker: reproduce the exact check / inventory mutation / wait ordering.
	pool.buckets[key] = b
	wait, changed, stop := pool.reserveWarmSlot(b)
	if wait <= 0 || stop {
		t.Fatal("expected idle worker to wait")
	}
	lease, err := pool.Acquire(context.Background(), key)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Discard()
	select {
	case <-changed:
	default:
		t.Fatal("refill lost an inventory change before starting its wait")
	}
}
