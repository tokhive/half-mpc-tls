package api

import (
	"errors"
	"math"
	"sync"
	"time"
)

var ErrInvalidRateLimit = errors.New("invalid rate limit configuration")

type RateLimitConfig struct {
	RequestsPerSecond float64
	Burst             int
	MaxConcurrent     int
	IdleTTL           time.Duration
}

func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{RequestsPerSecond: 2, Burst: 10, MaxConcurrent: 4, IdleTTL: 10 * time.Minute}
}

type limitState struct {
	tokens     float64
	last       time.Time
	lastSeen   time.Time
	concurrent int
}

type Limiter struct {
	mu     sync.Mutex
	config RateLimitConfig
	now    func() time.Time
	states map[string]*limitState
}

func NewLimiter(config RateLimitConfig) (*Limiter, error) {
	return newLimiter(config, time.Now)
}

func newLimiter(config RateLimitConfig, now func() time.Time) (*Limiter, error) {
	if config.RequestsPerSecond <= 0 || math.IsNaN(config.RequestsPerSecond) || math.IsInf(config.RequestsPerSecond, 0) ||
		config.Burst <= 0 || config.MaxConcurrent <= 0 || config.IdleTTL <= 0 || now == nil {
		return nil, ErrInvalidRateLimit
	}
	return &Limiter{config: config, now: now, states: make(map[string]*limitState)}, nil
}

// Acquire consumes one rate token and one concurrency slot. The returned
// release function is idempotent.
func (l *Limiter) Acquire(consumerID string) (func(), bool) {
	if l == nil || consumerID == "" {
		return nil, false
	}
	l.mu.Lock()
	now := l.now()
	l.prune(now)
	s := l.states[consumerID]
	if s == nil {
		s = &limitState{tokens: float64(l.config.Burst), last: now, lastSeen: now}
		l.states[consumerID] = s
	}
	elapsed := now.Sub(s.last).Seconds()
	if elapsed > 0 {
		s.tokens = math.Min(float64(l.config.Burst), s.tokens+elapsed*l.config.RequestsPerSecond)
		s.last = now
	}
	s.lastSeen = now
	if s.tokens < 1 || s.concurrent >= l.config.MaxConcurrent {
		l.mu.Unlock()
		return nil, false
	}
	s.tokens--
	s.concurrent++
	l.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			if current := l.states[consumerID]; current != nil && current.concurrent > 0 {
				current.concurrent--
				current.lastSeen = l.now()
			}
			l.mu.Unlock()
		})
	}, true
}

func (l *Limiter) prune(now time.Time) {
	for consumerID, state := range l.states {
		if state.concurrent == 0 && now.Sub(state.lastSeen) >= l.config.IdleTTL {
			delete(l.states, consumerID)
		}
	}
}
