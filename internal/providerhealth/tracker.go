// Package providerhealth applies bounded, in-memory admission penalties to
// Providers which fail authenticated protocol checks.
package providerhealth

import (
	"errors"
	"sync"
	"time"
)

var ErrInvalidConfig = errors.New("invalid Provider health configuration")

type FailureClass uint8

const (
	FailureTransient FailureClass = iota + 1
	FailureProtocol
	FailureAuthentication
)

type Config struct {
	Threshold       uint32
	TransientWeight uint32
	ProtocolWeight  uint32
	AuthWeight      uint32
	SuccessDecay    uint32
	Quarantine      time.Duration
}

func DefaultConfig() Config {
	return Config{
		Threshold:       10,
		TransientWeight: 1,
		ProtocolWeight:  5,
		AuthWeight:      10,
		SuccessDecay:    1,
		Quarantine:      5 * time.Minute,
	}
}

func (c Config) validate() error {
	if c.Threshold == 0 || c.TransientWeight == 0 || c.ProtocolWeight == 0 ||
		c.AuthWeight == 0 || c.SuccessDecay == 0 || c.Quarantine <= 0 {
		return ErrInvalidConfig
	}
	return nil
}

type Snapshot struct {
	Score            uint32
	Failures         uint64
	Successes        uint64
	QuarantinedUntil time.Time
}

type state struct {
	score      uint32
	failures   uint64
	successes  uint64
	quarantine time.Time
}

type Tracker struct {
	mu      sync.Mutex
	config  Config
	now     func() time.Time
	states  map[string]*state
	persist func(map[string]*state) error
	close   func() error
	failed  bool
}

func New(config Config) (*Tracker, error) {
	return newTracker(config, time.Now)
}

func newTracker(config Config, now func() time.Time) (*Tracker, error) {
	if err := config.validate(); err != nil || now == nil {
		return nil, ErrInvalidConfig
	}
	return &Tracker{config: config, now: now, states: make(map[string]*state)}, nil
}

// Allow reports whether the Provider may receive a new task. Expired
// quarantine clears the accumulated score so recovery is automatic.
func (t *Tracker) Allow(providerID string) bool {
	if t == nil || providerID == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failed {
		return false
	}
	s := t.states[providerID]
	if s == nil {
		return true
	}
	if !s.quarantine.IsZero() && !t.now().Before(s.quarantine) {
		s.score = 0
		s.quarantine = time.Time{}
		if t.persist != nil && t.persist(t.states) != nil {
			t.failed = true
		}
	}
	return !t.failed && s.quarantine.IsZero()
}

func (t *Tracker) Failure(providerID string, class FailureClass) {
	if t == nil || providerID == "" {
		return
	}
	weight := t.config.TransientWeight
	switch class {
	case FailureProtocol:
		weight = t.config.ProtocolWeight
	case FailureAuthentication:
		weight = t.config.AuthWeight
	case FailureTransient:
	default:
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.get(providerID)
	s.failures++
	if s.score > ^uint32(0)-weight {
		s.score = ^uint32(0)
	} else {
		s.score += weight
	}
	if s.score >= t.config.Threshold {
		s.quarantine = t.now().Add(t.config.Quarantine)
	}
	if t.persist != nil && t.persist(t.states) != nil {
		t.failed = true
	}
}

func (t *Tracker) Success(providerID string) {
	if t == nil || providerID == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.get(providerID)
	s.successes++
	if s.score <= t.config.SuccessDecay {
		s.score = 0
	} else {
		s.score -= t.config.SuccessDecay
	}
	if t.persist != nil && t.persist(t.states) != nil {
		t.failed = true
	}
}

func (t *Tracker) Snapshot(providerID string) Snapshot {
	if t == nil || providerID == "" {
		return Snapshot{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	s := t.states[providerID]
	if s == nil {
		return Snapshot{}
	}
	return Snapshot{Score: s.score, Failures: s.failures, Successes: s.successes, QuarantinedUntil: s.quarantine}
}

func (t *Tracker) get(providerID string) *state {
	s := t.states[providerID]
	if s == nil {
		s = &state{}
		t.states[providerID] = s
	}
	return s
}

func (t *Tracker) Close() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.close == nil {
		return nil
	}
	err := t.close()
	t.close = nil
	t.persist = nil
	t.failed = true
	return err
}
