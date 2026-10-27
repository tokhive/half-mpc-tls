// Package coordinator binds request admission, Provider selection, precomputed
// MPC sessions, authenticated response relay, and settlement into one task.
package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"tokenhive.local/half-mpc-tls/internal/canonical"
	"tokenhive.local/half-mpc-tls/internal/gateway"
	"tokenhive.local/half-mpc-tls/internal/precompute"
	"tokenhive.local/half-mpc-tls/internal/providerhealth"
	"tokenhive.local/half-mpc-tls/internal/response"
	"tokenhive.local/half-mpc-tls/internal/settlement"
	"tokenhive.local/half-mpc-tls/internal/sidecar"
)

var (
	ErrInvalidConfig      = errors.New("invalid coordinator configuration")
	ErrInvalidRequest     = errors.New("invalid Consumer request")
	ErrNoProvider         = errors.New("no healthy Provider supports the requested model")
	ErrSessionUnavailable = errors.New("no precomputed Provider session available")
	ErrProtocolFailure    = errors.New("Provider protocol evidence was rejected")
	ErrTaskReplay         = errors.New("task was already admitted and cannot be dispatched twice")
)

type Pool interface {
	Acquire(context.Context, precompute.Key) (*precompute.Lease, error)
}

type AccountLedger interface {
	Reserve(settlement.ReserveRequest) (settlement.Reservation, bool, error)
	Cancel(taskID, reasonCode string) (settlement.Cancellation, bool, error)
}

type ProviderHealth interface {
	Allow(providerID string) bool
	Failure(providerID string, class providerhealth.FailureClass)
	Success(providerID string)
}

type Session interface {
	precompute.Resource
	EncryptAndDeliver(context.Context, sidecar.SelectiveRequestParams, []byte) (precompute.RequestResult, error)
	Responses() *response.Stream
}

type Route struct {
	TLSVersion            string                   `json:"tls_version,omitempty"`
	ProviderID            string                   `json:"provider_id"`
	CredentialID          string                   `json:"credential_id"`
	CredentialLength      int                      `json:"credential_length"`
	Host                  string                   `json:"host"`
	Port                  uint16                   `json:"port"`
	ServerName            string                   `json:"server_name"`
	Models                []string                 `json:"models"`
	AllowedResponseModels []string                 `json:"allowed_response_models"`
	MaxInputTokens        int64                    `json:"max_input_tokens"`
	MaxOutputTokens       int64                    `json:"max_output_tokens"`
	Price                 settlement.PriceSnapshot `json:"price"`
	Capacity              sidecar.MPCCapacity      `json:"capacity"`
}

func (r Route) Key() precompute.Key {
	return precompute.Key{
		ProviderID: r.ProviderID, CredentialID: r.CredentialID, Host: r.Host,
		Port: r.Port, ServerName: r.ServerName, Capacity: r.Capacity, TLSVersion: r.TLSVersion,
	}
}

type Config struct {
	Pool     Pool
	Ledger   AccountLedger
	Receipts gateway.ReceiptSink
	Health   ProviderHealth
	Routes   []Route
}

type Coordinator struct {
	pool     Pool
	ledger   AccountLedger
	receipts gateway.ReceiptSink
	health   ProviderHealth

	routes        map[string][]Route
	latencyMu     sync.Mutex
	firstResponse map[precompute.Key]time.Duration
}

func New(config Config) (*Coordinator, error) {
	if config.Pool == nil || config.Ledger == nil || config.Receipts == nil || config.Health == nil || len(config.Routes) == 0 {
		return nil, ErrInvalidConfig
	}
	c := &Coordinator{
		pool: config.Pool, ledger: config.Ledger, receipts: config.Receipts, health: config.Health,
		routes:        make(map[string][]Route),
		firstResponse: make(map[precompute.Key]time.Duration),
	}
	for _, route := range config.Routes {
		if err := validateRoute(route); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidConfig, err)
		}
		for _, model := range route.Models {
			c.routes[model] = append(c.routes[model], cloneRoute(route))
		}
	}
	return c, nil
}

// Execute runs one admitted Consumer task. The task ID is the idempotency key
// for both reservation and receipt settlement.
func (c *Coordinator) Execute(ctx context.Context, writer http.ResponseWriter, consumerID, taskID string, body json.RawMessage) error {
	if ctx == nil || writer == nil || !validID(consumerID) || !validID(taskID) {
		return ErrInvalidRequest
	}
	policy, err := canonical.ParseOpenAIChatCompletionsPolicy(body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	route, request, ok := c.selectRoute(taskID, policy.Model, body)
	if !ok {
		return ErrNoProvider
	}
	requestHash := hex.EncodeToString(request.Hash[:])
	_, created, err := c.ledger.Reserve(settlement.ReserveRequest{
		TaskID: taskID, ConsumerID: consumerID, ProviderID: route.ProviderID,
		RequestHash: requestHash, RequestedModel: request.Model,
		AllowedResponseModels: append([]string(nil), route.AllowedResponseModels...),
		MaxInputTokens:        route.MaxInputTokens, MaxOutputTokens: route.MaxOutputTokens,
		Price: route.Price,
	})
	if err != nil {
		return err
	}
	if !created {
		return ErrTaskReplay
	}
	reservationOpen := true
	defer func() {
		if reservationOpen {
			_, _, _ = c.ledger.Cancel(taskID, "task_failed")
		}
	}()

	lease, err := c.pool.Acquire(ctx, route.Key())
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSessionUnavailable, err)
	}
	defer lease.Discard()
	// A disconnected Consumer may still be drained and settled, but never past
	// the original request deadline. Response reads need transport closure to
	// observe that deadline; their parser is not context-aware.
	if deadline, ok := ctx.Deadline(); ok {
		timer := time.AfterFunc(time.Until(deadline), lease.Discard)
		defer timer.Stop()
	}
	session, ok := lease.Resource().(Session)
	if !ok || session.Responses() == nil {
		c.health.Failure(route.ProviderID, providerhealth.FailureProtocol)
		return ErrProtocolFailure
	}
	dispatchStarted := time.Now()
	result, err := session.EncryptAndDeliver(ctx, sidecar.SelectiveRequestParams{
		TaskID: taskID, Adapter: request.Adapter, CredentialLength: route.CredentialLength,
		PublicRequestHash: requestHash,
	}, request.Bytes)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ctx.Err()
		}
		c.health.Failure(route.ProviderID, providerhealth.FailureProtocol)
		return fmt.Errorf("%w: request delivery failed", ErrProtocolFailure)
	}
	if result.TaskID != taskID || result.RequestedModel != request.Model || result.Streaming != request.Stream ||
		result.PublicRequestHash != requestHash || result.RequestBytes == 0 {
		c.health.Failure(route.ProviderID, providerhealth.FailureProtocol)
		return fmt.Errorf("%w: request binding mismatch", ErrProtocolFailure)
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+route.Host+"/v1/chat/completions", nil)
	if err != nil {
		return err
	}
	upstream, err := session.Responses().Next(httpRequest)
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ctx.Err()
		}
		c.health.Failure(route.ProviderID, providerhealth.FailureProtocol)
		return fmt.Errorf("%w: invalid authenticated response", ErrProtocolFailure)
	}
	c.observeLatency(route.Key(), time.Since(dispatchStarted))
	receipt, relayErr := gateway.RelayOpenAI(writer, upstream, gateway.RelayConfig{
		TaskID: taskID, ProviderID: route.ProviderID, RequestHash: requestHash,
		RequestedModel: request.Model, Streaming: request.Stream,
		AllowedResponseModels: append([]string(nil), route.AllowedResponseModels...),
	}, c.receipts)
	if receipt.TaskID != "" {
		// A returned receipt may already be in the durable outbox even when ledger
		// application failed. Cancellation would conflict with crash replay.
		reservationOpen = false
	}
	if relayErr != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return ctx.Err()
		}
		if errors.Is(relayErr, gateway.ErrResponseRejected) {
			c.health.Failure(route.ProviderID, providerhealth.FailureProtocol)
		} else if !errors.Is(relayErr, gateway.ErrDownstreamWrite) && !errors.Is(relayErr, gateway.ErrReceiptCommit) {
			c.health.Failure(route.ProviderID, providerhealth.FailureTransient)
		}
		return relayErr
	}
	reservationOpen = false
	c.health.Success(route.ProviderID)
	return nil
}

func (c *Coordinator) selectRoute(taskID, model string, body json.RawMessage) (Route, canonical.Request, bool) {
	routes := c.routes[model]
	if len(routes) == 0 {
		return Route{}, canonical.Request{}, false
	}
	digest := sha256.Sum256([]byte(taskID + "\x00" + model))
	start := uint64(digest[0])<<56 | uint64(digest[1])<<48 | uint64(digest[2])<<40 | uint64(digest[3])<<32 |
		uint64(digest[4])<<24 | uint64(digest[5])<<16 | uint64(digest[6])<<8 | uint64(digest[7])
	start %= uint64(len(routes))
	var best Route
	var bestRequest canonical.Request
	var bestScore routeScore
	found := false
	// Many routes differ only in Provider or capacity. Canonicalizing a large
	// body again for each candidate would make routing scale with body*routes.
	type templateKey struct {
		host             string
		credentialLength int
	}
	templates := make(map[templateKey]canonical.Request)
	for offset := range routes {
		index := (int(start) + offset) % len(routes)
		route := routes[index]
		if !c.health.Allow(route.ProviderID) {
			continue
		}
		score, available := c.scoreRoute(route)
		if !available || (found && !score.less(bestScore)) {
			continue
		}
		template := templateKey{route.Host, route.CredentialLength}
		request, cached := templates[template]
		if !cached {
			var err error
			request, err = canonical.BuildOpenAIChatCompletions(route.Host, route.CredentialLength, body)
			if err != nil {
				continue
			}
			templates[template] = request
		}
		if len(request.Bytes) > int(route.Capacity.MaxRequestBytes) {
			continue
		}
		if !found || score.less(bestScore) {
			best, bestRequest, bestScore, found = route, request, score, true
		}
	}
	return cloneRoute(best), bestRequest, found
}

// Readiness dominates the score: avoid a cold handshake when a compatible
// warm session exists. Equal scores retain the task-hash rotation above.
type routeScore struct {
	cold     bool
	delay    time.Duration
	capacity uint32
	load     int
}

func (a routeScore) less(b routeScore) bool {
	if a.cold != b.cold {
		return !a.cold
	}
	if a.delay != b.delay {
		return a.delay < b.delay
	}
	if a.capacity != b.capacity {
		return a.capacity < b.capacity
	}
	return a.load < b.load
}

func (c *Coordinator) scoreRoute(route Route) (routeScore, bool) {
	key := route.Key()
	c.latencyMu.Lock()
	delay := c.firstResponse[key]
	c.latencyMu.Unlock()
	if delay == 0 {
		delay = time.Second
	}
	score := routeScore{delay: delay, capacity: route.Capacity.MaxRequestBytes}
	if pool, ok := c.pool.(interface {
		Stats(precompute.Key) (precompute.Stats, bool)
	}); ok {
		stats, exists := pool.Stats(key)
		if !exists || stats.TargetReady == 0 {
			return score, false
		}
		score.cold = stats.Ready <= stats.Waiting
		score.load = stats.Leased + stats.Waiting
		if score.cold {
			warm := time.Second
			if stats.WarmSuccesses != 0 {
				warm = stats.WarmSuccessDuration / time.Duration(stats.WarmSuccesses)
			}
			score.delay += warm
			if wait := time.Until(stats.NextAttempt); wait > 0 {
				score.delay += wait
			}
		}
	}
	return score, true
}

func (c *Coordinator) observeLatency(key precompute.Key, sample time.Duration) {
	c.latencyMu.Lock()
	defer c.latencyMu.Unlock()
	if previous := c.firstResponse[key]; previous > 0 {
		sample = previous*3/4 + sample/4
	}
	c.firstResponse[key] = sample
}

func validateRoute(route Route) error {
	if !validID(route.ProviderID) || route.CredentialID == "" || route.CredentialLength <= 0 ||
		route.CredentialLength > 512 || route.Host == "" || route.ServerName == "" || route.Port == 0 ||
		len(route.Models) == 0 || len(route.AllowedResponseModels) == 0 ||
		route.MaxInputTokens < 0 || route.MaxOutputTokens < 0 || route.MaxInputTokens+route.MaxOutputTokens <= 0 ||
		route.Key().Validate() != nil || !sidecar.IsSupportedMPCCapacity(route.Capacity) {
		return errors.New("route fields are invalid")
	}
	for _, model := range append(append([]string(nil), route.Models...), route.AllowedResponseModels...) {
		if model == "" || len(model) > 256 {
			return errors.New("route model is invalid")
		}
	}
	return nil
}

func cloneRoute(route Route) Route {
	route.Models = append([]string(nil), route.Models...)
	route.AllowedResponseModels = append([]string(nil), route.AllowedResponseModels...)
	return route
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

// Models returns the configured model IDs without exposing Provider metadata.
func (c *Coordinator) Models() []string {
	models := make([]string, 0, len(c.routes))
	for model := range c.routes {
		models = append(models, model)
	}
	return models
}

// Ready reports whether any healthy route has a precomputed session available.
// This is a snapshot, not a reservation or a guarantee for every model.
func (c *Coordinator) Ready() bool {
	pool, ok := c.pool.(interface {
		Stats(precompute.Key) (precompute.Stats, bool)
	})
	if !ok {
		return false
	}
	for _, routes := range c.routes {
		for _, route := range routes {
			if !c.health.Allow(route.ProviderID) {
				continue
			}
			if stats, exists := pool.Stats(route.Key()); exists && stats.TargetReady > 0 && stats.Ready > stats.Waiting {
				return true
			}
		}
	}
	return false
}
