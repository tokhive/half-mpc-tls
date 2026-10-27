package coordinator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/gateway"
	"tokenhive.local/half-mpc-tls/internal/precompute"
	"tokenhive.local/half-mpc-tls/internal/providerhealth"
	"tokenhive.local/half-mpc-tls/internal/response"
	"tokenhive.local/half-mpc-tls/internal/settlement"
	"tokenhive.local/half-mpc-tls/internal/sidecar"
)

type fakeSession struct {
	stream *response.Stream
	model  string
	bad    bool
}

func (s *fakeSession) Close() error                { return s.stream.Close() }
func (s *fakeSession) Responses() *response.Stream { return s.stream }
func (s *fakeSession) EncryptAndDeliver(_ context.Context, params sidecar.SelectiveRequestParams, request []byte) (precompute.RequestResult, error) {
	digest := sha256.Sum256(request)
	hash := hex.EncodeToString(digest[:])
	if s.bad {
		hash = strings.Repeat("0", 64)
	}
	return precompute.RequestResult{
		TaskID: params.TaskID, RequestedModel: s.model, PublicRequestHash: hash,
		RequestBytes: uint64(len(request)), Streaming: false,
	}, nil
}

func testRoute() Route {
	return Route{
		ProviderID: "provider-1", CredentialID: "openai-main", CredentialLength: 32,
		Host: "api.openai.com", Port: 443, ServerName: "api.openai.com",
		Models: []string{"gpt-5"}, AllowedResponseModels: []string{"gpt-5", "gpt-5-2026-08-01"},
		MaxInputTokens: 100, MaxOutputTokens: 100,
		Price: settlement.PriceSnapshot{
			ID: "price-1", Currency: "USD", ConsumerInputMicrosPerMillion: 2_000_000,
			ConsumerOutputMicrosPerMillion: 6_000_000, ProviderInputMicrosPerMillion: 1_000_000,
			ProviderOutputMicrosPerMillion: 4_000_000,
		},
		Capacity: sidecar.BaselineMPCCapacity(),
	}
}

func setupCoordinator(t *testing.T, rawResponse string, badBinding bool) (*Coordinator, *settlement.Ledger, *providerhealth.Tracker, func()) {
	t.Helper()
	warmer := precompute.WarmerFunc(func(context.Context, precompute.Key) (precompute.Resource, error) {
		stream, err := response.NewStream(io.NopCloser(strings.NewReader(rawResponse)))
		if err != nil {
			return nil, err
		}
		return &fakeSession{stream: stream, model: "gpt-5", bad: badBinding}, nil
	})
	config := precompute.ConservativeConfig(1)
	config.WarmTimeout = time.Second
	config.HealthCheckInterval = 10 * time.Millisecond
	pool, err := precompute.NewPool(context.Background(), warmer, config)
	if err != nil {
		t.Fatal(err)
	}
	route := testRoute()
	if err := pool.Register(route.Key()); err != nil {
		t.Fatal(err)
	}
	ledger, err := settlement.NewLedger("tokenhive")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.FundConsumer("fund-1", "consumer-1", "USD", 10_000); err != nil {
		t.Fatal(err)
	}
	journal, err := settlement.OpenJournal(filepath.Join(t.TempDir(), "receipts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	processor, err := settlement.NewProcessor(journal, ledger)
	if err != nil {
		t.Fatal(err)
	}
	health, err := providerhealth.New(providerhealth.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := New(Config{Pool: pool, Ledger: ledger, Receipts: processor, Health: health, Routes: []Route{route}})
	if err != nil {
		t.Fatal(err)
	}
	return coordinator, ledger, health, func() { _ = pool.Close(); _ = journal.Close() }
}

func TestExecuteClosesAuthenticatedSettlementLoop(t *testing.T) {
	body := `{"id":"chatcmpl-1","model":"gpt-5-2026-08-01","choices":[],"usage":{"prompt_tokens":8,"completion_tokens":2,"total_tokens":10}}`
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	coordinator, ledger, health, closeAll := setupCoordinator(t, raw, false)
	defer closeAll()
	recorder := httptest.NewRecorder()
	requestBody := []byte(`{"model":"gpt-5","messages":[{"role":"user","content":"hello"}]}`)
	if err := coordinator.Execute(context.Background(), recorder, "consumer-1", "task-1", requestBody); err != nil {
		t.Fatal(err)
	}
	if recorder.Code != 200 || recorder.Body.String() != body {
		t.Fatalf("unexpected response: %d %q", recorder.Code, recorder.Body.String())
	}
	providerBalance, err := ledger.Balance(settlement.AccountProvider, "provider-1", "USD")
	if err != nil || providerBalance != 16 {
		t.Fatalf("provider balance=%d err=%v", providerBalance, err)
	}
	if snapshot := health.Snapshot("provider-1"); snapshot.Successes != 1 || snapshot.Failures != 0 {
		t.Fatalf("unexpected health: %+v", snapshot)
	}
}

func TestExecuteOverBudgetReceiptRetainsReserveWithoutProviderPenalty(t *testing.T) {
	body := `{"id":"chatcmpl-1","model":"gpt-5","choices":[],"usage":{"prompt_tokens":101,"completion_tokens":2,"total_tokens":103}}`
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	c, ledger, health, cleanup := setupCoordinator(t, raw, false)
	defer cleanup()
	recorder := httptest.NewRecorder()
	err := c.Execute(context.Background(), recorder, "consumer-1", "over-budget", []byte(`{"model":"gpt-5","messages":[]}`))
	if !errors.Is(err, gateway.ErrReceiptCommit) || recorder.Body.Len() != 0 {
		t.Fatalf("exceptional settlement exposed successful JSON: body=%q err=%v", recorder.Body.String(), err)
	}
	status, ok, err := ledger.Task("consumer-1", "over-budget")
	if err != nil || !ok || status.State != settlement.ReservationReviewRequired || status.RefundMicros != 0 || status.ChargeMicros != 0 {
		t.Fatalf("exceptional task state: %+v %v", status, err)
	}
	if _, exists, _ := ledger.Task("other-consumer", "over-budget"); exists {
		t.Fatal("review evidence leaked across consumers")
	}
	if snapshot := health.Snapshot("provider-1"); snapshot.Failures != 0 || snapshot.Successes != 0 {
		t.Fatalf("accounting exception affected Provider health: %+v", snapshot)
	}
}

func TestExecuteRejectsBindingMismatchAndRefundsReservation(t *testing.T) {
	body := `{"id":"chatcmpl-1","model":"gpt-5","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	coordinator, ledger, health, closeAll := setupCoordinator(t, raw, true)
	defer closeAll()
	err := coordinator.Execute(context.Background(), httptest.NewRecorder(), "consumer-1", "task-bad", []byte(`{"model":"gpt-5","messages":[]}`))
	if !errorsIs(err, ErrProtocolFailure) {
		t.Fatalf("expected protocol failure, got %v", err)
	}
	balance, _ := ledger.Balance(settlement.AccountConsumer, "consumer-1", "USD")
	if balance != 10_000 {
		t.Fatalf("reservation was not refunded: %d", balance)
	}
	if snapshot := health.Snapshot("provider-1"); snapshot.Failures != 1 || snapshot.Score != 5 {
		t.Fatalf("unexpected health penalty: %+v", snapshot)
	}
}

func TestExecuteNeverDispatchesSameTaskTwice(t *testing.T) {
	body := `{"id":"chatcmpl-1","model":"gpt-5","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	coordinator, _, _, closeAll := setupCoordinator(t, raw, false)
	defer closeAll()
	requestBody := []byte(`{"model":"gpt-5","messages":[]}`)
	if err := coordinator.Execute(context.Background(), httptest.NewRecorder(), "consumer-1", "task-once", requestBody); err != nil {
		t.Fatal(err)
	}
	err := coordinator.Execute(context.Background(), httptest.NewRecorder(), "consumer-1", "task-once", requestBody)
	if !errorsIs(err, ErrTaskReplay) {
		t.Fatalf("expected fail-closed task replay, got %v", err)
	}
}

func TestSelectRouteRequiresEnoughCanonicalRequestCapacity(t *testing.T) {
	body := `{"id":"chatcmpl-1","model":"gpt-5","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	coordinator, _, _, closeAll := setupCoordinator(t, raw, false)
	defer closeAll()
	requestBody := append([]byte(`{"model":"gpt-5","input":"`), []byte(strings.Repeat("x", 8<<10))...)
	requestBody = append(requestBody, []byte(`"}`)...)

	if _, _, ok := coordinator.selectRoute("task-capacity", "gpt-5", requestBody); ok {
		t.Fatal("selected a baseline route for a request above its MPC capacity")
	}
	route := coordinator.routes["gpt-5"][0]
	route.Capacity = sidecar.LargeMPCCapacity()
	coordinator.routes["gpt-5"][0] = route
	if err := coordinator.pool.(*precompute.Pool).Register(route.Key()); err != nil {
		t.Fatal(err)
	}
	if _, request, ok := coordinator.selectRoute("task-capacity", "gpt-5", requestBody); !ok || len(request.Bytes) <= 4<<10 {
		t.Fatal("large-capacity route was not selected")
	}
}

func TestExecuteRejectsAmbiguousOrUnbillableRequestBeforeReservation(t *testing.T) {
	body := `{"id":"chatcmpl-1","model":"gpt-5","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	coordinator, ledger, health, closeAll := setupCoordinator(t, raw, false)
	defer closeAll()
	requests := [][]byte{
		[]byte(`{"model":"gpt-5","model":"cheap-model","messages":[]}`),
		[]byte(`{"model":"gpt-5","stream":true,"messages":[]}`),
		[]byte(`{"model":"gpt-5","stream":false,"stream_options":{"include_usage":true},"messages":[]}`),
	}
	for index, request := range requests {
		err := coordinator.Execute(context.Background(), httptest.NewRecorder(), "consumer-1", fmt.Sprintf("task-invalid-%d", index), request)
		if !errorsIs(err, ErrInvalidRequest) {
			t.Fatalf("request %d was not rejected: %v", index, err)
		}
	}
	balance, _ := ledger.Balance(settlement.AccountConsumer, "consumer-1", "USD")
	if balance != 10_000 {
		t.Fatalf("invalid request changed balance: %d", balance)
	}
	if snapshot := health.Snapshot("provider-1"); snapshot.Failures != 0 || snapshot.Successes != 0 {
		t.Fatalf("invalid Consumer input affected Provider health: %+v", snapshot)
	}
}

func errorsIs(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		next, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = next.Unwrap()
	}
	return false
}

type inventoryPool map[precompute.Key]precompute.Stats

func (p inventoryPool) Stats(key precompute.Key) (precompute.Stats, bool) {
	s, ok := p[key]
	return s, ok
}
func (p inventoryPool) Acquire(context.Context, precompute.Key) (*precompute.Lease, error) {
	panic("selection must not dispatch")
}

func TestRouteSelectionUsesWarmInventoryLatencyAndCapacity(t *testing.T) {
	a, b := testRoute(), testRoute()
	b.ProviderID = "provider-2"
	b.Capacity = sidecar.LargeMPCCapacity()
	inventory := inventoryPool{
		a.Key(): {TargetReady: 1, Ready: 0},
		b.Key(): {TargetReady: 1, Ready: 1},
	}
	health, _ := providerhealth.New(providerhealth.DefaultConfig())
	c := &Coordinator{pool: inventory, health: health, routes: map[string][]Route{"gpt-5": {a, b}}, firstResponse: make(map[precompute.Key]time.Duration)}
	body := []byte(`{"model":"gpt-5","messages":[]}`)
	chosen, _, ok := c.selectRoute("warm-first", "gpt-5", body)
	if !ok || chosen.ProviderID != b.ProviderID {
		t.Fatal("cold route displaced ready route")
	}
	inventory[a.Key()] = precompute.Stats{TargetReady: 1, Ready: 1}
	chosen, _, _ = c.selectRoute("size-first", "gpt-5", body)
	if chosen.ProviderID != a.ProviderID {
		t.Fatal("oversized capacity displaced compatible small pool")
	}
	c.observeLatency(a.Key(), 2*time.Second)
	c.observeLatency(b.Key(), 100*time.Millisecond)
	chosen, _, _ = c.selectRoute("latency-first", "gpt-5", body)
	if chosen.ProviderID != b.ProviderID {
		t.Fatal("observed latency was ignored")
	}
	inventory[b.Key()] = precompute.Stats{TargetReady: 1, Ready: 1, Waiting: 1}
	chosen, _, _ = c.selectRoute("reserved-inventory", "gpt-5", body)
	if chosen.ProviderID != a.ProviderID {
		t.Fatal("inventory owed to an older waiter was treated as immediately available")
	}
	inventory[a.Key()] = precompute.Stats{TargetReady: 1, Ready: 1, Waiting: 1}
	if c.Ready() {
		t.Fatal("readiness advertised inventory already owed to waiters")
	}
	inventory[a.Key()] = precompute.Stats{TargetReady: 1, Ready: 1}
	if !c.Ready() {
		t.Fatal("unclaimed inventory was not ready")
	}
	inventory[b.Key()] = precompute.Stats{TargetReady: 0, Ready: 1}
	chosen, _, _ = c.selectRoute("draining", "gpt-5", body)
	if chosen.ProviderID != a.ProviderID {
		t.Fatal("selected draining Provider")
	}
}

type failingAcquirePool struct{ err error }

func (p failingAcquirePool) Acquire(context.Context, precompute.Key) (*precompute.Lease, error) {
	return nil, p.err
}

func TestQueueRejectionReleasesReservationWithoutProviderPenalty(t *testing.T) {
	for _, cause := range []error{precompute.ErrQueueFull, precompute.ErrWaitTimeout} {
		t.Run(cause.Error(), func(t *testing.T) {
			c, ledger, health, cleanup := setupCoordinator(t, "", false)
			defer cleanup()
			c.pool = failingAcquirePool{cause}
			before, balanceErr := ledger.Balance(settlement.AccountConsumer, "consumer-1", "USD")
			if balanceErr != nil {
				t.Fatal(balanceErr)
			}
			err := c.Execute(context.Background(), httptest.NewRecorder(), "consumer-1", "queue-task", []byte(`{"model":"gpt-5","messages":[]}`))
			if !errors.Is(err, cause) {
				t.Fatalf("lost queue error: %v", err)
			}
			after, balanceErr := ledger.Balance(settlement.AccountConsumer, "consumer-1", "USD")
			if balanceErr != nil {
				t.Fatal(balanceErr)
			}
			if before != after {
				t.Fatalf("queue rejection changed balance: %+v -> %+v", before, after)
			}
			if health.Snapshot("provider-1").Failures != 0 {
				t.Fatal("queue rejection penalized Provider")
			}
		})
	}
}

func TestResponseDeadlineUnblocksReadAndRefundsReservation(t *testing.T) {
	c, ledger, health, cleanup := setupCoordinator(t, "", false)
	defer cleanup()
	source, remote := net.Pipe()
	defer remote.Close()
	stream, err := response.NewStream(source)
	if err != nil {
		t.Fatal(err)
	}
	cfg := precompute.ConservativeConfig(1)
	cfg.MaxSessions = 1
	pool, err := precompute.NewPool(context.Background(), precompute.WarmerFunc(func(context.Context, precompute.Key) (precompute.Resource, error) {
		return &fakeSession{stream: stream, model: "gpt-5"}, nil
	}), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = pool.Register(testRoute().Key()); err != nil {
		t.Fatal(err)
	}
	c.pool = pool
	go func() {
		_, _ = io.WriteString(remote, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10\r\n\r\n")
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- c.Execute(ctx, httptest.NewRecorder(), "consumer-1", "stalled-response", []byte(`{"model":"gpt-5","messages":[]}`))
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request deadline did not unblock response")
	}
	state, ok, err := ledger.Task("consumer-1", "stalled-response")
	if err != nil || !ok || state.State != settlement.ReservationCancelled || state.RefundMicros != state.ReservedMicros {
		t.Fatalf("task state: %+v %v", state, err)
	}
	if health.Snapshot("provider-1").Failures != 0 {
		t.Fatal("own deadline penalized Provider")
	}
}
