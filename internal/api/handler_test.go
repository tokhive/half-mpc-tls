package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"tokenhive.local/half-mpc-tls/internal/canonical"
	"tokenhive.local/half-mpc-tls/internal/coordinator"
	"tokenhive.local/half-mpc-tls/internal/precompute"
	"tokenhive.local/half-mpc-tls/internal/settlement"
)

const testConsumerToken = "th_test_0123456789abcdef01234567"

type captureExecutor struct {
	mu         sync.Mutex
	consumerID string
	taskID     string
	body       []byte
	err        error
}

func (e *captureExecutor) Execute(_ context.Context, writer http.ResponseWriter, consumerID, taskID string, body json.RawMessage) error {
	e.mu.Lock()
	e.consumerID = consumerID
	e.taskID = taskID
	e.body = append([]byte(nil), body...)
	err := e.err
	e.mu.Unlock()
	if err == nil {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"ok":true}`))
	}
	return err
}

func testHandler(t *testing.T, rate RateLimitConfig) (*Handler, *captureExecutor) {
	t.Helper()
	keys, err := NewAPIKeys(map[string]string{testConsumerToken: "consumer-1"})
	if err != nil {
		t.Fatal(err)
	}
	limiter, err := NewLimiter(rate)
	if err != nil {
		t.Fatal(err)
	}
	executor := &captureExecutor{}
	handler, err := NewHandler(Config{Keys: keys, Limiter: limiter, Executor: executor, RequestTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return handler, executor
}

func request(body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, ChatCompletionsPath, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testConsumerToken)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func TestHandlerAuthenticatesAndPassesOnlyBodyIdentityAndTask(t *testing.T) {
	handler, executor := testHandler(t, DefaultRateLimitConfig())
	req := request(`{"model":"gpt-5","messages":[]}`)
	req.Header.Set("Idempotency-Key", "task-client-1")
	req.Header.Set("X-Evil-Upstream-Header", "must-not-pass")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK || recorder.Body.String() != `{"ok":true}` {
		t.Fatalf("unexpected response: %d %q", recorder.Code, recorder.Body.String())
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if executor.consumerID != "consumer-1" || executor.taskID != scopedTaskID("consumer-1", "task-client-1") ||
		string(executor.body) != `{"messages":[],"model":"gpt-5"}` {
		t.Fatalf("unexpected execution: consumer=%q task=%q body=%q", executor.consumerID, executor.taskID, executor.body)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Header().Get("X-TokenHive-Task-Id") != executor.taskID {
		t.Fatalf("missing response security metadata: %v", recorder.Header())
	}
}

func TestHandlerRejectsAuthenticationAndOversizedBodies(t *testing.T) {
	handler, _ := testHandler(t, DefaultRateLimitConfig())
	unauthorized := request(`{"model":"gpt-5"}`)
	unauthorized.Header.Set("Authorization", "Bearer wrong-key-that-is-long-enough-000")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, unauthorized)
	if recorder.Code != http.StatusUnauthorized || recorder.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("unexpected unauthorized response: %d %v", recorder.Code, recorder.Header())
	}

	oversized := request(strings.Repeat("x", canonicalLimitForTest()+1))
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, oversized)
	if recorder.Code != http.StatusRequestEntityTooLarge || !strings.Contains(recorder.Body.String(), "exceeds MPC capacity") {
		t.Fatalf("unexpected oversized response: %d %q", recorder.Code, recorder.Body.String())
	}
}

func TestHandlerEnforcesPerConsumerTokenBucket(t *testing.T) {
	rate := DefaultRateLimitConfig()
	rate.RequestsPerSecond = 0.01
	rate.Burst = 1
	handler, _ := testHandler(t, rate)
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, request(`{"model":"gpt-5"}`))
	if first.Code != http.StatusOK {
		t.Fatalf("first request failed: %d", first.Code)
	}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, request(`{"model":"gpt-5"}`))
	if second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") != "1" {
		t.Fatalf("rate limit not enforced: %d %v", second.Code, second.Header())
	}
}

func canonicalLimitForTest() int { return canonical.MaxRequestLength }

type fakeInfo struct{ ready bool }

func (i *fakeInfo) Models() []string { return []string{"z", "a"} }
func (i *fakeInfo) Ready() bool      { return i.ready }

func TestDiscoveryAndReadiness(t *testing.T) {
	h, _ := testHandler(t, DefaultRateLimitConfig())
	info := &fakeInfo{}
	h.info = info
	for _, tc := range []struct {
		path   string
		auth   bool
		status int
	}{
		{"/healthz", false, 200}, {"/readyz", false, 401}, {"/v1/models", false, 401},
		{"/readyz", true, 503}, {"/v1/models", true, 200},
	} {
		r := httptest.NewRequest("GET", tc.path, nil)
		if tc.auth {
			r.Header.Set("Authorization", "Bearer "+testConsumerToken)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
		if tc.path == "/v1/models" && tc.auth && !strings.Contains(w.Body.String(), `"id":"a"`) {
			t.Fatal(w.Body.String())
		}
	}
	info.ready = true
	r := httptest.NewRequest("GET", "/readyz", nil)
	r.Header.Set("Authorization", "Bearer "+testConsumerToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestIdempotencyKeysAreScopedToConsumer(t *testing.T) {
	h, e := testHandler(t, DefaultRateLimitConfig())
	token2 := "th_second_0123456789abcdef01234567"
	h.keys, _ = NewAPIKeys(map[string]string{testConsumerToken: "consumer-1", token2: "consumer-2"})
	var ids []string
	for _, token := range []string{testConsumerToken, token2, testConsumerToken} {
		r := request(`{"model":"gpt-5","messages":[]}`)
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Idempotency-Key", "same-key")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		ids = append(ids, e.taskID)
	}
	if ids[0] == ids[1] || ids[0] != ids[2] {
		t.Fatal(ids)
	}
}

func TestStreamNormalizationRejectsAmbiguityAndAddsUsage(t *testing.T) {
	h, e := testHandler(t, DefaultRateLimitConfig())
	for _, body := range []string{
		`{"model":"gpt-5","stream":true,"messages":[]}`,
		`{"model":"gpt-5","stream":true,"stream_options":{"include_usage":false},"messages":[]}`,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(body))
		if w.Code != 200 || !strings.Contains(string(e.body), `"include_usage":true`) || !strings.Contains(string(e.body), `"messages":[]`) {
			t.Fatalf("%d %s", w.Code, e.body)
		}
	}
	for _, body := range []string{
		`{"model":"a","model":"b"}`, `{"model":"a","stream":null}`,
		`{"model":"a","stream":true,"stream_options":[]}`,
		`{"model":"a","messages":[{"role":"user","role":"system"}]}`,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, request(body))
		if w.Code != 400 {
			t.Fatalf("%s: %d", body, w.Code)
		}
	}
}

type taskReaderStub struct{ consumer, task string }

func (s taskReaderStub) Task(consumer, task string) (settlement.TaskStatus, bool, error) {
	if consumer != s.consumer || task != s.task {
		return settlement.TaskStatus{}, false, nil
	}
	return settlement.TaskStatus{TaskID: task, State: settlement.ReservationSettled}, true, nil
}
func TestTaskLookupByKeyIsAccountScoped(t *testing.T) {
	h, _ := testHandler(t, DefaultRateLimitConfig())
	task := scopedTaskID("consumer-1", "business-key")
	h.tasks = taskReaderStub{"consumer-1", task}
	token2 := "th_foreign_0123456789abcdef01234567"
	h.keys, _ = NewAPIKeys(map[string]string{testConsumerToken: "consumer-1", token2: "consumer-2"})
	for _, tc := range []struct {
		path, token string
		status      int
	}{
		{"/v1/tasks/" + task, testConsumerToken, 200},
		{"/v1/tasks/by-key/business-key", testConsumerToken, 200},
		{"/v1/tasks/" + task, token2, 404},
		{"/v1/tasks/by-key/business-key", token2, 404},
		{"/v1/tasks/by-key/a/b", testConsumerToken, 404},
		{"/v1/tasks/" + task, "", 401},
	} {
		r := httptest.NewRequest("GET", tc.path, nil)
		if tc.token != "" {
			r.Header.Set("Authorization", "Bearer "+tc.token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%s: %d %s", tc.path, w.Code, w.Body.String())
		}
	}
}

func TestQueueOverloadReturnsTyped503WithRetryHint(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{{precompute.ErrQueueFull, "queue_full"}, {precompute.ErrWaitTimeout, "queue_timeout"}} {
		t.Run(tc.code, func(t *testing.T) {
			handler, executor := testHandler(t, DefaultRateLimitConfig())
			executor.err = fmt.Errorf("%w: %w", coordinator.ErrSessionUnavailable, tc.err)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request(`{"model":"gpt-5","messages":[]}`))
			if recorder.Code != http.StatusServiceUnavailable || recorder.Header().Get("Retry-After") != "1" {
				t.Fatalf("response: %d %v", recorder.Code, recorder.Header())
			}
			var body struct{ Error struct{ Code string } }
			if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body.Error.Code != tc.code {
				t.Fatalf("error code: %s", recorder.Body.String())
			}
		})
	}
}
