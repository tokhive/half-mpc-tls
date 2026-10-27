package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "th_client_0123456789abcdef01234567"

func newTestClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	s := httptest.NewTLSServer(handler)
	t.Cleanup(s.Close)
	c, err := New(Config{BaseURL: s.URL + "/v1", APIKey: testToken, HTTPClient: s.Client()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}
func TestChatAndStreamPreserveExtraFields(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testToken || r.Header.Get("Idempotency-Key") != "business-1" {
			t.Error("missing authentication or idempotency key")
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body["custom"] != "kept" {
			t.Error(body)
		}
		w.Header().Set("X-TokenHive-Task-Id", "task-123")
		if body["stream"] == true {
			if body["stream_options"].(map[string]any)["include_usage"] != true {
				t.Error(body)
			}
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"id\":\"id-1\",\"choices\":[{\"delta\":{\"content\":\"你好\"}}]}\n\ndata: [DONE]\n\n")
		} else {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"id-1","model":"m","choices":[],"custom_response":true}`)
		}
	})
	req := ChatRequest{Model: "m", Messages: []Message{{Role: "user", Content: "hi"}}, Extra: map[string]any{"custom": "kept"}}
	opts := RequestOptions{IdempotencyKey: "business-1"}
	result, err := c.Chat(context.Background(), req, opts)
	if err != nil || result.TaskID != "task-123" || !strings.Contains(string(result.Raw), "custom_response") {
		t.Fatalf("%+v %v", result, err)
	}
	stream, err := c.Stream(context.Background(), req, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	chunk, err := stream.Recv()
	if err != nil || chunk.Choices[0].Delta.Content != "你好" {
		t.Fatalf("%+v %v", chunk, err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}
func TestTruncatedStreamIsNotSuccess(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"id\":\"x\"}\n\n")
	})
	s, err := c.Stream(context.Background(), ChatRequest{Model: "m"}, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Recv(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Recv(); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}
func TestAPIErrorNoAutomaticRetryOrRedirect(t *testing.T) {
	var calls atomic.Int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "1")
		w.Header().Set("X-TokenHive-Task-Id", "task-failed")
		w.WriteHeader(503)
		fmt.Fprint(w, `{"error":{"code":"provider_unavailable","message":"warming"}}`)
	})
	_, err := c.Chat(context.Background(), ChatRequest{Model: "m"}, RequestOptions{IdempotencyKey: "op-1"})
	var apiError *APIError
	if !errors.As(err, &apiError) || apiError.StatusCode != 503 || apiError.TaskID != "task-failed" || apiError.RetryAfter != "1" || calls.Load() != 1 {
		t.Fatalf("%v %d", err, calls.Load())
	}
	var targetCalls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	redirected := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) })
	_, err = redirected.Chat(context.Background(), ChatRequest{Model: "m"}, RequestOptions{})
	if !errors.As(err, &apiError) || apiError.StatusCode != 307 || targetCalls.Load() != 0 {
		t.Fatal(err)
	}
}
func TestCancellationAndReservedFields(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body); <-r.Context().Done() })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := c.Chat(ctx, ChatRequest{Model: "m"}, RequestOptions{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	_, err = encodeRequest(ChatRequest{Extra: map[string]any{"stream": false}}, true)
	if err == nil {
		t.Fatal("reserved stream override accepted")
	}
}
