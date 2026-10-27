// Package client provides a concurrent-safe Go client for the TokenHive gateway.
// Requests are never automatically retried: a lost response can already be billed.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tokenhive.local/half-mpc-tls/internal/response"
)

// Config configures a shared client. BaseURL includes /v1. HTTPClient may supply
// private CA roots, connection limits, and a timeout appropriate for long streams.
type Config struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("TokenHive base URL must be an HTTPS URL without user info, query or fragment")
	}
	if len(cfg.APIKey) < 32 || len(cfg.APIKey) > 256 || strings.ContainsAny(cfg.APIKey, " \t\r\n") {
		return nil, errors.New("invalid TokenHive API key")
	}
	hc := cfg.HTTPClient
	if hc == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.MaxIdleConns = 100
		transport.MaxIdleConnsPerHost = 32
		hc = &http.Client{Transport: transport, Timeout: 5 * time.Minute}
	}
	// Copy the client to avoid mutating the caller's instance. A redirect must
	// never forward credentials or silently dispatch a task to another endpoint.
	copied := *hc
	copied.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{strings.TrimRight(cfg.BaseURL, "/"), cfg.APIKey, &copied}, nil
}

// CloseIdleConnections releases idle connections without interrupting requests.
func (c *Client) CloseIdleConnections() { c.http.CloseIdleConnections() }

type RequestOptions struct {
	// IdempotencyKey must be reused for retries of the same logical request.
	// An admitted duplicate returns HTTP 409; responses are not cached/replayed.
	IdempotencyKey string
}

type Message struct {
	Role       string          `json:"role"`
	Content    any             `json:"content,omitempty"`
	Name       string          `json:"name,omitempty"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
	ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
}

type ChatRequest struct {
	Model               string          `json:"model"`
	Messages            []Message       `json:"messages"`
	MaxCompletionTokens int64           `json:"max_completion_tokens,omitempty"`
	MaxTokens           int64           `json:"max_tokens,omitempty"`
	Temperature         *float64        `json:"temperature,omitempty"`
	Tools               json.RawMessage `json:"tools,omitempty"`
	ToolChoice          json.RawMessage `json:"tool_choice,omitempty"`
	ResponseFormat      json.RawMessage `json:"response_format,omitempty"`
	// Extra carries upstream-specific JSON fields; reserved fields cannot be overridden.
	Extra map[string]any `json:"-"`
}

type Usage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	Delta        Message `json:"delta"`
	FinishReason *string `json:"finish_reason"`
}

// Completion preserves Raw for fields not represented by the convenience types.
// Streaming chunks use the same structure; Choices[].Delta contains incremental data.
type Completion struct {
	ID      string          `json:"id"`
	Model   string          `json:"model"`
	Choices []Choice        `json:"choices"`
	Usage   *Usage          `json:"usage"`
	TaskID  string          `json:"-"`
	Raw     json.RawMessage `json:"-"`
}

// APIError represents a non-2xx gateway response, including its task identifier.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	TaskID     string
	RetryAfter string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("TokenHive HTTP %d (%s): %s", e.StatusCode, e.Code, e.Message)
}

func (c *Client) Chat(ctx context.Context, request ChatRequest, opts RequestOptions) (*Completion, error) {
	body, err := encodeRequest(request, false)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, http.MethodPost, "/chat/completions", body, opts)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := expectMediaType(resp, "application/json"); err != nil {
		return nil, err
	}
	raw, err := readBounded(resp.Body, 16<<20)
	if err != nil {
		return nil, err
	}
	return decodeCompletion(raw, resp.Header.Get("X-TokenHive-Task-Id"))
}

func (c *Client) Stream(ctx context.Context, request ChatRequest, opts RequestOptions) (*Stream, error) {
	body, err := encodeRequest(request, true)
	if err != nil {
		return nil, err
	}
	resp, err := c.do(ctx, http.MethodPost, "/chat/completions", body, opts)
	if err != nil {
		return nil, err
	}
	if err := expectMediaType(resp, "text/event-stream"); err != nil {
		resp.Body.Close()
		return nil, err
	}
	return &Stream{TaskID: resp.Header.Get("X-TokenHive-Task-Id"), body: resp.Body, decoder: response.NewSSEDecoder(resp.Body)}, nil
}

type Model struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	OwnedBy string `json:"owned_by"`
}

func (c *Client) Models(ctx context.Context) ([]Model, error) {
	resp, err := c.do(ctx, http.MethodGet, "/models", nil, RequestOptions{})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := readBounded(resp.Body, 1<<20)
	if err != nil {
		return nil, err
	}
	var list struct {
		Data []Model `json:"data"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	return list.Data, nil
}

// Stream must be closed. Recv returns io.EOF only on the verified [DONE] marker;
// an interrupted stream returns an error even if HTTP headers indicated success.
// Recv and Close are intended for one consumer; cancel ctx to interrupt a blocked Recv.
type Stream struct {
	TaskID  string
	body    io.ReadCloser
	decoder *response.SSEDecoder
	done    bool
	closed  bool
}

func (s *Stream) Recv() (*Completion, error) {
	if s.done {
		return nil, io.EOF
	}
	if s.closed {
		return nil, io.ErrClosedPipe
	}
	event, err := s.decoder.Next()
	if err != nil {
		s.Close()
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if response.IsSSEDone(event.Data) {
		s.done = true
		s.Close()
		return nil, io.EOF
	}
	chunk, err := decodeCompletion([]byte(event.Data), s.TaskID)
	if err != nil {
		s.Close()
	}
	return chunk, err
}
func (s *Stream) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return s.body.Close()
}

func encodeRequest(request ChatRequest, streaming bool) ([]byte, error) {
	raw, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	reserved := map[string]bool{"model": true, "messages": true, "max_completion_tokens": true, "max_tokens": true, "temperature": true, "tools": true, "tool_choice": true, "response_format": true, "stream": true, "stream_options": true}
	for key, value := range request.Extra {
		if reserved[key] {
			return nil, fmt.Errorf("Extra cannot override reserved field %q", key)
		}
		object[key], err = json.Marshal(value)
		if err != nil {
			return nil, err
		}
	}
	if streaming {
		object["stream"] = json.RawMessage("true")
		object["stream_options"] = json.RawMessage(`{"include_usage":true}`)
	}
	return json.Marshal(object)
}
func (c *Client) do(ctx context.Context, method, path string, body []byte, opts RequestOptions) (*http.Response, error) {
	if opts.IdempotencyKey != "" && !validIdentifier(opts.IdempotencyKey) {
		return nil, errors.New("invalid idempotency key")
	}
	// Use a streaming reader so net/http cannot replay this POST on a stale
	// connection even when the Idempotency-Key header is present.
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		return nil, err
	}
	if method == http.MethodGet {
		req.Body = nil
	} else {
		req.ContentLength = int64(len(body))
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if opts.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", opts.IdempotencyKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return resp, nil
	}
	defer resp.Body.Close()
	raw, _ := readBounded(resp.Body, 64<<10)
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &envelope)
	if envelope.Error.Message == "" {
		envelope.Error.Message = http.StatusText(resp.StatusCode)
	}
	return nil, &APIError{resp.StatusCode, envelope.Error.Code, envelope.Error.Message, resp.Header.Get("X-TokenHive-Task-Id"), resp.Header.Get("Retry-After")}
}
func readBounded(r io.Reader, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, errors.New("TokenHive response exceeds client limit")
	}
	return raw, nil
}
func expectMediaType(resp *http.Response, expected string) error {
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != expected {
		return fmt.Errorf("unexpected response content type: expected %s", expected)
	}
	return nil
}
func decodeCompletion(raw []byte, task string) (*Completion, error) {
	var value Completion
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	value.TaskID = task
	value.Raw = append(json.RawMessage(nil), raw...)
	return &value, nil
}

// TaskStatus describes durable settlement state, not a cached model response.
// Pending or review_required means the outcome remains unresolved; do not
// resubmit under a new key. Review retains the reserve for manual reconciliation.
type TaskStatus struct {
	TaskID         string `json:"task_id"`
	State          string `json:"state"`
	Model          string `json:"model"`
	Currency       string `json:"currency"`
	ReservedMicros int64  `json:"reserved_micros"`
	ChargeMicros   int64  `json:"charge_micros"`
	RefundMicros   int64  `json:"refund_micros"`
	InputTokens    int64  `json:"input_tokens"`
	OutputTokens   int64  `json:"output_tokens"`
	ReviewReason   string `json:"review_reason,omitempty"`
}

func (c *Client) Task(ctx context.Context, taskID string) (*TaskStatus, error) {
	if !validIdentifier(taskID) {
		return nil, errors.New("invalid task ID")
	}
	return c.task(ctx, "/tasks/"+taskID)
}

// TaskByKey recovers task state when a network failure lost the response headers.
// Lookup is scoped to the account authenticated by this client.
func (c *Client) TaskByKey(ctx context.Context, key string) (*TaskStatus, error) {
	if !validIdentifier(key) {
		return nil, errors.New("invalid idempotency key")
	}
	return c.task(ctx, "/tasks/by-key/"+key)
}
func (c *Client) task(ctx context.Context, path string) (*TaskStatus, error) {
	resp, err := c.do(ctx, http.MethodGet, path, nil, RequestOptions{})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := readBounded(resp.Body, 64<<10)
	if err != nil {
		return nil, err
	}
	var status TaskStatus
	if err := json.Unmarshal(raw, &status); err != nil {
		return nil, err
	}
	return &status, nil
}
func validIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
