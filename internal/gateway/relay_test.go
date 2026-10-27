package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	authresponse "tokenhive.local/half-mpc-tls/internal/response"
)

const testRequestHash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type memorySink struct {
	receipts []Receipt
	err      error
}

type failingResponseWriter struct {
	header http.Header
}

func (w *failingResponseWriter) Header() http.Header {
	return w.header
}

func (w *failingResponseWriter) WriteHeader(_ int) {}

func (w *failingResponseWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("consumer disconnected")
}

func (w *failingResponseWriter) Flush() {}

func (s *memorySink) RecordReceipt(receipt Receipt) error {
	if s.err != nil {
		return s.err
	}
	s.receipts = append(s.receipts, receipt)
	return nil
}

func relayConfig(streaming bool) RelayConfig {
	return RelayConfig{
		TaskID:                "task-123",
		ProviderID:            "provider-7",
		RequestHash:           testRequestHash,
		RequestedModel:        "gpt-5",
		Streaming:             streaming,
		AllowedResponseModels: []string{"gpt-5", "gpt-5-2026-08-01"},
	}
}

func parsedResponse(t *testing.T, raw string) *authresponse.Response {
	t.Helper()
	stream, err := authresponse.NewStream(io.NopCloser(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := stream.Next(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func rawResponse(status, contentType, body string) string {
	return "HTTP/1.1 " + status + "\r\nContent-Type: " + contentType +
		"\r\nX-Request-Id: req_http_1\r\nContent-Length: " +
		strconvItoa(len(body)) + "\r\n\r\n" + body
}

func TestRelayJSONCommitsOnlyValidatedBillableResponse(t *testing.T) {
	body := `{"id":"chatcmpl_1","model":"gpt-5-2026-08-01","choices":[],"usage":{"prompt_tokens":8,"completion_tokens":2,"total_tokens":10}}`
	upstream := parsedResponse(t, rawResponse("200 OK", "application/json", body))
	recorder := httptest.NewRecorder()
	sink := &memorySink{}
	receipt, err := RelayOpenAI(recorder, upstream, relayConfig(false), sink)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(body))
	if recorder.Body.String() != body || recorder.Code != http.StatusOK || recorder.Header().Get("X-Request-Id") != "req_http_1" {
		t.Fatalf("unexpected downstream response: code=%d headers=%v body=%q", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if !receipt.Billable || receipt.ResponseModel != "gpt-5-2026-08-01" || receipt.UpstreamResponseID != "chatcmpl_1" ||
		receipt.Usage.TotalTokens != 10 || receipt.ResponseHash != hex.EncodeToString(digest[:]) || receipt.BodyBytes != int64(len(body)) {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	if len(sink.receipts) != 1 || sink.receipts[0] != receipt {
		t.Fatalf("receipt was not committed exactly once: %+v", sink.receipts)
	}
}

func TestRelayJSONRejectsModelSwapBeforeWriting(t *testing.T) {
	body := `{"id":"chatcmpl_1","model":"cheap-model","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	upstream := parsedResponse(t, rawResponse("200 OK", "application/json", body))
	recorder := httptest.NewRecorder()
	if receipt, err := RelayOpenAI(recorder, upstream, relayConfig(false), &memorySink{}); !errors.Is(err, ErrResponseRejected) || receipt.Billable {
		t.Fatalf("expected model rejection, receipt=%+v err=%v", receipt, err)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("invalid JSON was written downstream: %q", recorder.Body.String())
	}
}

func TestRelayJSONRejectsTruncationBeforeWriting(t *testing.T) {
	upstream := parsedResponse(t, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"id\":\"short\"}")
	recorder := httptest.NewRecorder()
	if _, err := RelayOpenAI(recorder, upstream, relayConfig(false), &memorySink{}); !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("expected truncation rejection, got %v", err)
	}
	if recorder.Body.Len() != 0 || upstream.Outcome().State != authresponse.StateFailed {
		t.Fatalf("truncated response was committed: body=%q outcome=%+v", recorder.Body.String(), upstream.Outcome())
	}
}

func TestRelayAuthenticatedUpstreamErrorIsNotBillable(t *testing.T) {
	body := `{"error":{"message":"rate limited"}}`
	upstream := parsedResponse(t, rawResponse("429 Too Many Requests", "application/json", body))
	recorder := httptest.NewRecorder()
	receipt, err := RelayOpenAI(recorder, upstream, relayConfig(false), &memorySink{})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Billable || receipt.StatusCode != http.StatusTooManyRequests || recorder.Code != http.StatusTooManyRequests || recorder.Body.String() != body {
		t.Fatalf("unexpected non-billable relay: receipt=%+v code=%d body=%q", receipt, recorder.Code, recorder.Body.String())
	}
}

func TestRelaySSEValidatesEventsAndWithholdsDoneUntilEOF(t *testing.T) {
	first := `{"id":"chatcmpl_stream","model":"gpt-5","choices":[{"delta":{"content":"hi"}}],"usage":null}`
	usage := `{"id":"chatcmpl_stream","model":"gpt-5","choices":[],"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5}}`
	body := "data: " + first + "\n\ndata: " + usage + "\n\ndata: [DONE]\n\n"
	upstream := parsedResponse(t, rawResponse("200 OK", "text/event-stream; charset=utf-8", body))
	recorder := httptest.NewRecorder()
	receipt, err := RelayOpenAI(recorder, upstream, relayConfig(true), &memorySink{})
	if err != nil {
		t.Fatal(err)
	}
	expected := "data: " + first + "\n\ndata: " + usage + "\n\ndata: [DONE]\n\n"
	if recorder.Body.String() != expected || !recorder.Flushed {
		t.Fatalf("unexpected SSE output: flushed=%v body=%q", recorder.Flushed, recorder.Body.String())
	}
	if !receipt.Billable || !receipt.Streaming || receipt.Usage.TotalTokens != 5 || receipt.ResponseModel != "gpt-5" {
		t.Fatalf("unexpected streaming receipt: %+v", receipt)
	}
}

func TestRelaySSERejectsModelSwapWithoutReceipt(t *testing.T) {
	first := `{"id":"chatcmpl_stream","model":"gpt-5","choices":[{"delta":{"content":"accepted"}}]}`
	swapped := `{"id":"chatcmpl_stream","model":"cheap-model","choices":[{"delta":{"content":"blocked"}}]}`
	body := "data: " + first + "\n\ndata: " + swapped + "\n\ndata: [DONE]\n\n"
	upstream := parsedResponse(t, rawResponse("200 OK", "text/event-stream", body))
	recorder := httptest.NewRecorder()
	receipt, err := RelayOpenAI(recorder, upstream, relayConfig(true), &memorySink{})
	if !errors.Is(err, ErrResponseRejected) || receipt.Billable {
		t.Fatalf("expected SSE model rejection, receipt=%+v err=%v", receipt, err)
	}
	if !strings.Contains(recorder.Body.String(), "accepted") || strings.Contains(recorder.Body.String(), "blocked") || strings.Contains(recorder.Body.String(), "[DONE]") {
		t.Fatalf("unexpected partial SSE output: %q", recorder.Body.String())
	}
	// The buffered parser may have already authenticated the remaining bytes,
	// but semantic rejection still prevents both the swapped event and receipt.
}

func TestRelayRejectsResponseModeMismatch(t *testing.T) {
	body := `{"id":"chatcmpl_1","model":"gpt-5","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	upstream := parsedResponse(t, rawResponse("200 OK", "application/json", body))
	recorder := httptest.NewRecorder()
	if _, err := RelayOpenAI(recorder, upstream, relayConfig(true), &memorySink{}); !errors.Is(err, ErrResponseRejected) {
		t.Fatalf("expected response mode rejection, got %v", err)
	}
	if upstream.Outcome().State != authresponse.StateAborted {
		t.Fatalf("mode mismatch should abort body: %+v", upstream.Outcome())
	}
}

func TestRelayRejectsInvalidTaskBinding(t *testing.T) {
	config := relayConfig(false)
	config.RequestHash = strings.ToUpper(config.RequestHash)
	upstream := parsedResponse(t, rawResponse("500 Internal Server Error", "application/json", `{}`))
	if _, err := RelayOpenAI(httptest.NewRecorder(), upstream, config, &memorySink{}); !errors.Is(err, ErrInvalidRelayConfig) {
		t.Fatalf("expected invalid config, got %v", err)
	}
}

func TestRelayDoesNotCommitTerminalSuccessWhenReceiptSinkFails(t *testing.T) {
	body := `{"id":"chatcmpl_1","model":"gpt-5","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	upstream := parsedResponse(t, rawResponse("200 OK", "application/json", body))
	recorder := httptest.NewRecorder()
	sink := &memorySink{err: errors.New("disk unavailable")}
	receipt, err := RelayOpenAI(recorder, upstream, relayConfig(false), sink)
	if !errors.Is(err, ErrReceiptCommit) || !receipt.Billable || receipt.TaskID != "task-123" {
		t.Fatalf("expected receipt commit error, got %v", err)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("JSON response committed before receipt: %q", recorder.Body.String())
	}

	first := `{"id":"chatcmpl_stream","model":"gpt-5","choices":[]}`
	usage := `{"id":"chatcmpl_stream","model":"gpt-5","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	sseBody := "data: " + first + "\n\ndata: " + usage + "\n\ndata: [DONE]\n\n"
	upstream = parsedResponse(t, rawResponse("200 OK", "text/event-stream", sseBody))
	recorder = httptest.NewRecorder()
	receipt, err = RelayOpenAI(recorder, upstream, relayConfig(true), sink)
	if !errors.Is(err, ErrReceiptCommit) || !receipt.Billable || !receipt.Streaming {
		t.Fatalf("expected streaming receipt commit error, got %v", err)
	}
	if !strings.Contains(recorder.Body.String(), "chatcmpl_stream") || strings.Contains(recorder.Body.String(), "[DONE]") {
		t.Fatalf("SSE terminal marker committed before receipt: %q", recorder.Body.String())
	}
}

func TestRelayReturnsCommittedReceiptWhenConsumerWriteFails(t *testing.T) {
	body := `{"id":"chatcmpl_1","model":"gpt-5","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	upstream := parsedResponse(t, rawResponse("200 OK", "application/json", body))
	sink := &memorySink{}
	writer := &failingResponseWriter{header: make(http.Header)}
	receipt, err := RelayOpenAI(writer, upstream, relayConfig(false), sink)
	if !errors.Is(err, ErrDownstreamWrite) {
		t.Fatalf("expected downstream write error, got %v", err)
	}
	if !receipt.Billable || len(sink.receipts) != 1 || sink.receipts[0] != receipt {
		t.Fatalf("committed receipt was lost: receipt=%+v sink=%+v", receipt, sink.receipts)
	}

	first := `{"id":"chatcmpl_stream","model":"gpt-5","choices":[{"delta":{"content":"charged"}}]}`
	usage := `{"id":"chatcmpl_stream","model":"gpt-5","choices":[],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	sseBody := "data: " + first + "\n\ndata: " + usage + "\n\ndata: [DONE]\n\n"
	upstream = parsedResponse(t, rawResponse("200 OK", "text/event-stream", sseBody))
	sink = &memorySink{}
	receipt, err = RelayOpenAI(writer, upstream, relayConfig(true), sink)
	if !errors.Is(err, ErrDownstreamWrite) {
		t.Fatalf("expected streaming downstream write error, got %v", err)
	}
	if !receipt.Billable || !receipt.Streaming || receipt.Usage.TotalTokens != 2 ||
		len(sink.receipts) != 1 || sink.receipts[0] != receipt || upstream.Outcome().State != authresponse.StateComplete {
		t.Fatalf("stream was not drained and settled: receipt=%+v sink=%+v outcome=%+v", receipt, sink.receipts, upstream.Outcome())
	}
}

func strconvItoa(value int) string {
	return strconv.Itoa(value)
}
