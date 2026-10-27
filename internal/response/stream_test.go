package response

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func testRequest(t *testing.T) *http.Request {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "https://api.example.com/v1/chat/completions", nil)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestStreamParsesChunkedResponseAndPreservesKeepAliveBytes(t *testing.T) {
	raw := strings.Join([]string{
		"HTTP/1.1 200 OK\r\n",
		"Content-Type: application/json\r\n",
		"Transfer-Encoding: chunked\r\n",
		"Trailer: X-Usage\r\n",
		"X-Request-Id: req_123\r\n",
		"\r\n",
		"2\r\nhe\r\n",
		"3\r\nllo\r\n",
		"0\r\nX-Usage: 5\r\n\r\n",
		"HTTP/1.1 204 No Content\r\n",
		"X-Request-Id: req_124\r\n",
		"\r\n",
	}, "")
	stream, err := NewStream(io.NopCloser(strings.NewReader(raw)))
	if err != nil {
		t.Fatal(err)
	}

	first, err := stream.Next(testRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if !reflectMetadata(first.Metadata, Metadata{StatusCode: 200, RequestID: "req_123", MediaType: "application/json"}) {
		t.Fatalf("unexpected metadata: %+v", first.Metadata)
	}
	if _, err := stream.Next(testRequest(t)); !errors.Is(err, ErrResponseInFlight) {
		t.Fatalf("expected active-body rejection, got %v", err)
	}
	body, err := io.ReadAll(first.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "hello" || first.Trailer.Get("X-Usage") != "5" {
		t.Fatalf("unexpected body/trailer: %q %+v", body, first.Trailer)
	}
	digest := sha256.Sum256(body)
	if outcome := first.Outcome(); outcome.State != StateComplete || outcome.BodyBytes != 5 || outcome.BodySHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}

	second, err := stream.Next(testRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if second.StatusCode != http.StatusNoContent || second.Metadata.RequestID != "req_124" {
		t.Fatalf("unexpected second response: %+v", second.Metadata)
	}
	if body, err := io.ReadAll(second.Body); err != nil || len(body) != 0 {
		t.Fatalf("read empty second body: %q %v", body, err)
	}
}

func TestStreamFailsClosedOnTruncationAndEarlyClose(t *testing.T) {
	stream, err := NewStream(io.NopCloser(strings.NewReader(
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc",
	)))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := stream.Next(testRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(parsed.Body); err == nil {
		t.Fatal("expected truncated body error")
	}
	if outcome := parsed.Outcome(); outcome.State != StateFailed || outcome.ErrorCode != "body_read_failed" {
		t.Fatalf("unexpected truncated outcome: %+v", outcome)
	}
	if _, err := stream.Next(testRequest(t)); !errors.Is(err, ErrResponsePathClosed) {
		t.Fatalf("expected closed response path, got %v", err)
	}

	stream, err = NewStream(io.NopCloser(strings.NewReader(
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
	)))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err = stream.Next(testRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 1)
	if _, err := parsed.Body.Read(buffer); err != nil {
		t.Fatal(err)
	}
	if err := parsed.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if outcome := parsed.Outcome(); outcome.State != StateAborted || outcome.ErrorCode != "body_not_consumed" {
		t.Fatalf("unexpected aborted outcome: %+v", outcome)
	}
}

func TestStreamEnforcesHeaderAndDecodedBodyLimits(t *testing.T) {
	stream, err := newStream(io.NopCloser(strings.NewReader(
		"HTTP/1.1 200 OK\r\nX-Large: 1234567890\r\n\r\n",
	)), 24, 32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(testRequest(t)); !errors.Is(err, ErrHeaderTooLarge) {
		t.Fatalf("expected header limit error, got %v", err)
	}

	stream, err = newStream(io.NopCloser(strings.NewReader(
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
	)), 256, 4)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := stream.Next(testRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(parsed.Body); !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("expected body limit error, got %v", err)
	}
	if outcome := parsed.Outcome(); outcome.State != StateFailed || outcome.BodyBytes != 4 {
		t.Fatalf("unexpected oversized outcome: %+v", outcome)
	}
}

func TestStreamRejectsUnsupportedResponseSemantics(t *testing.T) {
	cases := []string{
		"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
	}
	for _, raw := range cases {
		stream, err := newStream(io.NopCloser(strings.NewReader(raw)), 256, 32)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stream.Next(testRequest(t)); err == nil {
			t.Fatalf("expected rejection for %q", raw)
		}
	}
}

func reflectMetadata(left, right Metadata) bool {
	return left.StatusCode == right.StatusCode &&
		left.RequestID == right.RequestID &&
		left.MediaType == right.MediaType &&
		left.SSE == right.SSE
}

func TestStreamRecognizesSSEContentType(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nContent-Length: 0\r\n\r\n"
	stream, err := NewStream(io.NopCloser(bytes.NewBufferString(raw)))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := stream.Next(testRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.Metadata.SSE || parsed.Metadata.MediaType != "text/event-stream" {
		t.Fatalf("unexpected SSE metadata: %+v", parsed.Metadata)
	}
}
