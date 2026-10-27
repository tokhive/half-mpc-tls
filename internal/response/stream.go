package response

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
)

const (
	DefaultMaxHeaderBytes = 64 << 10
	DefaultMaxBodyBytes   = 16 << 20
)

var (
	ErrInvalidHTTPResponse = errors.New("invalid authenticated HTTP response")
	ErrHeaderTooLarge      = errors.New("authenticated HTTP response headers too large")
	ErrBodyTooLarge        = errors.New("authenticated HTTP response body too large")
	ErrResponseInFlight    = errors.New("authenticated HTTP response body is still active")
	ErrResponsePathClosed  = errors.New("authenticated HTTP response path is closed")
	ErrResponseAborted     = errors.New("authenticated HTTP response body was not fully consumed")
)

type State string

const (
	StateReading  State = "reading"
	StateComplete State = "complete"
	StateFailed   State = "failed"
	StateAborted  State = "aborted"
)

type Metadata struct {
	StatusCode int
	RequestID  string
	MediaType  string
	SSE        bool
}

type Outcome struct {
	State      State
	BodyBytes  int64
	BodySHA256 string
	ErrorCode  string
}

type Response struct {
	*http.Response
	Metadata Metadata
	body     *trackedBody
}

func (r *Response) Outcome() Outcome {
	if r == nil || r.body == nil {
		return Outcome{State: StateFailed, ErrorCode: "missing_body"}
	}
	return r.body.outcome()
}

type Stream struct {
	mu         sync.Mutex
	source     io.ReadCloser
	gate       *headerGateReader
	reader     *bufio.Reader
	activeBody *trackedBody
	closed     bool
	maxHeader  int64
	maxBody    int64
}

func NewStream(source io.ReadCloser) (*Stream, error) {
	return newStream(source, DefaultMaxHeaderBytes, DefaultMaxBodyBytes)
}

func newStream(source io.ReadCloser, maxHeader, maxBody int64) (*Stream, error) {
	if source == nil || maxHeader <= 0 || maxBody <= 0 {
		return nil, fmt.Errorf("%w: invalid stream limits", ErrInvalidHTTPResponse)
	}
	gate := &headerGateReader{source: source}
	return &Stream{
		source:    source,
		gate:      gate,
		reader:    bufio.NewReader(gate),
		maxHeader: maxHeader,
		maxBody:   maxBody,
	}, nil
}

func (s *Stream) Next(request *http.Request) (*Response, error) {
	if request == nil {
		return nil, fmt.Errorf("%w: request is required", ErrInvalidHTTPResponse)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrResponsePathClosed
	}
	if s.activeBody != nil {
		return nil, ErrResponseInFlight
	}
	if err := s.gate.begin(s.maxHeader, s.reader.Buffered()); err != nil {
		s.failLocked()
		return nil, err
	}
	httpResponse, err := http.ReadResponse(s.reader, request)
	headerLimitHit := s.gate.end()
	if err != nil {
		s.failLocked()
		if headerLimitHit {
			return nil, ErrHeaderTooLarge
		}
		return nil, fmt.Errorf("%w: parse failed", ErrInvalidHTTPResponse)
	}
	metadata, err := validateResponse(httpResponse, s.maxBody)
	if err != nil {
		_ = httpResponse.Body.Close()
		s.failLocked()
		return nil, err
	}
	body := &trackedBody{
		source:     httpResponse.Body,
		owner:      s,
		state:      StateReading,
		maxBytes:   s.maxBody,
		closeAfter: httpResponse.Close,
		hash:       sha256.New(),
	}
	s.activeBody = body
	httpResponse.Body = body
	return &Response{Response: httpResponse, Metadata: metadata, body: body}, nil
}

func (s *Stream) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	return s.source.Close()
}

func (s *Stream) bodyFinished(body *trackedBody, state State, closeAfter bool) {
	s.mu.Lock()
	if s.activeBody == body {
		s.activeBody = nil
	}
	shouldClose := state != StateComplete || closeAfter
	if shouldClose {
		s.closed = true
	}
	s.mu.Unlock()
	if shouldClose {
		_ = s.source.Close()
	}
}

func (s *Stream) failLocked() {
	s.closed = true
	_ = s.source.Close()
}

func validateResponse(response *http.Response, maxBody int64) (Metadata, error) {
	if response.ProtoMajor != 1 || response.ProtoMinor != 1 || response.StatusCode < 200 || response.StatusCode > 599 {
		return Metadata{}, ErrInvalidHTTPResponse
	}
	if response.StatusCode == http.StatusSwitchingProtocols || response.Header.Get("Upgrade") != "" {
		return Metadata{}, ErrInvalidHTTPResponse
	}
	if response.ContentLength > maxBody {
		return Metadata{}, ErrBodyTooLarge
	}
	if encoding := strings.TrimSpace(response.Header.Get("Content-Encoding")); encoding != "" && !strings.EqualFold(encoding, "identity") {
		return Metadata{}, ErrInvalidHTTPResponse
	}

	mediaType := ""
	if raw := response.Header.Get("Content-Type"); raw != "" {
		parsed, _, err := mime.ParseMediaType(raw)
		if err != nil {
			return Metadata{}, ErrInvalidHTTPResponse
		}
		mediaType = strings.ToLower(parsed)
	}
	requestID := firstHeader(response.Header, "X-Request-Id", "Openai-Request-Id", "Request-Id")
	if len(requestID) > 256 || !printableASCII(requestID) {
		return Metadata{}, ErrInvalidHTTPResponse
	}
	return Metadata{
		StatusCode: response.StatusCode,
		RequestID:  requestID,
		MediaType:  mediaType,
		SSE:        mediaType == "text/event-stream",
	}, nil
}

func printableASCII(value string) bool {
	for _, character := range []byte(value) {
		if character < 0x20 || character > 0x7e {
			return false
		}
	}
	return true
}

func firstHeader(header http.Header, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(header.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

type headerGateReader struct {
	source    io.Reader
	limited   bool
	remaining int64
	limitHit  bool
}

func (r *headerGateReader) begin(limit int64, buffered int) error {
	if int64(buffered) > limit {
		return ErrHeaderTooLarge
	}
	r.limited = true
	r.remaining = limit - int64(buffered)
	r.limitHit = false
	return nil
}

func (r *headerGateReader) end() bool {
	r.limited = false
	return r.limitHit
}

func (r *headerGateReader) Read(destination []byte) (int, error) {
	if !r.limited {
		return r.source.Read(destination)
	}
	if r.remaining == 0 {
		r.limitHit = true
		return 0, ErrHeaderTooLarge
	}
	if int64(len(destination)) > r.remaining {
		destination = destination[:r.remaining]
	}
	n, err := r.source.Read(destination)
	r.remaining -= int64(n)
	return n, err
}

type trackedBody struct {
	mu         sync.Mutex
	source     io.ReadCloser
	owner      *Stream
	state      State
	maxBytes   int64
	bytes      int64
	errorCode  string
	closeAfter bool
	hash       hashWriter
}

type hashWriter interface {
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

func (b *trackedBody) Read(destination []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(destination) == 0 {
		return 0, nil
	}
	if b.state == StateComplete {
		return 0, io.EOF
	}
	if b.state == StateAborted {
		return 0, ErrResponseAborted
	}
	if b.state != StateReading {
		return 0, ErrResponsePathClosed
	}
	remaining := b.maxBytes - b.bytes
	if remaining == 0 {
		var probe [1]byte
		n, err := b.source.Read(probe[:])
		if n > 0 {
			b.finishLocked(StateFailed, "body_too_large")
			return 0, ErrBodyTooLarge
		}
		if errors.Is(err, io.EOF) {
			b.finishLocked(StateComplete, "")
			return 0, io.EOF
		}
		if err != nil {
			b.finishLocked(StateFailed, "body_read_failed")
			return 0, err
		}
		return 0, nil
	}
	if int64(len(destination)) > remaining {
		destination = destination[:remaining]
	}
	n, err := b.source.Read(destination)
	if n > 0 {
		b.bytes += int64(n)
		_, _ = b.hash.Write(destination[:n])
	}
	if errors.Is(err, io.EOF) {
		b.finishLocked(StateComplete, "")
	} else if err != nil {
		b.finishLocked(StateFailed, "body_read_failed")
	}
	return n, err
}

func (b *trackedBody) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	if b.state == StateReading {
		b.finishLocked(StateAborted, "body_not_consumed")
	}
	b.mu.Unlock()
	return b.source.Close()
}

func (b *trackedBody) finishLocked(state State, errorCode string) {
	if b.state != StateReading {
		return
	}
	b.state = state
	b.errorCode = errorCode
	b.owner.bodyFinished(b, state, b.closeAfter)
	// On failure/abort, bodyFinished closes the attachment first. This keeps
	// net/http's Body.Close from blocking while trying to drain a long stream.
	_ = b.source.Close()
}

func (b *trackedBody) outcome() Outcome {
	b.mu.Lock()
	defer b.mu.Unlock()
	outcome := Outcome{State: b.state, BodyBytes: b.bytes, ErrorCode: b.errorCode}
	if b.state == StateComplete {
		outcome.BodySHA256 = hex.EncodeToString(b.hash.Sum(nil))
	}
	return outcome
}
