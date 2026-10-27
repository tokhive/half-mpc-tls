package response

import (
	"errors"
	"io"
	"strings"
	"testing"
)

type smallChunkReader struct {
	source io.Reader
	max    int
}

func (r smallChunkReader) Read(destination []byte) (int, error) {
	if len(destination) > r.max {
		destination = destination[:r.max]
	}
	return r.source.Read(destination)
}

func TestSSEDecoderHandlesFragmentedCRLFAndMultilineData(t *testing.T) {
	raw := ": keepalive\r\nevent: response.output_text.delta\r\nid: evt_1\r\n" +
		"data: {\"delta\":\"hel\"}\r\ndata: second line\r\nretry: 1500\r\n\r\n" +
		"data: [DONE]\n\n"
	decoder := NewSSEDecoder(smallChunkReader{source: strings.NewReader(raw), max: 3})
	first, err := decoder.Next()
	if err != nil {
		t.Fatal(err)
	}
	if first.Event != "response.output_text.delta" || first.ID != "evt_1" || first.Data != "{\"delta\":\"hel\"}\nsecond line" {
		t.Fatalf("unexpected first event: %+v", first)
	}
	if first.RetryMillis == nil || *first.RetryMillis != 1500 {
		t.Fatalf("unexpected retry: %+v", first.RetryMillis)
	}
	second, err := decoder.Next()
	if err != nil {
		t.Fatal(err)
	}
	if second.Event != "message" || second.Data != "[DONE]" {
		t.Fatalf("unexpected terminal event: %+v", second)
	}
	if _, err := decoder.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected EOF, got %v", err)
	}
}

func TestSSEDecoderRejectsOversizedAndTruncatedEvents(t *testing.T) {
	decoder := newSSEDecoder(strings.NewReader("data: 123456789\n\n"), 10)
	if _, err := decoder.Next(); !errors.Is(err, ErrSSEEventTooLarge) {
		t.Fatalf("expected event size error, got %v", err)
	}

	decoder = NewSSEDecoder(strings.NewReader("data: unfinished"))
	if _, err := decoder.Next(); !errors.Is(err, ErrSSETruncated) {
		t.Fatalf("expected truncation error, got %v", err)
	}
}

func TestSSEDecoderIgnoresUnknownFieldsAndEventsWithoutData(t *testing.T) {
	decoder := NewSSEDecoder(strings.NewReader("id: ignored-without-data\nfoo: bar\n\ndata: ok\n\n"))
	event, err := decoder.Next()
	if err != nil {
		t.Fatal(err)
	}
	if event.Data != "ok" || event.Event != "message" || event.ID != "" {
		t.Fatalf("unexpected event: %+v", event)
	}
}
