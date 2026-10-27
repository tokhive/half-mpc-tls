package response

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

const DefaultMaxSSEEventBytes = 1 << 20

var (
	ErrSSEEventTooLarge = errors.New("SSE event too large")
	ErrSSETruncated     = errors.New("SSE event stream truncated between events")
)

type SSEEvent struct {
	Event       string
	Data        string
	ID          string
	RetryMillis *int64
}

type SSEDecoder struct {
	reader   *bufio.Reader
	maxEvent int
}

func NewSSEDecoder(source io.Reader) *SSEDecoder {
	return newSSEDecoder(source, DefaultMaxSSEEventBytes)
}

func newSSEDecoder(source io.Reader, maxEvent int) *SSEDecoder {
	if source == nil {
		return &SSEDecoder{maxEvent: maxEvent}
	}
	return &SSEDecoder{reader: bufio.NewReader(source), maxEvent: maxEvent}
}

func (d *SSEDecoder) Next() (SSEEvent, error) {
	if d == nil || d.reader == nil || d.maxEvent <= 0 {
		return SSEEvent{}, ErrSSETruncated
	}
	var event SSEEvent
	var data []string
	eventBytes := 0
	hadFields := false
	for {
		line, err := readBoundedLine(d.reader, d.maxEvent-eventBytes)
		if err != nil {
			if errors.Is(err, io.EOF) && !hadFields {
				return SSEEvent{}, io.EOF
			}
			if errors.Is(err, ErrSSEEventTooLarge) {
				return SSEEvent{}, err
			}
			return SSEEvent{}, ErrSSETruncated
		}
		eventBytes += len(line) + 1
		if eventBytes > d.maxEvent {
			return SSEEvent{}, ErrSSEEventTooLarge
		}
		if len(line) == 0 {
			if len(data) == 0 {
				event = SSEEvent{}
				hadFields = false
				eventBytes = 0
				continue
			}
			event.Data = strings.Join(data, "\n")
			if event.Event == "" {
				event.Event = "message"
			}
			return event, nil
		}
		if line[0] == ':' {
			continue
		}
		hadFields = true
		field, value, _ := strings.Cut(line, ":")
		if strings.HasPrefix(value, " ") {
			value = value[1:]
		}
		switch field {
		case "event":
			event.Event = value
		case "data":
			data = append(data, value)
		case "id":
			if !strings.ContainsRune(value, '\x00') {
				event.ID = value
			}
		case "retry":
			milliseconds, parseErr := strconv.ParseInt(value, 10, 64)
			if parseErr == nil && milliseconds >= 0 {
				event.RetryMillis = &milliseconds
			}
		}
	}
}

func readBoundedLine(reader *bufio.Reader, remaining int) (string, error) {
	if remaining <= 0 {
		return "", ErrSSEEventTooLarge
	}
	var line []byte
	for {
		fragment, prefix, err := reader.ReadLine()
		if len(line)+len(fragment) > remaining {
			return "", ErrSSEEventTooLarge
		}
		line = append(line, fragment...)
		if err != nil {
			if errors.Is(err, io.EOF) && len(line) > 0 {
				return "", fmt.Errorf("%w: missing event delimiter", ErrSSETruncated)
			}
			return "", err
		}
		if !prefix {
			return string(line), nil
		}
	}
}
