package canonical

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type requestVector struct {
	Adapter             string          `json:"adapter"`
	Host                string          `json:"host"`
	CredentialLength    int             `json:"credential_length"`
	Body                json.RawMessage `json:"body"`
	CanonicalRequestHex string          `json:"canonical_request_hex"`
	PublicRequestHash   string          `json:"public_request_hash"`
	SecretOffset        uint32          `json:"secret_offset"`
	SecretLength        uint32          `json:"secret_length"`
}

func TestOpenAIChatCompletionsCrossLanguageVector(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "testdata", "canonical-request-v1.json")
	encoded, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var vector requestVector
	if err := json.Unmarshal(encoded, &vector); err != nil {
		t.Fatal(err)
	}
	request, err := BuildOpenAIChatCompletions(vector.Host, vector.CredentialLength, vector.Body)
	if err != nil {
		t.Fatal(err)
	}
	if request.Adapter != vector.Adapter {
		t.Fatalf("adapter = %q, want %q", request.Adapter, vector.Adapter)
	}
	if request.Model != "gpt-4o" {
		t.Fatalf("model = %q, want gpt-4o", request.Model)
	}
	if request.Stream {
		t.Fatal("fixture request unexpectedly marked as streaming")
	}
	if hex.EncodeToString(request.Bytes) != vector.CanonicalRequestHex {
		t.Fatal("canonical request bytes do not match fixture")
	}
	if hex.EncodeToString(request.Hash[:]) != vector.PublicRequestHash {
		t.Fatal("public request hash does not match fixture")
	}
	if len(request.Layout.Spans) != 1 || request.Layout.Spans[0].Offset != vector.SecretOffset ||
		request.Layout.Spans[0].Length != vector.SecretLength {
		t.Fatalf("unexpected secret layout: %+v", request.Layout)
	}
	span := request.Layout.Spans[0]
	if !bytes.Equal(request.Bytes[span.Offset:span.Offset+span.Length], make([]byte, span.Length)) {
		t.Fatal("credential slot is not zero-filled")
	}
}

func TestCanonicalJSONSortsKeysAndRejectsAmbiguity(t *testing.T) {
	request, err := BuildOpenAIChatCompletions(
		"api.openai.com",
		32,
		json.RawMessage(` { "z": 1, "model": "gpt-5", "a": { "b": true } } `),
	)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(request.Bytes, []byte(`{"a":{"b":true},"model":"gpt-5","z":1}`)) {
		t.Fatalf("body is not canonical: %q", request.Bytes)
	}

	invalidBodies := []json.RawMessage{
		json.RawMessage(`{"model":"a","model":"b"}`),
		json.RawMessage(`[]`),
		json.RawMessage(`{"model":"a"} trailing`),
		json.RawMessage(`{"messages":[]}`),
		json.RawMessage(`{"model":"bad model"}`),
		json.RawMessage(`{"model":7}`),
		json.RawMessage(`{"model":"gpt-5","stream":"true"}`),
		json.RawMessage(`{"model":"gpt-5","stream":true}`),
		json.RawMessage(`{"model":"gpt-5","stream":true,"stream_options":{}}`),
		json.RawMessage(`{"model":"gpt-5","stream":true,"stream_options":{"include_usage":false}}`),
		json.RawMessage(`{"model":"gpt-5","stream":false,"stream_options":{"include_usage":true}}`),
	}
	for _, body := range invalidBodies {
		if _, err := BuildOpenAIChatCompletions("api.openai.com", 32, body); err == nil {
			t.Fatalf("accepted ambiguous body %q", body)
		}
	}
}

func TestCanonicalRequestBindsStreamingUsagePolicy(t *testing.T) {
	request, err := BuildOpenAIChatCompletions(
		"api.openai.com",
		32,
		json.RawMessage(`{"model":"gpt-5","stream":true,"stream_options":{"include_usage":true}}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.Model != "gpt-5" || !request.Stream {
		t.Fatalf("unexpected request policy: model=%q stream=%v", request.Model, request.Stream)
	}
}

func TestCanonicalRequestRejectsUnsafeMetadata(t *testing.T) {
	body := json.RawMessage(`{"model":"gpt-4o"}`)
	for _, host := range []string{"", "API.OPENAI.COM", "api.openai.com.", "api.openai.com\r\nx: y", "-api.example"} {
		if _, err := BuildOpenAIChatCompletions(host, 32, body); err == nil {
			t.Fatalf("accepted invalid host %q", host)
		}
	}
	for _, length := range []int{0, -1, maxCredentialLength + 1} {
		if _, err := BuildOpenAIChatCompletions("api.openai.com", length, body); err == nil {
			t.Fatalf("accepted invalid credential length %d", length)
		}
	}
}

func TestCanonicalRequestRejectsBodyAboveMPCCapacity(t *testing.T) {
	body := append([]byte(`{"model":"gpt-5","input":"`), bytes.Repeat([]byte{'x'}, MaxRequestLength)...)
	body = append(body, []byte(`"}`)...)
	if _, err := BuildOpenAIChatCompletions("api.openai.com", 32, body); err == nil {
		t.Fatalf("accepted body above %d-byte MPC request capacity", MaxRequestLength)
	}
}

func TestCanonicalRequestAcceptsLargeCapacityBody(t *testing.T) {
	payloadSize := MaxRequestLength - 1024
	body := append([]byte(`{"model":"gpt-5","input":"`), bytes.Repeat([]byte{'x'}, payloadSize)...)
	body = append(body, []byte(`"}`)...)
	request, err := BuildOpenAIChatCompletions("api.openai.com", 32, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(request.Bytes) <= 4<<10 || len(request.Bytes) > MaxRequestLength {
		t.Fatalf("unexpected large canonical request size: %d", len(request.Bytes))
	}
}
