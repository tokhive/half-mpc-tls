package gateway

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authresponse "tokenhive.local/half-mpc-tls/internal/response"
)

type benchmarkSink struct{}

func (benchmarkSink) RecordReceipt(Receipt) error { return nil }

func BenchmarkRelayOpenAISSE(b *testing.B) {
	const chunks = 256
	var body strings.Builder
	for index := range chunks {
		fmt.Fprintf(&body, "data: {\"id\":\"chatcmpl-bench\",\"model\":\"gpt-5\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"token-%d\"}}]}\n\n", index)
	}
	body.WriteString("data: {\"id\":\"chatcmpl-bench\",\"model\":\"gpt-5\",\"choices\":[],\"usage\":{\"prompt_tokens\":64,\"completion_tokens\":256,\"total_tokens\":320}}\n\n")
	body.WriteString("data: [DONE]\n\n")
	responseBody := body.String()
	raw := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: %d\r\n\r\n%s", len(responseBody), responseBody)
	b.SetBytes(int64(len(responseBody)))
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		stream, err := authresponse.NewStream(io.NopCloser(strings.NewReader(raw)))
		if err != nil {
			b.Fatal(err)
		}
		request, _ := http.NewRequest(http.MethodPost, "https://api.openai.com/v1/chat/completions", nil)
		upstream, err := stream.Next(request)
		if err != nil {
			b.Fatal(err)
		}
		writer := httptest.NewRecorder()
		_, err = RelayOpenAI(writer, upstream, RelayConfig{
			TaskID: "task-bench", ProviderID: "provider-bench", RequestHash: testRequestHash,
			RequestedModel: "gpt-5", Streaming: true, AllowedResponseModels: []string{"gpt-5"},
		}, benchmarkSink{})
		if err != nil {
			b.Fatal(err)
		}
	}
}
