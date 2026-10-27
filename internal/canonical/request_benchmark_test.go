package canonical

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func BenchmarkBuildOpenAIChatCompletions(b *testing.B) {
	for _, padding := range []int{0, 512, 1536, 3072, 3500} {
		body := json.RawMessage(fmt.Sprintf(
			`{"input":"%s","messages":[{"content":"ping","role":"user"}],"model":"gpt-5"}`,
			strings.Repeat("x", padding),
		))
		b.Run(fmt.Sprintf("padding_%d", padding), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if _, err := BuildOpenAIChatCompletions("api.openai.com", 48, body); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
