package response

import (
	"errors"
	"strings"
	"testing"
)

func TestExtractOpenAIResultSupportsChatAndResponsesUsage(t *testing.T) {
	tests := []struct {
		json     string
		expected OpenAIResult
	}{
		{
			json:     `{"id":"chatcmpl_1","model":"gpt-5","usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18,"prompt_tokens_details":{"cached_tokens":3}}}`,
			expected: OpenAIResult{ID: "chatcmpl_1", Model: "gpt-5", Usage: &TokenUsage{InputTokens: 11, OutputTokens: 7, TotalTokens: 18}},
		},
		{
			json:     `{"id":"resp_1","model":"gpt-5.1","usage":{"input_tokens":20,"output_tokens":4,"total_tokens":24}}`,
			expected: OpenAIResult{ID: "resp_1", Model: "gpt-5.1", Usage: &TokenUsage{InputTokens: 20, OutputTokens: 4, TotalTokens: 24}},
		},
		{
			json:     `{"id":"chunk_1","model":"gpt-5","usage":null,"choices":[]}`,
			expected: OpenAIResult{ID: "chunk_1", Model: "gpt-5"},
		},
	}
	for _, test := range tests {
		actual, err := ExtractOpenAIResult([]byte(test.json))
		if err != nil {
			t.Fatalf("extract %s: %v", test.json, err)
		}
		if actual.ID != test.expected.ID || actual.Model != test.expected.Model || !equalUsage(actual.Usage, test.expected.Usage) {
			t.Fatalf("unexpected result: %+v", actual)
		}
	}
}

func TestExtractOpenAIResultRejectsAmbiguousOrInvalidBillingData(t *testing.T) {
	tests := []string{
		`{"usage":{"prompt_tokens":1,"prompt_tokens":2,"completion_tokens":1,"total_tokens":3}}`,
		`{"usage":{"prompt_tokens":1,"input_tokens":1,"completion_tokens":1,"total_tokens":2}}`,
		`{"usage":{"prompt_tokens":-1,"completion_tokens":1,"total_tokens":0}}`,
		`{"usage":{"prompt_tokens":1.5,"completion_tokens":1,"total_tokens":2}}`,
		`{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":3}}`,
		`{"usage":{"prompt_tokens":1,"completion_tokens":1}}`,
		`{"model":"bad\nmodel"}`,
		`[1,2,3]`,
		`{"id":"x"} trailing`,
	}
	for _, input := range tests {
		if _, err := ExtractOpenAIResult([]byte(input)); !errors.Is(err, ErrInvalidOpenAIResponse) {
			t.Fatalf("expected invalid metadata for %q, got %v", input, err)
		}
	}
}

func TestExtractOpenAIResultRejectsExcessiveNestingAndDoneMarker(t *testing.T) {
	deep := strings.Repeat(`{"x":`, maxJSONDepth+2) + `0` + strings.Repeat(`}`, maxJSONDepth+2)
	if _, err := ExtractOpenAIResult([]byte(deep)); !errors.Is(err, ErrInvalidOpenAIResponse) {
		t.Fatalf("expected nesting error, got %v", err)
	}
	if !IsSSEDone("  [DONE]\r\n") {
		t.Fatal("expected SSE done marker")
	}
	if _, err := ExtractOpenAIResult([]byte("[DONE]")); !errors.Is(err, ErrInvalidOpenAIResponse) {
		t.Fatalf("expected done marker rejection, got %v", err)
	}
}

func TestOpenAIAccumulatorRequiresStableModelUsageAndDone(t *testing.T) {
	var accumulator OpenAIAccumulator
	chunks := []string{
		`{"id":"chatcmpl_1","model":"gpt-5-2026-08-01","choices":[{"delta":{"content":"hi"}}],"usage":null}`,
		`{"id":"chatcmpl_1","model":"gpt-5-2026-08-01","choices":[],"usage":{"prompt_tokens":8,"completion_tokens":2,"total_tokens":10}}`,
	}
	for _, chunk := range chunks {
		done, err := accumulator.ObserveSSEData(chunk)
		if err != nil || done {
			t.Fatalf("observe chunk: done=%v err=%v", done, err)
		}
	}
	if _, err := accumulator.Finalize([]string{"gpt-5-2026-08-01"}); !errors.Is(err, ErrInvalidOpenAIResponse) {
		t.Fatalf("expected missing done rejection, got %v", err)
	}
	done, err := accumulator.ObserveSSEData("[DONE]")
	if err != nil || !done {
		t.Fatalf("observe done: done=%v err=%v", done, err)
	}
	result, err := accumulator.Finalize([]string{"gpt-5", "gpt-5-2026-08-01"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Model != "gpt-5-2026-08-01" || result.Usage == nil || result.Usage.TotalTokens != 10 {
		t.Fatalf("unexpected final result: %+v", result)
	}
	if _, err := accumulator.ObserveSSEData(chunks[0]); !errors.Is(err, ErrInvalidOpenAIResponse) {
		t.Fatalf("expected post-done rejection, got %v", err)
	}
}

func TestOpenAIAccumulatorRejectsModelOrUsageChanges(t *testing.T) {
	var modelChange OpenAIAccumulator
	if _, err := modelChange.ObserveSSEData(`{"id":"x","model":"gpt-5"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := modelChange.ObserveSSEData(`{"id":"x","model":"cheap-model"}`); !errors.Is(err, ErrInvalidOpenAIResponse) {
		t.Fatalf("expected model change rejection, got %v", err)
	}

	var usageChange OpenAIAccumulator
	first := `{"id":"x","model":"gpt-5","usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`
	second := `{"id":"x","model":"gpt-5","usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`
	if _, err := usageChange.ObserveSSEData(first); err != nil {
		t.Fatal(err)
	}
	if _, err := usageChange.ObserveSSEData(second); !errors.Is(err, ErrInvalidOpenAIResponse) {
		t.Fatalf("expected usage change rejection, got %v", err)
	}
	if result, _ := ExtractOpenAIResult([]byte(first)); result.ValidateBillable([]string{"other-model"}) == nil {
		t.Fatal("expected model allowlist rejection")
	}
}

func equalUsage(left, right *TokenUsage) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}
