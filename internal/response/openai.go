package response

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	maxOpenAIJSONBytes = DefaultMaxBodyBytes
	maxJSONDepth       = 64
	maxTokenCount      = int64(1_000_000_000)
)

var ErrInvalidOpenAIResponse = errors.New("invalid OpenAI response metadata")

type TokenUsage struct {
	InputTokens  int64
	OutputTokens int64
	TotalTokens  int64
}

type OpenAIResult struct {
	ID    string
	Model string
	Usage *TokenUsage
}

type OpenAIAccumulator struct {
	result OpenAIResult
	done   bool
}

func IsSSEDone(data string) bool {
	return strings.TrimSpace(data) == "[DONE]"
}

func ExtractOpenAIResult(data []byte) (OpenAIResult, error) {
	if len(data) == 0 || len(data) > maxOpenAIJSONBytes || IsSSEDone(string(data)) {
		return OpenAIResult{}, ErrInvalidOpenAIResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeUniqueJSON(decoder, 0)
	if err != nil {
		return OpenAIResult{}, ErrInvalidOpenAIResponse
	}
	if _, err := decoder.Token(); err != io.EOF {
		return OpenAIResult{}, ErrInvalidOpenAIResponse
	}
	root, ok := value.(map[string]any)
	if !ok {
		return OpenAIResult{}, ErrInvalidOpenAIResponse
	}

	result := OpenAIResult{}
	if result.ID, err = optionalBoundedString(root, "id", 256); err != nil {
		return OpenAIResult{}, err
	}
	if result.Model, err = optionalBoundedString(root, "model", 256); err != nil {
		return OpenAIResult{}, err
	}
	usageValue, exists := root["usage"]
	if !exists || usageValue == nil {
		return result, nil
	}
	usageObject, ok := usageValue.(map[string]any)
	if !ok {
		return OpenAIResult{}, ErrInvalidOpenAIResponse
	}
	usage, err := parseTokenUsage(usageObject)
	if err != nil {
		return OpenAIResult{}, err
	}
	result.Usage = &usage
	return result, nil
}

func (r OpenAIResult) ValidateBillable(allowedModels []string) error {
	if r.ID == "" || r.Model == "" || r.Usage == nil || len(allowedModels) == 0 {
		return ErrInvalidOpenAIResponse
	}
	for _, allowed := range allowedModels {
		if r.Model == allowed {
			return nil
		}
	}
	return ErrInvalidOpenAIResponse
}

func (a *OpenAIAccumulator) ObserveSSEData(data string) (bool, error) {
	if a == nil || a.done {
		return false, ErrInvalidOpenAIResponse
	}
	if IsSSEDone(data) {
		a.done = true
		return true, nil
	}
	chunk, err := ExtractOpenAIResult([]byte(data))
	if err != nil {
		return false, err
	}
	if err := mergeStableString(&a.result.ID, chunk.ID); err != nil {
		return false, err
	}
	if err := mergeStableString(&a.result.Model, chunk.Model); err != nil {
		return false, err
	}
	if chunk.Usage != nil {
		if a.result.Usage != nil && *a.result.Usage != *chunk.Usage {
			return false, ErrInvalidOpenAIResponse
		}
		usage := *chunk.Usage
		a.result.Usage = &usage
	}
	return false, nil
}

func (a *OpenAIAccumulator) Finalize(allowedModels []string) (OpenAIResult, error) {
	if a == nil || !a.done {
		return OpenAIResult{}, ErrInvalidOpenAIResponse
	}
	if err := a.result.ValidateBillable(allowedModels); err != nil {
		return OpenAIResult{}, err
	}
	result := a.result
	usage := *a.result.Usage
	result.Usage = &usage
	return result, nil
}

func mergeStableString(current *string, next string) error {
	if next == "" {
		return nil
	}
	if *current != "" && *current != next {
		return ErrInvalidOpenAIResponse
	}
	*current = next
	return nil
}

func parseTokenUsage(object map[string]any) (TokenUsage, error) {
	input, err := alternativeTokenCount(object, "input_tokens", "prompt_tokens")
	if err != nil {
		return TokenUsage{}, err
	}
	output, err := alternativeTokenCount(object, "output_tokens", "completion_tokens")
	if err != nil {
		return TokenUsage{}, err
	}
	total, err := requiredTokenCount(object, "total_tokens")
	if err != nil {
		return TokenUsage{}, err
	}
	if input > maxTokenCount-output || input+output != total {
		return TokenUsage{}, ErrInvalidOpenAIResponse
	}
	return TokenUsage{InputTokens: input, OutputTokens: output, TotalTokens: total}, nil
}

func alternativeTokenCount(object map[string]any, primary, legacy string) (int64, error) {
	_, hasPrimary := object[primary]
	_, hasLegacy := object[legacy]
	if hasPrimary == hasLegacy {
		return 0, ErrInvalidOpenAIResponse
	}
	if hasPrimary {
		return requiredTokenCount(object, primary)
	}
	return requiredTokenCount(object, legacy)
}

func requiredTokenCount(object map[string]any, name string) (int64, error) {
	number, ok := object[name].(json.Number)
	if !ok {
		return 0, ErrInvalidOpenAIResponse
	}
	value, err := number.Int64()
	if err != nil || value < 0 || value > maxTokenCount {
		return 0, ErrInvalidOpenAIResponse
	}
	return value, nil
}

func optionalBoundedString(object map[string]any, name string, maxLength int) (string, error) {
	value, exists := object[name]
	if !exists || value == nil {
		return "", nil
	}
	text, ok := value.(string)
	if !ok || len(text) == 0 || len(text) > maxLength {
		return "", ErrInvalidOpenAIResponse
	}
	for _, character := range []byte(text) {
		if character < 0x20 || character > 0x7e {
			return "", ErrInvalidOpenAIResponse
		}
	}
	return text, nil
}

func decodeUniqueJSON(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, fmt.Errorf("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("JSON object key is not a string")
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("duplicate JSON object key")
			}
			value, err := decodeUniqueJSON(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, fmt.Errorf("JSON object is not terminated")
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			value, err := decodeUniqueJSON(decoder, depth+1)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, fmt.Errorf("JSON array is not terminated")
		}
		return array, nil
	default:
		return nil, fmt.Errorf("unexpected JSON delimiter")
	}
}
