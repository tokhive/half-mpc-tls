// Package gateway turns authenticated upstream responses into constrained
// Consumer-facing OpenAI responses and settlement receipts.
package gateway

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	authresponse "tokenhive.local/half-mpc-tls/internal/response"
)

var (
	ErrInvalidRelayConfig = errors.New("invalid authenticated response relay configuration")
	ErrResponseRejected   = errors.New("authenticated upstream response rejected")
	ErrReceiptCommit      = errors.New("settlement receipt commit failed")
	ErrDownstreamWrite    = errors.New("consumer response write failed")
)

// RelayConfig is immutable task metadata established before the upstream
// request is encrypted. AllowedResponseModels should be a policy snapshot for
// the requested model, including any permitted version-pinned model IDs.
type RelayConfig struct {
	TaskID                string
	ProviderID            string
	RequestHash           string
	RequestedModel        string
	Streaming             bool
	AllowedResponseModels []string
}

// Receipt is emitted only after the authenticated response body has reached a
// clean EOF. Billable is false for authenticated non-2xx upstream responses.
type Receipt struct {
	TaskID             string                  `json:"task_id"`
	ProviderID         string                  `json:"provider_id"`
	RequestHash        string                  `json:"request_hash"`
	ResponseHash       string                  `json:"response_hash"`
	RequestedModel     string                  `json:"requested_model"`
	ResponseModel      string                  `json:"response_model,omitempty"`
	UpstreamRequestID  string                  `json:"upstream_request_id,omitempty"`
	UpstreamResponseID string                  `json:"upstream_response_id,omitempty"`
	StatusCode         int                     `json:"status_code"`
	Streaming          bool                    `json:"streaming"`
	BodyBytes          int64                   `json:"body_bytes"`
	Usage              authresponse.TokenUsage `json:"usage"`
	Billable           bool                    `json:"billable"`
}

// ReceiptSink must durably and idempotently store a receipt before returning.
// TaskID is the idempotency key.
type ReceiptSink interface {
	RecordReceipt(Receipt) error
}

// RelayOpenAI validates and relays one authenticated OpenAI response. A nil
// error and Billable=true is the sole success condition for token settlement.
func RelayOpenAI(writer http.ResponseWriter, upstream *authresponse.Response, config RelayConfig, sink ReceiptSink) (Receipt, error) {
	if writer == nil || upstream == nil || upstream.Response == nil || upstream.Body == nil || sink == nil || !validConfig(config) {
		return Receipt{}, ErrInvalidRelayConfig
	}
	defer upstream.Body.Close()

	if upstream.StatusCode < http.StatusOK || upstream.StatusCode >= http.StatusMultipleChoices {
		return relayNonBillable(writer, upstream, config, sink)
	}
	if upstream.Metadata.SSE != config.Streaming {
		return Receipt{}, fmt.Errorf("%w: response type does not match hashed request", ErrResponseRejected)
	}
	if config.Streaming {
		return relaySSE(writer, upstream, config, sink)
	}
	return relayJSON(writer, upstream, config, sink)
}

func relayNonBillable(writer http.ResponseWriter, upstream *authresponse.Response, config RelayConfig, sink ReceiptSink) (Receipt, error) {
	body, outcome, err := readComplete(upstream)
	if err != nil {
		return Receipt{}, err
	}
	receipt := baseReceipt(upstream, config, outcome)
	if err := commitReceipt(sink, receipt); err != nil {
		return receipt, err
	}
	copyResponseHeaders(writer.Header(), upstream, false)
	writer.WriteHeader(upstream.StatusCode)
	if _, err := writer.Write(body); err != nil {
		return receipt, fmt.Errorf("%w: %v", ErrDownstreamWrite, err)
	}
	return receipt, nil
}

func relayJSON(writer http.ResponseWriter, upstream *authresponse.Response, config RelayConfig, sink ReceiptSink) (Receipt, error) {
	if upstream.Metadata.MediaType != "application/json" {
		return Receipt{}, fmt.Errorf("%w: successful non-stream response is not JSON", ErrResponseRejected)
	}
	body, outcome, err := readComplete(upstream)
	if err != nil {
		return Receipt{}, err
	}
	result, err := authresponse.ExtractOpenAIResult(body)
	if err != nil || result.ValidateBillable(config.AllowedResponseModels) != nil {
		return Receipt{}, fmt.Errorf("%w: invalid billable JSON response", ErrResponseRejected)
	}

	receipt := billableReceipt(upstream, config, outcome, result)
	if err := commitReceipt(sink, receipt); err != nil {
		return receipt, err
	}
	copyResponseHeaders(writer.Header(), upstream, false)
	writer.WriteHeader(upstream.StatusCode)
	if _, err := writer.Write(body); err != nil {
		return receipt, fmt.Errorf("%w: %v", ErrDownstreamWrite, err)
	}
	return receipt, nil
}

func relaySSE(writer http.ResponseWriter, upstream *authresponse.Response, config RelayConfig, sink ReceiptSink) (Receipt, error) {
	flusher, ok := writer.(http.Flusher)
	if !ok {
		return Receipt{}, fmt.Errorf("%w: downstream does not support streaming", ErrInvalidRelayConfig)
	}
	decoder := authresponse.NewSSEDecoder(upstream.Body)
	var accumulator authresponse.OpenAIAccumulator
	wroteHeaders := false
	sawAllowedModel := false
	var downstreamErr error

	for {
		event, err := decoder.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Receipt{}, fmt.Errorf("%w: invalid SSE event stream", ErrResponseRejected)
		}
		if event.Event != "message" {
			return Receipt{}, fmt.Errorf("%w: unsupported SSE event type", ErrResponseRejected)
		}
		done := authresponse.IsSSEDone(event.Data)
		if !done {
			chunk, err := authresponse.ExtractOpenAIResult([]byte(event.Data))
			if err != nil {
				return Receipt{}, fmt.Errorf("%w: invalid SSE JSON", ErrResponseRejected)
			}
			if chunk.Model != "" {
				if !allowedModel(chunk.Model, config.AllowedResponseModels) {
					return Receipt{}, fmt.Errorf("%w: SSE model is not allowed", ErrResponseRejected)
				}
				sawAllowedModel = true
			}
			if !sawAllowedModel {
				return Receipt{}, fmt.Errorf("%w: SSE emitted data before an allowed model", ErrResponseRejected)
			}
		}
		observedDone, err := accumulator.ObserveSSEData(event.Data)
		if err != nil || observedDone != done {
			return Receipt{}, fmt.Errorf("%w: inconsistent SSE result metadata", ErrResponseRejected)
		}
		if done {
			continue
		}
		if !wroteHeaders && downstreamErr == nil {
			copyResponseHeaders(writer.Header(), upstream, true)
			writer.WriteHeader(upstream.StatusCode)
			wroteHeaders = true
		}
		if downstreamErr != nil {
			continue
		}
		if _, err := writer.Write(encodeSSEEvent(event)); err != nil {
			downstreamErr = err
			continue
		}
		flusher.Flush()
	}

	outcome := upstream.Outcome()
	if outcome.State != authresponse.StateComplete || outcome.BodySHA256 == "" {
		return Receipt{}, fmt.Errorf("%w: authenticated SSE body did not complete", ErrResponseRejected)
	}
	result, err := accumulator.Finalize(config.AllowedResponseModels)
	if err != nil {
		return Receipt{}, fmt.Errorf("%w: incomplete billable SSE response", ErrResponseRejected)
	}
	receipt := billableReceipt(upstream, config, outcome, result)
	if err := commitReceipt(sink, receipt); err != nil {
		if downstreamErr != nil {
			return receipt, errors.Join(err, fmt.Errorf("%w: %v", ErrDownstreamWrite, downstreamErr))
		}
		return receipt, err
	}
	if downstreamErr != nil {
		return receipt, fmt.Errorf("%w: %v", ErrDownstreamWrite, downstreamErr)
	}
	if !wroteHeaders {
		copyResponseHeaders(writer.Header(), upstream, true)
		writer.WriteHeader(upstream.StatusCode)
	}
	if _, err := writer.Write([]byte("data: [DONE]\n\n")); err != nil {
		return receipt, fmt.Errorf("%w: %v", ErrDownstreamWrite, err)
	}
	flusher.Flush()
	return receipt, nil
}

func commitReceipt(sink ReceiptSink, receipt Receipt) error {
	if err := sink.RecordReceipt(receipt); err != nil {
		return fmt.Errorf("%w: %v", ErrReceiptCommit, err)
	}
	return nil
}

func readComplete(upstream *authresponse.Response) ([]byte, authresponse.Outcome, error) {
	body, err := io.ReadAll(upstream.Body)
	if err != nil {
		return nil, upstream.Outcome(), fmt.Errorf("%w: authenticated body read failed", ErrResponseRejected)
	}
	outcome := upstream.Outcome()
	if outcome.State != authresponse.StateComplete || outcome.BodySHA256 == "" || outcome.BodyBytes != int64(len(body)) {
		return nil, outcome, fmt.Errorf("%w: authenticated body did not complete", ErrResponseRejected)
	}
	return body, outcome, nil
}

func copyResponseHeaders(destination http.Header, upstream *authresponse.Response, streaming bool) {
	contentType := upstream.Header.Get("Content-Type")
	if contentType != "" {
		destination.Set("Content-Type", contentType)
	}
	if upstream.Metadata.RequestID != "" {
		destination.Set("X-Request-Id", upstream.Metadata.RequestID)
	}
	if streaming {
		destination.Set("Cache-Control", "no-cache")
	}
}

func encodeSSEEvent(event authresponse.SSEEvent) []byte {
	var output strings.Builder
	if event.Event != "" && event.Event != "message" {
		output.WriteString("event: ")
		output.WriteString(event.Event)
		output.WriteByte('\n')
	}
	if event.ID != "" {
		output.WriteString("id: ")
		output.WriteString(event.ID)
		output.WriteByte('\n')
	}
	if event.RetryMillis != nil {
		output.WriteString("retry: ")
		output.WriteString(strconv.FormatInt(*event.RetryMillis, 10))
		output.WriteByte('\n')
	}
	for _, line := range strings.Split(event.Data, "\n") {
		output.WriteString("data: ")
		output.WriteString(line)
		output.WriteByte('\n')
	}
	output.WriteByte('\n')
	return []byte(output.String())
}

func baseReceipt(upstream *authresponse.Response, config RelayConfig, outcome authresponse.Outcome) Receipt {
	return Receipt{
		TaskID:            config.TaskID,
		ProviderID:        config.ProviderID,
		RequestHash:       config.RequestHash,
		ResponseHash:      outcome.BodySHA256,
		RequestedModel:    config.RequestedModel,
		UpstreamRequestID: upstream.Metadata.RequestID,
		StatusCode:        upstream.StatusCode,
		Streaming:         config.Streaming,
		BodyBytes:         outcome.BodyBytes,
	}
}

func billableReceipt(upstream *authresponse.Response, config RelayConfig, outcome authresponse.Outcome, result authresponse.OpenAIResult) Receipt {
	receipt := baseReceipt(upstream, config, outcome)
	receipt.ResponseModel = result.Model
	receipt.UpstreamResponseID = result.ID
	receipt.Usage = *result.Usage
	receipt.Billable = true
	return receipt
}

func validConfig(config RelayConfig) bool {
	if !validIdentifier(config.TaskID, 128) || !validIdentifier(config.ProviderID, 128) ||
		!validHash(config.RequestHash) || !validModel(config.RequestedModel) ||
		len(config.AllowedResponseModels) == 0 || len(config.AllowedResponseModels) > 32 {
		return false
	}
	seen := make(map[string]struct{}, len(config.AllowedResponseModels))
	for _, model := range config.AllowedResponseModels {
		if !validModel(model) {
			return false
		}
		if _, exists := seen[model]; exists {
			return false
		}
		seen[model] = struct{}{}
	}
	return true
}

func allowedModel(model string, allowed []string) bool {
	for _, candidate := range allowed {
		if model == candidate {
			return true
		}
	}
	return false
}

func validIdentifier(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, character := range []byte(value) {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_') {
			return false
		}
	}
	return true
}

func validHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range []byte(value) {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func validModel(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, character := range []byte(value) {
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("-._:/", rune(character))) {
			return false
		}
	}
	return true
}
