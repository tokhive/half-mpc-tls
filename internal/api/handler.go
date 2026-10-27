// Package api exposes the bounded OpenAI-compatible Consumer HTTP surface.
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
	"time"

	"tokenhive.local/half-mpc-tls/internal/canonical"
	"tokenhive.local/half-mpc-tls/internal/coordinator"
	"tokenhive.local/half-mpc-tls/internal/precompute"
	"tokenhive.local/half-mpc-tls/internal/settlement"
)

const ChatCompletionsPath = "/v1/chat/completions"

var errBodyTooLarge = errors.New("request body exceeds MPC capacity")

type Executor interface {
	Execute(context.Context, http.ResponseWriter, string, string, json.RawMessage) error
}

// ServiceInfo supplies public model names and an instantaneous readiness check.
type ServiceInfo interface {
	Models() []string
	Ready() bool
}

type TaskReader interface {
	Task(string, string) (settlement.TaskStatus, bool, error)
}

type Config struct {
	Tasks           TaskReader
	Info            ServiceInfo
	BodyReadTimeout time.Duration
	Keys            *APIKeys
	Limiter         *Limiter
	Executor        Executor
	RequestTimeout  time.Duration
	MaxBodyBytes    int64
}

type Handler struct {
	tasks           TaskReader
	info            ServiceInfo
	bodyReadTimeout time.Duration
	keys            *APIKeys
	limiter         *Limiter
	executor        Executor
	requestTimeout  time.Duration
	maxBodyBytes    int64
}

func NewHandler(config Config) (*Handler, error) {
	if config.Keys == nil || config.Limiter == nil || config.Executor == nil || config.RequestTimeout <= 0 {
		return nil, errors.New("invalid API handler configuration")
	}
	if config.MaxBodyBytes == 0 {
		config.MaxBodyBytes = canonical.MaxRequestLength
	}
	if config.MaxBodyBytes < 1 || config.MaxBodyBytes > canonical.MaxRequestLength {
		return nil, errors.New("API body limit exceeds the negotiated MPC capacity")
	}
	if config.BodyReadTimeout == 0 {
		config.BodyReadTimeout = 30 * time.Second
	}
	if config.BodyReadTimeout < 0 {
		return nil, errors.New("invalid body read timeout")
	}
	return &Handler{
		info: config.Info, bodyReadTimeout: config.BodyReadTimeout,
		tasks: config.Tasks, keys: config.Keys, limiter: config.Limiter, executor: config.Executor,
		requestTimeout: config.RequestTimeout, maxBodyBytes: config.MaxBodyBytes,
	}, nil
}

func (h *Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	setSecurityHeaders(writer.Header())
	switch {
	case request.URL.Path == "/healthz":
		if !requireMethod(writer, request, http.MethodGet) {
			return
		}
		writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
		return
	case request.URL.Path == ChatCompletionsPath:
		if !requireMethod(writer, request, http.MethodPost) {
			return
		}
	case request.URL.Path == "/v1/models", request.URL.Path == "/readyz", strings.HasPrefix(request.URL.Path, "/v1/tasks/"):
		if !requireMethod(writer, request, http.MethodGet) {
			return
		}
	default:
		writeError(writer, http.StatusNotFound, "not_found", "endpoint not found")
		return
	}
	consumerID, ok := h.keys.Authenticate(request.Header.Get("Authorization"))
	if !ok {
		writer.Header().Set("WWW-Authenticate", `Bearer realm="tokenhive"`)
		writeError(writer, http.StatusUnauthorized, "invalid_api_key", "invalid TokenHive API key")
		return
	}
	if strings.HasPrefix(request.URL.Path, "/v1/tasks/") {
		id := strings.TrimPrefix(request.URL.Path, "/v1/tasks/")
		if key, ok := strings.CutPrefix(id, "by-key/"); ok {
			if !validID(key) {
				writeError(writer, 404, "not_found", "task not found")
				return
			}
			id = scopedTaskID(consumerID, key)
		}
		if !validID(id) || h.tasks == nil {
			writeError(writer, 404, "not_found", "task not found")
			return
		}
		status, exists, err := h.tasks.Task(consumerID, id)
		if err != nil {
			writeError(writer, 503, "ledger_unavailable", "task state temporarily unavailable")
			return
		}
		if !exists {
			writeError(writer, 404, "not_found", "task not found")
			return
		}
		writeJSON(writer, 200, status)
		return
	}
	if request.URL.Path == "/readyz" {
		if h.info == nil || !h.info.Ready() {
			writer.Header().Set("Retry-After", "1")
			writeJSON(writer, http.StatusServiceUnavailable, map[string]string{"status": "warming"})
		} else {
			writeJSON(writer, http.StatusOK, map[string]string{"status": "ready"})
		}
		return
	}
	if request.URL.Path == "/v1/models" {
		models := []string{}
		if h.info != nil {
			models = append(models, h.info.Models()...)
		}
		sort.Strings(models)
		data := make([]map[string]any, 0, len(models))
		for _, model := range models {
			data = append(data, map[string]any{"id": model, "object": "model", "created": 0, "owned_by": "tokenhive"})
		}
		writeJSON(writer, http.StatusOK, map[string]any{"object": "list", "data": data})
		return
	}
	if !isJSON(request.Header.Get("Content-Type")) {
		writeError(writer, http.StatusUnsupportedMediaType, "invalid_content_type", "Content-Type must be application/json")
		return
	}
	release, ok := h.limiter.Acquire(consumerID)
	if !ok {
		writer.Header().Set("Retry-After", "1")
		writeError(writer, http.StatusTooManyRequests, "rate_limit_exceeded", "request rate or concurrency limit exceeded")
		return
	}
	defer release()

	// Bound slow uploads separately; clear the read deadline before long SSE.
	controller := http.NewResponseController(writer)
	_ = controller.SetReadDeadline(time.Now().Add(h.bodyReadTimeout))
	body, err := readBody(writer, request, h.maxBodyBytes)
	_ = controller.SetReadDeadline(time.Time{})
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errBodyTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writeError(writer, status, "invalid_request", err.Error())
		return
	}
	body, err = canonical.NormalizeOpenAIChatCompletions(body)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "invalid chat completion JSON")
		return
	}
	if int64(len(body)) > h.maxBodyBytes {
		writeError(writer, http.StatusRequestEntityTooLarge, "invalid_request", errBodyTooLarge.Error())
		return
	}
	taskID := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if taskID == "" {
		taskID, err = randomTaskID()
		if err != nil {
			writeError(writer, http.StatusInternalServerError, "internal_error", "could not allocate task")
			return
		}
	} else if !validID(taskID) {
		writeError(writer, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key has an invalid format")
		return
	}
	// Namespace all client keys by the authenticated account, including across
	// API key rotation. Neither a raw client key nor another account can collide.
	taskID = scopedTaskID(consumerID, taskID)
	writer.Header().Set("X-TokenHive-Task-Id", taskID)
	writer.Header().Set("X-Request-Id", taskID)
	ctx, cancel := context.WithTimeout(request.Context(), h.requestTimeout)
	defer cancel()
	tracked := &trackingWriter{ResponseWriter: writer}
	var downstream http.ResponseWriter = tracked
	if flusher, ok := writer.(http.Flusher); ok {
		downstream = &flushTrackingWriter{trackingWriter: tracked, flusher: flusher}
	}
	err = h.executor.Execute(ctx, downstream, consumerID, taskID, body)
	if err == nil || tracked.wroteHeader {
		return
	}
	status, code, message := mapError(err)
	if status == http.StatusServiceUnavailable {
		writer.Header().Set("Retry-After", "1")
	}
	writeError(writer, status, code, message)
}

type trackingWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *trackingWriter) WriteHeader(status int) {
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *trackingWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

type flushTrackingWriter struct {
	*trackingWriter
	flusher http.Flusher
}

func (w *flushTrackingWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	w.flusher.Flush()
}

func readBody(writer http.ResponseWriter, request *http.Request, limit int64) ([]byte, error) {
	defer request.Body.Close()
	reader := http.MaxBytesReader(writer, request.Body, limit)
	body, err := io.ReadAll(reader)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, errBodyTooLarge
		}
		return nil, errors.New("could not read request body")
	}
	if len(body) == 0 {
		return nil, errors.New("request body is required")
	}
	return body, nil
}

func isJSON(value string) bool {
	mediaType, params, err := mime.ParseMediaType(value)
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		return false
	}
	for key, value := range params {
		if !strings.EqualFold(key, "charset") || !strings.EqualFold(value, "utf-8") {
			return false
		}
	}
	return true
}

func randomTaskID() (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return "task-" + hex.EncodeToString(entropy[:]), nil
}

func mapError(err error) (int, string, string) {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "request_timeout", "request timed out"
	case errors.Is(err, precompute.ErrQueueFull):
		return http.StatusServiceUnavailable, "queue_full", "Provider wait queue is full"
	case errors.Is(err, precompute.ErrWaitTimeout):
		return http.StatusServiceUnavailable, "queue_timeout", "Provider queue wait timed out"
	case errors.Is(err, coordinator.ErrInvalidRequest):
		return http.StatusBadRequest, "invalid_request", "request is invalid"
	case errors.Is(err, coordinator.ErrTaskReplay):
		return http.StatusConflict, "idempotency_conflict", "task was already admitted"
	case errors.Is(err, settlement.ErrTaskConflict), errors.Is(err, settlement.ErrLedgerStateConflict):
		return http.StatusConflict, "idempotency_conflict", "task conflicts with existing state"
	case errors.Is(err, settlement.ErrInsufficientFunds):
		return http.StatusPaymentRequired, "insufficient_balance", "insufficient TokenHive balance"
	case errors.Is(err, coordinator.ErrNoProvider), errors.Is(err, coordinator.ErrSessionUnavailable):
		return http.StatusServiceUnavailable, "provider_unavailable", "no Provider capacity is currently available"
	case errors.Is(err, coordinator.ErrProtocolFailure):
		return http.StatusBadGateway, "upstream_verification_failed", "upstream response verification failed"
	default:
		return http.StatusInternalServerError, "internal_error", "request could not be completed"
	}
}

func writeError(writer http.ResponseWriter, status int, code, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"error": map[string]string{"message": message, "type": code, "code": code},
	})
}

func setSecurityHeaders(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
}

func scopedTaskID(consumerID, key string) string {
	digest := sha256.Sum256([]byte("tokenhive-task-v1\x00" + consumerID + "\x00" + key))
	return "task-" + hex.EncodeToString(digest[:])
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not supported")
	return false
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
