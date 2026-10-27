// Load generator for the four-process acceptance fixture. Uses the public Go SDK.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/httptrace"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tokenhive.local/half-mpc-tls/client"
)

type config struct {
	BaseURL string `json:"base_url"`
	APIKey  string `json:"api_key"`
	CAFile  string `json:"ca_file"`
}
type sample struct {
	ID             int64   `json:"id"`
	StartMS        float64 `json:"start_ms"`
	ScheduleLagMS  float64 `json:"schedule_lag_ms"`
	TTFBMS         float64 `json:"ttfb_ms"`
	FirstContentMS float64 `json:"first_content_ms"`
	TotalMS        float64 `json:"total_ms"`
	MaxEventGapMS  float64 `json:"max_event_gap_ms"`
	Events         int     `json:"events"`
	Error          string  `json:"error,omitempty"`
	HTTPStatus     int     `json:"http_status,omitempty"`
	TaskID         string  `json:"task_id,omitempty"`
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
func percentiles(values []float64) map[string]float64 {
	if len(values) == 0 {
		return nil
	}
	sort.Float64s(values)
	out := map[string]float64{"min": values[0], "max": values[len(values)-1]}
	for key, p := range map[string]float64{"p50": .5, "p95": .95, "p99": .99} {
		out[key] = values[int(math.Ceil(p*float64(len(values))))-1]
	}
	return out
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	configPath := flag.String("config", "", "private client configuration")
	output := flag.String("output", "", "JSON result path")
	duration := flag.Duration("duration", 30*time.Second, "request admission window")
	concurrency := flag.Int("concurrency", 1, "workers, or maximum in-flight with -rate")
	rate := flag.Float64("rate", 0, "fixed arrivals per second; zero means closed loop")
	promptBytes := flag.Int("prompt-bytes", 1024, "ASCII prompt length")
	streaming := flag.Bool("stream", false, "consume SSE through verified DONE")
	requests := flag.Int64("requests", 0, "optional request-count cap")
	readyEach := flag.Bool("ready-each", false, "wait for readyz before each sequential request; outside timing")
	flag.Parse()
	if *duration <= 0 || *concurrency < 1 || *concurrency > 128 || *rate < 0 || *rate > 1000 || *promptBytes < 1 || *promptBytes > 5<<20 || *output == "" {
		return errors.New("invalid load settings")
	}
	if *readyEach && (*concurrency != 1 || *rate != 0) {
		return errors.New("ready-each requires a single closed-loop worker")
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		return err
	}
	var cfg config
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	roots := x509.NewCertPool()
	pem, err := os.ReadFile(cfg.CAFile)
	if err != nil {
		return err
	}
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("invalid CA")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	transport.ForceAttemptHTTP2 = false
	transport.MaxIdleConns = 256
	transport.MaxIdleConnsPerHost = *concurrency
	hc := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	sdk, err := client.New(client.Config{BaseURL: cfg.BaseURL, APIKey: cfg.APIKey, HTTPClient: hc})
	if err != nil {
		return err
	}
	defer sdk.CloseIdleConnections()
	req := client.ChatRequest{Model: "demo-model", Messages: []client.Message{{Role: "user", Content: strings.Repeat("x", *promptBytes)}}, MaxCompletionTokens: 128}
	begin := time.Now()
	end := begin.Add(*duration)
	var next atomic.Int64
	var dropped atomic.Int64
	var active atomic.Int64
	var maxActive atomic.Int64
	var mutex sync.Mutex
	var samples []sample
	execute := func(id int64, scheduled time.Time) {
		n := active.Add(1)
		defer active.Add(-1)
		for old := maxActive.Load(); n > old; old = maxActive.Load() {
			if maxActive.CompareAndSwap(old, n) {
				break
			}
		}
		start := time.Now()
		s := sample{ID: id, StartMS: ms(start.Sub(begin)), ScheduleLagMS: math.Max(0, ms(start.Sub(scheduled)))}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		var firstByte atomic.Int64
		ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotFirstResponseByte: func() { firstByte.CompareAndSwap(0, time.Since(start).Nanoseconds()) }})
		opts := client.RequestOptions{IdempotencyKey: fmt.Sprintf("load-%d-%d", begin.UnixNano(), id)}
		var callErr error
		if *streaming {
			stream, e := sdk.Stream(ctx, req, opts)
			callErr = e
			if e == nil {
				s.TaskID = stream.TaskID
				var previous time.Time
				for {
					chunk, e := stream.Recv()
					if e == io.EOF {
						break
					}
					if e != nil {
						callErr = e
						break
					}
					content := false
					for _, choice := range chunk.Choices {
						if value, ok := choice.Delta.Content.(string); ok && value != "" {
							content = true
						}
					}
					if content {
						now := time.Now()
						s.Events++
						if s.FirstContentMS == 0 {
							s.FirstContentMS = ms(now.Sub(start))
						}
						if !previous.IsZero() {
							s.MaxEventGapMS = math.Max(s.MaxEventGapMS, ms(now.Sub(previous)))
						}
						previous = now
					}
				}
				_ = stream.Close()
				if callErr == nil && s.Events != 40 {
					callErr = fmt.Errorf("expected 40 content events, got %d", s.Events)
				}
			}
		} else {
			result, e := sdk.Chat(ctx, req, opts)
			callErr = e
			if e == nil {
				s.TaskID = result.TaskID
				s.FirstContentMS = ms(time.Since(start))
				if result.Usage == nil || result.Usage.CompletionTokens != 40 {
					callErr = errors.New("unexpected fixture usage")
				}
			}
		}
		s.TotalMS = ms(time.Since(start))
		s.TTFBMS = float64(firstByte.Load()) / float64(time.Millisecond)
		if callErr != nil {
			s.Error = callErr.Error()
			var api *client.APIError
			if errors.As(callErr, &api) {
				s.HTTPStatus = api.StatusCode
			}
		} else {
			s.HTTPStatus = 200
		}
		mutex.Lock()
		samples = append(samples, s)
		mutex.Unlock()
	}
	var wg sync.WaitGroup
	if *rate == 0 {
		for range *concurrency {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for time.Now().Before(end) {
					if *readyEach {
						for time.Now().Before(end) {
							r, _ := http.NewRequest(http.MethodGet, strings.TrimSuffix(cfg.BaseURL, "/v1")+"/readyz", nil)
							r.Header.Set("Authorization", "Bearer "+cfg.APIKey)
							response, e := hc.Do(r)
							ok := false
							if e == nil {
								ok = response.StatusCode == 200
								_, _ = io.Copy(io.Discard, response.Body)
								_ = response.Body.Close()
							}
							if ok {
								break
							}
							time.Sleep(20 * time.Millisecond)
						}
						if !time.Now().Before(end) {
							return
						}
					}
					id := next.Add(1)
					if *requests > 0 && id > *requests {
						return
					}
					execute(id, time.Now())
				}
			}()
		}
	} else {
		slots := make(chan struct{}, *concurrency)
		for i := int64(0); ; i++ {
			due := begin.Add(time.Duration(float64(time.Second) * float64(i) / *rate))
			if !due.Before(end) || (*requests > 0 && i >= *requests) {
				break
			}
			if delay := time.Until(due); delay > 0 {
				time.Sleep(delay)
			}
			id := next.Add(1)
			select {
			case slots <- struct{}{}:
				wg.Add(1)
				go func() { defer wg.Done(); defer func() { <-slots }(); execute(id, due) }()
			default:
				dropped.Add(1)
			}
		}
	}
	wg.Wait()
	elapsed := time.Since(begin)
	var ttfb, first, total, gaps, lag []float64
	success := 0
	failures := map[string]int{}
	for _, s := range samples {
		lag = append(lag, s.ScheduleLagMS)
		if s.Error != "" {
			failures[s.Error]++
			continue
		}
		success++
		ttfb = append(ttfb, s.TTFBMS)
		first = append(first, s.FirstContentMS)
		total = append(total, s.TotalMS)
		if s.Events > 1 {
			gaps = append(gaps, s.MaxEventGapMS)
		}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i].ID < samples[j].ID })
	result := map[string]any{"admission_seconds": duration.Seconds(), "elapsed_seconds": elapsed.Seconds(), "concurrency": *concurrency, "rate": *rate, "prompt_bytes": *promptBytes, "stream": *streaming, "ready_each": *readyEach, "attempted": len(samples), "succeeded": success, "failed": len(samples) - success, "dropped_arrivals": dropped.Load(), "peak_inflight": maxActive.Load(), "completed_rps": float64(success) / elapsed.Seconds(), "ttfb_ms": percentiles(ttfb), "first_content_ms": percentiles(first), "total_ms": percentiles(total), "max_event_gap_ms": percentiles(gaps), "schedule_lag_ms": percentiles(lag), "errors": failures, "samples": samples}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(*output, append(encoded, '\n'), 0600)
}
