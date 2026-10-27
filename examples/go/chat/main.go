// Run with: go run ./examples/go/chat /tmp/tokenhive-demo-.../client.json
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"tokenhive.local/half-mpc-tls/client"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 2 {
		return errors.New("usage: chat CLIENT.json")
	}
	encoded, err := os.ReadFile(os.Args[1])
	if err != nil {
		return err
	}
	var cfg struct {
		BaseURL string `json:"base_url"`
		APIKey  string `json:"api_key"`
		CAFile  string `json:"ca_file"`
		Model   string `json:"model"`
	}
	if err := json.Unmarshal(encoded, &cfg); err != nil {
		return err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 32
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return err
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return errors.New("invalid CA PEM")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	}
	c, err := client.New(client.Config{BaseURL: cfg.BaseURL, APIKey: cfg.APIKey, HTTPClient: &http.Client{Transport: transport, Timeout: 5 * time.Minute}})
	if err != nil {
		return err
	}
	defer c.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	models, err := c.Models(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("Models: %v\n", models)
	request := client.ChatRequest{Model: cfg.Model, Messages: []client.Message{{Role: "user", Content: "Hello"}}, MaxCompletionTokens: 128}
	// Persist business operation IDs before dispatch. This example uses a new prefix per run.
	operation := fmt.Sprintf("example-%d", time.Now().UnixNano())
	completion, err := c.Chat(ctx, request, client.RequestOptions{IdempotencyKey: operation + "-json"})
	if err != nil {
		return err
	}
	fmt.Printf("Task: %s; response: %s\n", completion.TaskID, completion.Raw)
	stream, err := c.Stream(ctx, request, client.RequestOptions{IdempotencyKey: operation + "-sse"})
	if err != nil {
		return err
	}
	defer stream.Close()
	for {
		chunk, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("stream incomplete: %w", err)
		}
		for _, choice := range chunk.Choices {
			if text, ok := choice.Delta.Content.(string); ok {
				fmt.Print(text)
			}
		}
	}
	fmt.Println("\nStream completed and settled.")
	status, err := c.TaskByKey(ctx, operation+"-sse")
	if err != nil {
		return err
	}
	if status.State != "settled" {
		return fmt.Errorf("unexpected settlement state %s", status.State)
	}
	fmt.Printf("Settlement: %s %d micros\n", status.Currency, status.ChargeMicros)
	return nil
}
