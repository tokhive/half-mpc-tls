//go:build integration

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestGoClientTalksToRustSidecarProcess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix sidecar sockets are not available on Windows")
	}
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	rustRoot := filepath.Join(repositoryRoot, "rust")
	build := exec.Command("cargo", "build", "-p", "tokenhive-sidecar")
	build.Dir = rustRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Rust sidecar: %v\n%s", err, output)
	}

	for _, version := range []string{TLS12, TLS13} {
		t.Run(version, func(t *testing.T) { testRustSidecarVersion(t, rustRoot, version) })
	}
}

func testRustSidecarVersion(t *testing.T, rustRoot, version string) {
	socketDirectory := t.TempDir()
	if err := os.Chmod(socketDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(socketDirectory, "hub.sock")
	binary := filepath.Join(rustRoot, "target", "debug", "tokenhive-sidecar")
	args := []string{"--role", "hub", "--socket", socket}
	// Omit the flag for the legacy case to verify the compatibility default.
	if version != TLS12 {
		args = append(args, "--tls-version", version)
	}
	process := exec.Command(binary, args...)
	process.Stderr = os.Stderr
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = process.Process.Signal(os.Interrupt)
		_ = process.Wait()
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := os.Stat(socket)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) || time.Now().After(deadline) {
			t.Fatalf("wait for sidecar socket: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, capabilities, err := DialRPC(ctx, socket, RoleHub)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	if capabilities.Role != RoleHub || len(capabilities.TLSVersions) != 1 || capabilities.TLSVersions[0] != version {
		t.Fatalf("unexpected capabilities: %+v", capabilities)
	}

	params := json.RawMessage(`{"upstream_policy":{"host":"api.example.com","port":443,"server_name":"api.example.com"}}`)
	if err := client.WriteCommand(101, RPCCommand{
		RequestID: 1,
		Operation: OperationCreateSession,
		Params:    params,
	}); err != nil {
		t.Fatal(err)
	}
	result, err := client.ReadResult(101, 1)
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != RPCStatusOK {
		t.Fatalf("unexpected create result: %+v", result)
	}
	var created struct {
		State           string `json:"state"`
		AttachmentToken string `json:"attachment_token"`
	}
	if err := decodeStrictJSON(result.Data, &created); err != nil {
		t.Fatal(err)
	}
	if created.State != "created" || len(created.AttachmentToken) != 64 {
		t.Fatalf("unexpected create data: %+v", created)
	}
	wrongTokenPrefix := "0"
	if created.AttachmentToken[0] == '0' {
		wrongTokenPrefix = "1"
	}
	_, err = DialAttachment(
		ctx,
		socket,
		RoleHub,
		101,
		1,
		OperationAttachMPCChannel,
		wrongTokenPrefix+created.AttachmentToken[1:],
	)
	var remoteError *RPCRemoteError
	if !errors.As(err, &remoteError) || remoteError.Code != "attachment_rejected" {
		t.Fatalf("expected attachment rejection, got %v", err)
	}
	attachment, err := DialAttachment(
		ctx,
		socket,
		RoleHub,
		101,
		1,
		OperationAttachMPCChannel,
		created.AttachmentToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x5a}, 256<<10)
	if written, err := attachment.Write(payload); err != nil || written != len(payload) {
		t.Fatalf("write attachment: written=%d err=%v", written, err)
	}
	if err := attachment.Close(); err != nil {
		t.Fatal(err)
	}

	if err := process.Process.Signal(syscall.SIGINT); err != nil {
		t.Fatal(err)
	}
}
