// Command profilehub runs the same public embedded Hub with a private CPU profile.
// It is a local diagnostic harness; no profiling HTTP endpoint is exposed.
package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"

	"tokenhive.local/half-mpc-tls/hub"
)

func run() error {
	if len(os.Args) != 3 {
		return errors.New("usage: profilehub CONFIG.json CPU.pprof")
	}
	profile, err := os.OpenFile(os.Args[2], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer profile.Close()
	if err = pprof.StartCPUProfile(profile); err != nil {
		return err
	}
	defer pprof.StopCPUProfile()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = hub.RunFile(ctx, os.Args[1])
	if errors.Is(err, context.Canceled) || errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
