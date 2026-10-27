// The same public package can be started from an existing application's goroutine.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"tokenhive.local/half-mpc-tls/hub"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: embedded HUB.json")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := hub.RunFile(ctx, os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
