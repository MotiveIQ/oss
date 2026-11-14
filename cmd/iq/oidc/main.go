package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"go.motiveiq.dev/cmd/iq/internal/oidc"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := oidc.Run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "iq-oidc: %v\n", err)
		os.Exit(1)
	}
}
