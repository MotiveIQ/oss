package main

import (
	"context"
	"os"
	"os/signal"

	"go.motiveiq.dev/cmd/iq/internal/publiccli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := publiccli.NewCommand().Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
