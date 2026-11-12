package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/MotiveIQ/public/cmd/iq/internal/publiccli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := publiccli.NewCommand().Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
