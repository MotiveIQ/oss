package publiccli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"
	sdkconfig "go.motiveiq.dev/platform/iam/sdk/config"
)

func (c *Command) loginCommand() *cobra.Command {
	return &cobra.Command{
		Use: "login", Short: "Authenticate the selected profile's interactive identity source.",
		Args: cobra.NoArgs, ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error { return c.Login(cmd.Context(), c.Stdout) },
	}
}

func (c *Command) login(ctx context.Context, output io.Writer) error {
	identity, err := c.ResolveIdentity("")
	if err != nil {
		return err
	}
	interactive, ok := identity.Provider.(sdkconfig.InteractiveSource)
	if !ok {
		return fmt.Errorf("selected web identity source does not support interactive login; authenticate with its provider")
	}
	return interactive.Login(ctx, output)
}
