package publiccli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/MotiveIQ/public/platform/iam/oauth"
)

func (c *Command) loginCommand() *cobra.Command {
	return &cobra.Command{
		Use:               "login",
		Short:             "Log in locally for MotiveIQ developer services.",
		Args:              cobra.NoArgs,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return c.runLogin(cmd.Context())
		},
	}
}

func (c *Command) runLogin(ctx context.Context) error {
	credentials, err := c.Login(ctx, c.Stdout)
	if err != nil {
		return err
	}
	if refreshToken, _ := credentials["refresh_token"].(string); refreshToken == "" {
		return errors.New("OAuth login did not return a refresh token; ensure offline_access is granted")
	}

	destination, err := c.SaveCredentials(credentials)
	if err != nil {
		return err
	}

	fmt.Fprintf(c.Stdout, "login: saved credentials to %s\n", destination)
	fmt.Fprintf(c.Stdout, "access token expires: %s\n", oauth.FormatTimestamp(credentials["expires_at"]))
	fmt.Fprintf(c.Stdout, "refresh token expires: %s\n", oauth.FormatTimestamp(credentials["refresh_expires_at"]))
	if c.LoginHint != "" {
		fmt.Fprintln(c.Stdout, c.LoginHint)
	}
	return nil
}
