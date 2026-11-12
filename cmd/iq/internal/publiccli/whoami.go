package publiccli

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/spf13/cobra"

	"github.com/MotiveIQ/public/platform/iam/oauth"
)

func (c *Command) whoamiCommand() *cobra.Command {
	options := outputOptions{}
	command := &cobra.Command{
		Use:               "whoami",
		Short:             "Decode the stored access token locally (no network).",
		Args:              cobra.NoArgs,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := options.validate(); err != nil {
				return err
			}
			return c.runWhoami(options)
		},
	}
	c.addOutputFlags(command, &options)
	return command
}

func (c *Command) runWhoami(options outputOptions) error {
	credentials, err := c.LoadCredentials()
	if err != nil {
		return err
	}
	if credentials == nil {
		return errors.New("not logged in; run iq login")
	}
	accessToken, _ := credentials["access_token"].(string)
	info, ok := oauth.DecodeTokenInfo(accessToken)
	if !ok {
		return errors.New("stored access token is not a decodable JWT; run iq login")
	}
	payload, err := json.Marshal(struct {
		Subject   string   `json:"subject"`
		Audiences []string `json:"audiences"`
		Scopes    []string `json:"scopes"`
		ExpiresAt int64    `json:"expires_at"`
	}{
		Subject:   info.Subject,
		Audiences: info.Audiences,
		Scopes:    info.Scopes,
		ExpiresAt: info.ExpiresAt,
	})
	if err != nil {
		return err
	}
	return c.printOutput(options, "whoami", payload, func() iamView { return iamTokenInfoView(info) })
}

// iamTokenInfoView names its fields after the json keys, and orders them
// the same way, so the three formats describe one record.
func iamTokenInfoView(info oauth.TokenInfo) iamView {
	return iamObjectView([]iamField{
		{"subject", info.Subject},
		{"audiences", strings.Join(info.Audiences, " ")},
		{"scopes", strings.Join(info.Scopes, " ")},
		{"expires_at", oauth.FormatTimestamp(info.ExpiresAt)},
	})
}
