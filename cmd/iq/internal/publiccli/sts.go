package publiccli

import (
	"context"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"

	iamv1 "go.motiveiq.dev/platform/iam/api/v1"
)

func (c *Command) stsCommand() *cobra.Command {
	options := iamOptions{Role: IAMHumanRoleURN}
	command := &cobra.Command{
		Use:           "sts",
		Short:         "Inspect MotiveIQ STS assumed-role sessions.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_ = cmd.Help()
			return errUsage
		},
	}
	c.addIAMFlags(command, &options)
	command.AddCommand(c.stsGetCallerIdentityCommand(&options))
	return command
}

func (c *Command) stsGetCallerIdentityCommand(options *iamOptions) *cobra.Command {
	command := &cobra.Command{
		Use:               "get-caller-identity",
		Short:             "Show the assumed-role session as STS sees it.",
		Args:              cobra.NoArgs,
		ValidArgsFunction: cobra.NoFileCompletions,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := options.validate(); err != nil {
				return err
			}
			return c.runGetCallerIdentity(cmd.Context(), *options)
		},
	}
	return command
}

func (c *Command) runGetCallerIdentity(ctx context.Context, options iamOptions) error {
	config, err := c.LoadSDKConfig(ctx, options.Role)
	if err != nil {
		return err
	}
	defer config.Close()
	client, err := c.NewSTSFromConfig(config)
	if err != nil {
		return err
	}
	response, err := client.GetCallerIdentity(ctx, &iamv1.GetCallerIdentityRequest{})
	if err != nil {
		return iamActionError(err, "sts:GetCallerIdentity")
	}
	return c.printIAMResponse(options.outputOptions, "sts:GetCallerIdentity", response, func(message proto.Message) iamView {
		return iamCallerIdentityView(message.(*iamv1.GetCallerIdentityResponse))
	})
}

func iamCallerIdentityView(identity *iamv1.GetCallerIdentityResponse) iamView {
	return iamObjectView([]iamField{
		{"session_id", identity.GetSessionId()},
		{"session_urn", identity.GetSessionUrn()},
		{"role_urn", identity.GetRoleUrn()},
		{"session_name", identity.GetSessionName()},
		{"expire_time", formatIAMTime(identity.GetExpireTime())},
	})
}
