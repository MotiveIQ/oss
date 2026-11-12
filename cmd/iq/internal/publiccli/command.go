// Package publiccli implements repository-independent MotiveIQ API commands.
package publiccli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	iamv1 "go.motiveiq.dev/platform/iam/api/v1"
	"go.motiveiq.dev/platform/iam/oauth"
	motiveiq "go.motiveiq.dev/platform/iam/sdk"
)

const IAMAddress = "api.motiveiq.net:443"

// ErrUsage distinguishes invalid command usage from an operation failure.
var ErrUsage = errors.New("usage error")
var errUsage = ErrUsage

type IAMClient interface {
	GetRole(context.Context, *iamv1.GetRoleRequest) (*iamv1.Role, error)
	ListRoles(context.Context, *iamv1.ListRolesRequest) (*iamv1.ListRolesResponse, error)
	GetPolicy(context.Context, *iamv1.GetPolicyRequest) (*iamv1.Policy, error)
	ListPolicies(context.Context, *iamv1.ListPoliciesRequest) (*iamv1.ListPoliciesResponse, error)
	GetOIDCProvider(context.Context, *iamv1.GetOIDCProviderRequest) (*iamv1.OIDCProvider, error)
	ListOIDCProviders(context.Context, *iamv1.ListOIDCProvidersRequest) (*iamv1.ListOIDCProvidersResponse, error)
	GetResourcePolicy(context.Context, *iamv1.GetResourcePolicyRequest) (*iamv1.ResourcePolicy, error)
	ListResourcePolicies(context.Context, *iamv1.ListResourcePoliciesRequest) (*iamv1.ListResourcePoliciesResponse, error)
	GetServiceDefinition(context.Context, *iamv1.GetServiceDefinitionRequest) (*iamv1.ServiceDefinition, error)
	ListServiceDefinitions(context.Context, *iamv1.ListServiceDefinitionsRequest) (*iamv1.ListServiceDefinitionsResponse, error)
}

type STSClient interface {
	GetCallerIdentity(context.Context, *iamv1.GetCallerIdentityRequest) (*iamv1.GetCallerIdentityResponse, error)
}

// Command owns API command dependencies. It never discovers a workspace or
// loads build, deployment, or cluster inventory configuration.
type Command struct {
	Stdin                       io.Reader
	Stdout, Stderr              io.Writer
	Env                         func(string) string
	LoadSDKConfig               func(context.Context, string) (*motiveiq.Config, error)
	NewIAMFromConfig            func(*motiveiq.Config) (IAMClient, error)
	NewSTSFromConfig            func(*motiveiq.Config) (STSClient, error)
	NewS3FromConfig             func(*motiveiq.Config, string) (S3Client, error)
	NewKMSFromConfig            func(*motiveiq.Config, string) (KMSClient, error)
	NewSecretsManagerFromConfig func(*motiveiq.Config, string) (SecretsManagerClient, error)
	WebIdentityToken            func(context.Context) (string, error)
	Login                       func(context.Context, io.Writer) (oauth.Credentials, error)
	SaveCredentials             func(oauth.Credentials) (string, error)
	LoadCredentials             func() (oauth.Credentials, error)

	// LoginHint is optional guidance supplied by a containing application.
	LoginHint string
}

func NewCommand() *Command {
	c := &Command{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
	c.applyDefaults()
	return c
}

func (c *Command) Run(ctx context.Context, args []string) int {
	c.applyDefaults()
	root := c.rootCommand()
	root.SetArgs(args)
	root.SetIn(c.Stdin)
	root.SetOut(c.Stdout)
	root.SetErr(c.Stderr)
	if err := root.ExecuteContext(ctx); err != nil {
		if errors.Is(err, ErrUsage) {
			return 2
		}
		fmt.Fprintf(c.Stderr, "iq: %v\n", err)
		return 1
	}
	return 0
}

// Commands returns fresh commands for composition into an existing CLI.
func (c *Command) Commands() []*cobra.Command {
	c.applyDefaults()
	return []*cobra.Command{
		c.loginCommand(), c.s3Command(), c.kmsCommand(),
		c.secretsManagerCommand(), c.iamCommand(), c.stsCommand(), c.whoamiCommand(),
	}
}

func (c *Command) rootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "iq",
		Short:         "MotiveIQ API command line client.",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_ = cmd.Help()
			return ErrUsage
		},
	}
	root.CompletionOptions.SetDefaultShellCompDirective(cobra.ShellCompDirectiveNoFileComp)
	root.AddCommand(c.Commands()...)
	return root
}

func (c *Command) applyDefaults() {
	if c.Stdin == nil {
		c.Stdin = os.Stdin
	}
	if c.Stdout == nil {
		c.Stdout = io.Discard
	}
	if c.Stderr == nil {
		c.Stderr = io.Discard
	}
	if c.Env == nil {
		c.Env = os.Getenv
	}
	if c.NewIAMFromConfig == nil {
		c.NewIAMFromConfig = newIAMFromConfig
	}
	if c.NewSTSFromConfig == nil {
		c.NewSTSFromConfig = newSTSFromConfig
	}
	if c.NewS3FromConfig == nil {
		c.NewS3FromConfig = newS3FromConfig
	}
	if c.NewKMSFromConfig == nil {
		c.NewKMSFromConfig = newKMSFromConfig
	}
	if c.NewSecretsManagerFromConfig == nil {
		c.NewSecretsManagerFromConfig = newSecretsManagerFromConfig
	}
	if c.LoadSDKConfig == nil {
		c.LoadSDKConfig = c.loadSDKConfig
	}
	if c.WebIdentityToken == nil {
		c.WebIdentityToken = webIdentityTokenFromStore
	}
	if c.Login == nil {
		c.Login = func(ctx context.Context, output io.Writer) (oauth.Credentials, error) {
			return oauth.LoginWithBrowser(ctx, oauth.LoginOptions{Output: output, OpenBrowser: true})
		}
	}
	if c.SaveCredentials == nil {
		c.SaveCredentials = func(credentials oauth.Credentials) (string, error) {
			return oauth.SaveCredentials(credentials, "")
		}
	}
	if c.LoadCredentials == nil {
		c.LoadCredentials = loadCredentialsFromStore
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func fixedCompletions(choices ...cobra.Completion) cobra.CompletionFunc {
	return cobra.FixedCompletions(choices, cobra.ShellCompDirectiveNoFileComp)
}
