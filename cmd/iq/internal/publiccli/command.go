// Package publiccli implements MotiveIQ API, profile login, and installation commands.
package publiccli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"go.motiveiq.dev/cmd/iq/internal/install"
	iamv1 "go.motiveiq.dev/platform/iam/api/v1"
	motiveiq "go.motiveiq.dev/platform/iam/sdk"
	sdkconfig "go.motiveiq.dev/platform/iam/sdk/config"
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

// Command owns the shared CLI. Only explicit installation discovers a Bazel
// workspace; API operations and login work independently of a checkout.
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
	Login                       func(context.Context, io.Writer) error
	Profile                     string
	ResolveIdentity             func(string) (sdkconfig.Identity, error)
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
	installer := &install.Command{
		Stdin: c.Stdin, Stdout: c.Stdout, Stderr: c.Stderr, Env: c.Env,
	}
	return []*cobra.Command{
		c.s3Command(), c.kmsCommand(),
		c.secretsManagerCommand(), c.iamCommand(), c.stsCommand(),
		c.loginCommand(), installer.CobraCommand(),
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
	root.PersistentFlags().StringVar(&c.Profile, "profile", "", "Credential profile (defaults to IQ_PROFILE or default).")
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
	if c.Login == nil {
		c.Login = c.login
	}
	if c.LoadSDKConfig == nil {
		c.LoadSDKConfig = c.loadSDKConfig
	}
	if c.ResolveIdentity == nil {
		c.ResolveIdentity = func(role string) (sdkconfig.Identity, error) {
			return (sdkconfig.Resolver{Env: c.Env, Profile: c.Profile}).Resolve(role)
		}
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
