package publiccli

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/credentials"

	iamv1 "github.com/MotiveIQ/public/platform/iam/api/v1"
	"github.com/MotiveIQ/public/platform/iam/oauth"
	motiveiq "github.com/MotiveIQ/public/platform/iam/sdk"
	sdkcli "github.com/MotiveIQ/public/platform/iam/sdk/cli"
	"github.com/MotiveIQ/public/platform/iam/sdk/sessioncache"
)

const (
	IAMEndpointEnv        = "MOTIVEIQ_IQ_IAM_ENDPOINT"
	IAMHumanRoleURN       = sdkcli.HumanRole
	IAMSessionCacheDirEnv = "MOTIVEIQ_IQ_SESSION_CACHE_DIR"
)

type iamClient struct {
	client *iamv1.ControlPlane
}

type stsClient struct {
	client *iamv1.STS
}

func newIAMFromConfig(config *motiveiq.Config) (IAMClient, error) {
	if config == nil {
		return nil, errors.New("nil MotiveIQ config")
	}
	return &iamClient{client: iamv1.NewControlPlaneFromConfig(config)}, nil
}

func newSTSFromConfig(config *motiveiq.Config) (STSClient, error) {
	if config == nil {
		return nil, errors.New("nil MotiveIQ config")
	}
	return &stsClient{client: iamv1.NewSTSFromConfig(config)}, nil
}

func (c *iamClient) GetRole(ctx context.Context, request *iamv1.GetRoleRequest) (*iamv1.Role, error) {
	return c.client.GetRole(ctx, request)
}

func (c *iamClient) ListRoles(ctx context.Context, request *iamv1.ListRolesRequest) (*iamv1.ListRolesResponse, error) {
	return c.client.ListRoles(ctx, request)
}

func (c *iamClient) GetPolicy(ctx context.Context, request *iamv1.GetPolicyRequest) (*iamv1.Policy, error) {
	return c.client.GetPolicy(ctx, request)
}

func (c *iamClient) ListPolicies(ctx context.Context, request *iamv1.ListPoliciesRequest) (*iamv1.ListPoliciesResponse, error) {
	return c.client.ListPolicies(ctx, request)
}

func (c *iamClient) GetOIDCProvider(ctx context.Context, request *iamv1.GetOIDCProviderRequest) (*iamv1.OIDCProvider, error) {
	return c.client.GetOIDCProvider(ctx, request)
}

func (c *iamClient) ListOIDCProviders(ctx context.Context, request *iamv1.ListOIDCProvidersRequest) (*iamv1.ListOIDCProvidersResponse, error) {
	return c.client.ListOIDCProviders(ctx, request)
}

func (c *iamClient) GetResourcePolicy(ctx context.Context, request *iamv1.GetResourcePolicyRequest) (*iamv1.ResourcePolicy, error) {
	return c.client.GetResourcePolicy(ctx, request)
}

func (c *iamClient) ListResourcePolicies(ctx context.Context, request *iamv1.ListResourcePoliciesRequest) (*iamv1.ListResourcePoliciesResponse, error) {
	return c.client.ListResourcePolicies(ctx, request)
}

func (c *iamClient) GetServiceDefinition(ctx context.Context, request *iamv1.GetServiceDefinitionRequest) (*iamv1.ServiceDefinition, error) {
	return c.client.GetServiceDefinition(ctx, request)
}

func (c *iamClient) ListServiceDefinitions(ctx context.Context, request *iamv1.ListServiceDefinitionsRequest) (*iamv1.ListServiceDefinitionsResponse, error) {
	return c.client.ListServiceDefinitions(ctx, request)
}

func (c *stsClient) GetCallerIdentity(ctx context.Context, request *iamv1.GetCallerIdentityRequest) (*iamv1.GetCallerIdentityResponse, error) {
	return c.client.GetCallerIdentity(ctx, request)
}

// webIdentityTokenFromStore returns the platform-audience access token that
// STS accepts as the web identity. The audience is the whole requirement:
// granted scopes attenuate the resulting session through its scopes principal
// tag, so a narrowed consent must still yield a token.
func webIdentityTokenFromStore(ctx context.Context) (string, error) {
	return sdkcli.HumanToken(ctx)
}

func loadCredentialsFromStore() (oauth.Credentials, error) {
	credentials, _, err := oauth.LoadCredentials("")
	return credentials, err
}

func (c *Command) iamAddress() string {
	if address := strings.TrimSpace(c.Env(IAMEndpointEnv)); address != "" {
		return address
	}
	return IAMAddress
}

// loadSDKConfig resolves one proof-only shared configuration for IAM and STS.
// Session issuance, refresh, the proof key, and all service connections are
// owned by the returned Config. IQ opts into the SDK's process-shared cache.
func (c *Command) loadSDKConfig(ctx context.Context, roleURN string) (*motiveiq.Config, error) {
	return c.loadSDKConfigWithOptions(ctx, roleURN)
}

func (c *Command) loadSDKConfigWithOptions(ctx context.Context, roleURN string, options ...motiveiq.Option) (*motiveiq.Config, error) {
	if strings.TrimSpace(roleURN) == "" {
		return nil, errors.New("--role is required")
	}
	address := c.iamAddress()
	cacheDirectory, err := c.sessionCacheDirectory()
	if err != nil {
		return nil, err
	}
	base := []motiveiq.Option{
		motiveiq.WithRoleURN(roleURN),
		motiveiq.WithSessionCache(sessioncache.NewFile(cacheDirectory)),
		// IQ obtains human OAuth credentials from its credential store rather
		// than ambient workload-identity variables in the caller's shell.
		motiveiq.WithWebIdentityTokenProvider(motiveiq.WebIdentityTokenProviderFunc(c.WebIdentityToken)),
		motiveiq.WithSTSEndpoint(address),
		motiveiq.WithSTSProofOrigin(iamv1.STSServiceOrigin),
		motiveiq.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})),
		motiveiq.WithClientTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})),
		motiveiq.WithServiceEndpoint(iamv1.ControlPlaneServiceKey, address),
		motiveiq.WithServiceEndpoint(iamv1.STSServiceKey, address),
	}
	return motiveiq.LoadDefaultConfig(ctx, append(base, options...)...)
}

// Session storage must be writable independently of the OAuth credential file,
// which may be mounted read-only or supplied by another process.
func (c *Command) sessionCacheDirectory() (string, error) {
	if directory := c.Env(IAMSessionCacheDirEnv); directory != "" {
		return directory, nil
	}
	cacheHome := c.Env("XDG_CACHE_HOME")
	if cacheHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		cacheHome = filepath.Join(home, ".cache")
	}
	return filepath.Join(cacheHome, "iq", "sts"), nil
}

// LoadConfig constructs the same proof-bound configuration used by API commands.
// Internal command extensions may supply service-specific endpoint options.
func (c *Command) LoadConfig(ctx context.Context, role string, options ...motiveiq.Option) (*motiveiq.Config, error) {
	c.applyDefaults()
	return c.loadSDKConfigWithOptions(ctx, role, options...)
}

func NewIAMFromConfig(cfg *motiveiq.Config) (IAMClient, error) { return newIAMFromConfig(cfg) }
func NewSTSFromConfig(cfg *motiveiq.Config) (STSClient, error) { return newSTSFromConfig(cfg) }
