package publiccli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	iamv1 "go.motiveiq.dev/platform/iam/api/v1"
	motiveiq "go.motiveiq.dev/platform/iam/sdk"
	sdkconfig "go.motiveiq.dev/platform/iam/sdk/config"
	"go.motiveiq.dev/platform/iam/sdk/sessioncache"
)

const (
	IAMEndpointEnv        = "IQ_IAM_ENDPOINT"
	IAMSessionCacheDirEnv = "IQ_SESSION_CACHE_DIR"
)

type iamClient struct {
	client *iamv1.IAM
}

type stsClient struct {
	client *iamv1.STS
}

func newIAMFromConfig(config *motiveiq.Config) (IAMClient, error) {
	if config == nil {
		return nil, errors.New("nil MotiveIQ config")
	}
	return &iamClient{client: iamv1.NewFromConfig(config)}, nil
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

// loadSDKConfig resolves one proof-only shared configuration for IAM and STS.
// Session issuance, refresh, the proof key, and all service connections are
// owned by the returned Config. IQ opts into the SDK's process-shared cache.
func (c *Command) loadSDKConfig(ctx context.Context, roleURN string) (*motiveiq.Config, error) {
	return c.loadSDKConfigWithOptions(ctx, roleURN)
}

func (c *Command) loadSDKConfigWithOptions(ctx context.Context, roleURN string, options ...motiveiq.Option) (*motiveiq.Config, error) {
	identity, err := c.ResolveIdentity(roleURN)
	if err != nil {
		return nil, err
	}
	address := identity.STSEndpoint
	if address == "" {
		address = IAMAddress
	}
	// An explicit IAM endpoint override also selects the STS ingress address.
	if override := strings.TrimSpace(c.Env(IAMEndpointEnv)); override != "" {
		address = override
	}
	identity.STSEndpoint = address
	cacheDirectory, err := c.sessionCacheDirectory()
	if err != nil {
		return nil, err
	}
	base := []motiveiq.Option{
		motiveiq.WithSessionCache(sessioncache.NewFile(cacheDirectory)),
		motiveiq.WithSTSProofOrigin(iamv1.STSServiceOrigin),
		motiveiq.WithServiceEndpoint(iamv1.ServiceKey, address),
		motiveiq.WithServiceEndpoint(iamv1.STSServiceKey, address),
	}
	return sdkconfig.LoadIdentity(ctx, identity, append(base, options...)...)
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
