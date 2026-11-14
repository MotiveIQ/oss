package publiccli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "go.motiveiq.dev/platform/iam/api/v1"
	motiveiq "go.motiveiq.dev/platform/iam/sdk"
	sdkconfig "go.motiveiq.dev/platform/iam/sdk/config"
)

type fakeIAMClient struct {
	method  string
	request proto.Message
	err     error
}

func (f *fakeIAMClient) record(method string, request proto.Message) error {
	f.method = method
	f.request = request
	return f.err
}

func (f *fakeIAMClient) GetRole(_ context.Context, request *iamv1.GetRoleRequest) (*iamv1.Role, error) {
	if err := f.record("GetRole", request); err != nil {
		return nil, err
	}
	return &iamv1.Role{Name: request.GetName(), Urn: "urn:motiveiq:iam:role/" + request.GetName()}, nil
}

func (f *fakeIAMClient) ListRoles(_ context.Context, request *iamv1.ListRolesRequest) (*iamv1.ListRolesResponse, error) {
	if err := f.record("ListRoles", request); err != nil {
		return nil, err
	}
	return &iamv1.ListRolesResponse{Roles: []*iamv1.Role{{Name: "human", Urn: "urn:motiveiq:iam:role/human"}}}, nil
}

func (f *fakeIAMClient) GetPolicy(_ context.Context, request *iamv1.GetPolicyRequest) (*iamv1.Policy, error) {
	if err := f.record("GetPolicy", request); err != nil {
		return nil, err
	}
	return &iamv1.Policy{Name: request.GetName(), Urn: "urn:motiveiq:iam:policy/" + request.GetName()}, nil
}

func (f *fakeIAMClient) ListPolicies(_ context.Context, request *iamv1.ListPoliciesRequest) (*iamv1.ListPoliciesResponse, error) {
	if err := f.record("ListPolicies", request); err != nil {
		return nil, err
	}
	return &iamv1.ListPoliciesResponse{Policies: []*iamv1.Policy{{Name: "human-cli", Urn: "urn:motiveiq:iam:policy/human-cli"}}}, nil
}

// testIssuerCABundle is a wide, multi-line value of the kind that used to
// be dropped from the human formats.
const testIssuerCABundle = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAJ2hgnBrK4kzMA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv\n-----END CERTIFICATE-----\n"

func (f *fakeIAMClient) GetOIDCProvider(_ context.Context, request *iamv1.GetOIDCProviderRequest) (*iamv1.OIDCProvider, error) {
	if err := f.record("GetOIDCProvider", request); err != nil {
		return nil, err
	}
	return &iamv1.OIDCProvider{
		Name:           request.GetName(),
		Urn:            "urn:motiveiq:iam:oidc-provider/" + request.GetName(),
		Issuer:         "https://auth.platform.motiveiq.net",
		IssuerCaBundle: testIssuerCABundle,
	}, nil
}

func (f *fakeIAMClient) ListOIDCProviders(_ context.Context, request *iamv1.ListOIDCProvidersRequest) (*iamv1.ListOIDCProvidersResponse, error) {
	if err := f.record("ListOIDCProviders", request); err != nil {
		return nil, err
	}
	return &iamv1.ListOIDCProvidersResponse{Providers: []*iamv1.OIDCProvider{{Name: "hydra"}}}, nil
}

func (f *fakeIAMClient) GetResourcePolicy(_ context.Context, request *iamv1.GetResourcePolicyRequest) (*iamv1.ResourcePolicy, error) {
	if err := f.record("GetResourcePolicy", request); err != nil {
		return nil, err
	}
	return &iamv1.ResourcePolicy{ResourceUrn: request.GetResourceUrn(), RevisionNumber: 3}, nil
}

func (f *fakeIAMClient) ListResourcePolicies(_ context.Context, request *iamv1.ListResourcePoliciesRequest) (*iamv1.ListResourcePoliciesResponse, error) {
	if err := f.record("ListResourcePolicies", request); err != nil {
		return nil, err
	}
	return &iamv1.ListResourcePoliciesResponse{}, nil
}

func (f *fakeIAMClient) GetServiceDefinition(_ context.Context, request *iamv1.GetServiceDefinitionRequest) (*iamv1.ServiceDefinition, error) {
	if err := f.record("GetServiceDefinition", request); err != nil {
		return nil, err
	}
	return &iamv1.ServiceDefinition{Name: request.GetName(), Actions: []string{"RegisterNamespace"}}, nil
}

func (f *fakeIAMClient) ListServiceDefinitions(_ context.Context, request *iamv1.ListServiceDefinitionsRequest) (*iamv1.ListServiceDefinitionsResponse, error) {
	if err := f.record("ListServiceDefinitions", request); err != nil {
		return nil, err
	}
	return &iamv1.ListServiceDefinitionsResponse{}, nil
}

type fakeSTSClient struct {
	callerCalls int
	callerErr   error
}

func (f *fakeSTSClient) GetCallerIdentity(_ context.Context, _ *iamv1.GetCallerIdentityRequest) (*iamv1.GetCallerIdentityResponse, error) {
	f.callerCalls++
	if f.callerErr != nil {
		return nil, f.callerErr
	}
	return &iamv1.GetCallerIdentityResponse{
		SessionId:   "session_123",
		SessionUrn:  "urn:motiveiq:sts:assumed-role/human/fabian",
		RoleUrn:     "urn:motiveiq:iam:role/human",
		SessionName: "fabian",
		ExpireTime:  timestamppb.New(time.Unix(1767225600, 0)),
	}, nil
}

type iamTestFixture struct {
	command     *Command
	iam         *fakeIAMClient
	sts         *fakeSTSClient
	iamDials    int
	stsDials    int
	loadedRoles []string
}

func newIAMTestFixture(t *testing.T) *iamTestFixture {
	t.Helper()
	fixture := &iamTestFixture{iam: &fakeIAMClient{}, sts: &fakeSTSClient{}}
	command := NewCommand()
	command.Stdout = &strings.Builder{}
	command.Stderr = &strings.Builder{}
	command.Env = func(string) string { return "" }
	command.LoadSDKConfig = func(ctx context.Context, roleURN string) (*motiveiq.Config, error) {
		fixture.loadedRoles = append(fixture.loadedRoles, roleURN)
		return testSDKConfig(ctx, roleURN)
	}

	command.NewIAMFromConfig = func(*motiveiq.Config) (IAMClient, error) {
		fixture.iamDials++
		return fixture.iam, nil
	}
	command.NewSTSFromConfig = func(*motiveiq.Config) (STSClient, error) {
		fixture.stsDials++
		return fixture.sts, nil
	}
	fixture.command = command
	return fixture
}

func testSDKConfig(ctx context.Context, roleURN string) (*motiveiq.Config, error) {
	return motiveiq.LoadDefaultConfig(ctx,
		motiveiq.WithRoleURN(roleURN),
		motiveiq.WithWebIdentityTokenProvider(motiveiq.WebIdentityTokenProviderFunc(func(context.Context) (string, error) {
			return "web-identity", nil
		})),
		motiveiq.WithSTSEndpoint("unused.test:443"),
	)
}

// runIAMOutput runs one command against a fresh fixture and returns its
// stdout, for the tests that care only about how a response is rendered.
func runIAMOutput(t *testing.T, args []string) string {
	t.Helper()
	fixture := newIAMTestFixture(t)
	if code := fixture.command.Run(context.Background(), args); code != 0 {
		t.Fatalf("%v exit code %d, stderr: %s", args, code, fixture.stderr())
	}
	return fixture.stdout()
}

func (f *iamTestFixture) stdout() string {
	return f.command.Stdout.(*strings.Builder).String()
}

func (f *iamTestFixture) stderr() string {
	return f.command.Stderr.(*strings.Builder).String()
}

func testJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return "eyJhbGciOiJub25lIn0." + base64.RawURLEncoding.EncodeToString(body) + ".signature"
}

const testRoleURN = "urn:motiveiq:iam:role/test"

func useTestIdentity(c *Command, provider func(context.Context) (string, error)) {
	c.ResolveIdentity = func(role string) (sdkconfig.Identity, error) {
		if role == "" {
			role = testRoleURN
		}
		return sdkconfig.Identity{RoleURN: role, Provider: motiveiq.WebIdentityTokenProviderFunc(provider)}, nil
	}
}
