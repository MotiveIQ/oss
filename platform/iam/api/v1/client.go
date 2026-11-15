package iamv1

import (
	"context"
	"strings"

	"google.golang.org/grpc"
)

const (
	// ServiceKey selects IAM configuration in the shared SDK.
	ServiceKey = "iam"
	// ServiceOrigin is the logical HTTPS origin bound into IAM request proofs.
	ServiceOrigin = "https://iam.platform.motiveiq.net"
	// STSServiceKey selects STS endpoint and origin configuration in the shared
	// SDK. It differs from the control-plane key because both APIs may be routed
	// independently even though they currently share a transport endpoint.
	STSServiceKey = "iam-sts"
	// STSServiceOrigin is the logical HTTPS origin bound into authenticated STS
	// request proofs.
	STSServiceOrigin = "https://sts.motiveiq.net"
)

// defaultEndpoint is the shared production gRPC endpoint for IAM and STS.
const defaultEndpoint = "dns:///api.motiveiq.net:443"

// GRPCClientConfig is the narrow shared-SDK contract consumed by the IAM API
// package. Keeping it structural avoids an import cycle with the IAM SDK.
type GRPCClientConfig interface {
	GRPCClientConn(serviceKey, defaultEndpoint, defaultOrigin, endpointOverride string) grpc.ClientConnInterface
}

// ClientOptions contains service-local client configuration. The zero value
// uses endpoint resolution from the shared Config and the production default.
type ClientOptions struct {
	// BaseEndpoint overrides endpoint resolution for this client only. It is
	// intended for tests, local development, and exceptional deployments.
	BaseEndpoint string
}

// IAM is a configured IAM client. The shared Config owns its transport.
type IAM struct {
	IAMClient
}

// NewFromConfig constructs an IAM client without network I/O. Configuration
// and transport errors surface from the first RPC.
func NewFromConfig(cfg GRPCClientConfig, optFns ...func(*ClientOptions)) *IAM {
	options := resolveClientOptions(optFns)
	conn := cfg.GRPCClientConn(ServiceKey, defaultEndpoint, ServiceOrigin, options.BaseEndpoint)
	return &IAM{IAMClient: NewIAMClient(conn)}
}

// STS is a configured client for authenticated STS operations. Session
// issuance remains an internal credential-provider concern because it must
// not carry an already-issued session credential.
type STS struct {
	client STSClient
}

// NewSTSFromConfig constructs an authenticated STS client from shared
// MotiveIQ configuration. It deliberately exposes only authenticated
// operations; AssumeRoleWithWebIdentity is performed by Config's credential
// provider on its separate issuance transport.
func NewSTSFromConfig(cfg GRPCClientConfig, optFns ...func(*ClientOptions)) *STS {
	options := resolveClientOptions(optFns)
	conn := cfg.GRPCClientConn(STSServiceKey, defaultEndpoint, STSServiceOrigin, options.BaseEndpoint)
	return &STS{client: NewSTSClient(conn)}
}

// GetCallerIdentity returns the identity of the proof-authenticated session.
func (c *STS) GetCallerIdentity(ctx context.Context, in *GetCallerIdentityRequest, opts ...grpc.CallOption) (*GetCallerIdentityResponse, error) {
	return c.client.GetCallerIdentity(ctx, in, opts...)
}

func resolveClientOptions(optFns []func(*ClientOptions)) ClientOptions {
	var options ClientOptions
	for _, optFn := range optFns {
		optFn(&options)
	}
	options.BaseEndpoint = strings.TrimSpace(options.BaseEndpoint)
	return options
}
