package kmsv1

import (
	"strings"

	"google.golang.org/grpc"
)

const (
	// ServiceKey selects the KMS endpoint and origin profile in the shared SDK.
	ServiceKey = "kms"
	// ServiceOrigin is the stable logical HTTPS origin bound into KMS request
	// proofs, independent of transport endpoint overrides.
	ServiceOrigin   = "https://kms.platform.motiveiq.net"
	defaultEndpoint = "dns:///kms.platform.motiveiq.net:443"
)

// GRPCClientConfig is the narrow shared-SDK contract used by the KMS package.
// It avoids coupling this generated API package to a concrete SDK package.
type GRPCClientConfig interface {
	GRPCClientConn(serviceKey, defaultEndpoint, defaultOrigin, endpointOverride string) grpc.ClientConnInterface
}

// ClientOptions contains service-local client configuration. The zero value
// uses shared endpoint resolution and the production default.
type ClientOptions struct {
	// BaseEndpoint is intended for tests, local development, and exceptional
	// deployments. It does not change ServiceOrigin.
	BaseEndpoint string
}

// Client is a configured KMS client. The shared Config owns its transport.
type Client struct {
	DataPlaneClient
	cfg      GRPCClientConfig
	endpoint string
}

// NewFromConfig constructs an KMS client without performing network I/O.
func NewFromConfig(cfg GRPCClientConfig, optFns ...func(*ClientOptions)) *Client {
	var options ClientOptions
	for _, optFn := range optFns {
		optFn(&options)
	}
	conn := cfg.GRPCClientConn(ServiceKey, defaultEndpoint, ServiceOrigin, strings.TrimSpace(options.BaseEndpoint))
	return &Client{DataPlaneClient: NewDataPlaneClient(conn), cfg: cfg, endpoint: strings.TrimSpace(options.BaseEndpoint)}
}

const ControlPlaneServiceKey = "kms-control"

// Both APIs share a public origin while retaining distinct service profiles.
// Request proofs also bind the generated full method and request payload.
const ControlPlaneServiceOrigin = ServiceOrigin

func NewControlPlaneFromConfig(cfg GRPCClientConfig, optFns ...func(*ClientOptions)) ControlPlaneClient {
	var options ClientOptions
	for _, fn := range optFns {
		fn(&options)
	}
	return NewControlPlaneClient(cfg.GRPCClientConn(ControlPlaneServiceKey, defaultEndpoint, ControlPlaneServiceOrigin, strings.TrimSpace(options.BaseEndpoint)))
}

func NewDataPlaneFromConfig(cfg GRPCClientConfig, optFns ...func(*ClientOptions)) *Client {
	return NewFromConfig(cfg, optFns...)
}
