package secretsmanagerv1

import (
	"strings"

	"google.golang.org/grpc"
)

const (
	// ServiceKey selects the Secrets Manager endpoint and origin profile in the shared SDK.
	ServiceKey = "secretsmanager"
	// ServiceOrigin is the stable logical HTTPS origin bound into Secrets Manager request
	// proofs, independent of transport endpoint overrides.
	ServiceOrigin   = "https://secretsmanager.platform.motiveiq.net"
	defaultEndpoint = "dns:///api.motiveiq.net:443"
)

// GRPCClientConfig is the narrow shared-SDK contract used by the Secrets Manager package.
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

// Client is a configured Secrets Manager client. The shared Config owns its transport.
type Client struct {
	SecretsManagerClient
	cfg      GRPCClientConfig
	endpoint string
}

// NewFromConfig constructs a Secrets Manager client without performing network I/O.
func NewFromConfig(cfg GRPCClientConfig, optFns ...func(*ClientOptions)) *Client {
	var options ClientOptions
	for _, optFn := range optFns {
		optFn(&options)
	}
	conn := cfg.GRPCClientConn(ServiceKey, defaultEndpoint, ServiceOrigin, strings.TrimSpace(options.BaseEndpoint))
	return &Client{SecretsManagerClient: NewSecretsManagerClient(conn), cfg: cfg, endpoint: strings.TrimSpace(options.BaseEndpoint)}
}
