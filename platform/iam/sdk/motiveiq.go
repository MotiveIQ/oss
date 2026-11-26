// Package motiveiq supplies outbound API clients with shared, proof-bound STS
// credentials. All clients constructed from one Config share session refresh,
// request signing and pooled transports. Config.Close releases those transports.
//
// LoadDefaultConfig reads IQ_ROLE_URN, IQ_WEB_IDENTITY_TOKEN_FILE,
// IQ_STS_ENDPOINT, IQ_STS_PROOF_ORIGIN and IQ_SESSION_NAME.
// Functional options override the environment. Credential acquisition is lazy;
// a dynamic WebIdentityTokenProvider can replace the projected token file.
// Legacy MOTIVEIQ_* aliases remain supported during workload migration;
// IQ_* values take precedence, with the role and token file selected together.
package motiveiq

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"go.motiveiq.dev/platform/iam/sdk/internal/envconfig"
	sdktransport "go.motiveiq.dev/platform/iam/sdk/internal/transport"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"go.motiveiq.dev/platform/iam/internal/urn"
)

// Environment variables read by LoadDefaultConfig. The admission webhook
// injects RoleURN, WebIdentityTokenFile, and STSEndpoint;
// deployment configuration supplies the rest.
const (
	EnvRoleURN              = "IQ_ROLE_URN"
	EnvWebIdentityTokenFile = "IQ_WEB_IDENTITY_TOKEN_FILE"
	EnvSTSEndpoint          = "IQ_STS_ENDPOINT"
	EnvSTSProofOrigin       = "IQ_STS_PROOF_ORIGIN"
	EnvSessionName          = "IQ_SESSION_NAME"
)

// DefaultSTSProofOrigin is the production logical HTTPS origin bound into STS
// issuance proofs. A request-proof origin is exactly a scheme and authority;
// token issuer verification belongs to the private service SDK.
const DefaultSTSProofOrigin = "https://sts.motiveiq.net"

// Config is the resolved SDK configuration and the factory for the client
// components. It is safe for concurrent use; the component accessors
// each build their component once and hand every caller the same instance,
// so all of a process's clients share one session cache.
type Config struct {
	// RoleURN is the role this workload assumes.
	RoleURN string
	// WebIdentityTokenFile is the projected OIDC token path. It is re-read
	// on every STS exchange — the kubelet rotates the file in place. An
	// explicit WebIdentityTokenProvider takes precedence when configured.
	WebIdentityTokenFile string
	// STSEndpoint is the STS gRPC endpoint (host:port).
	STSEndpoint string
	// STSProofOrigin is the canonical HTTPS origin signed into STS issuance
	// proofs. It is independent of the server-side token issuer.
	STSProofOrigin string

	sessionName              string
	sessionDuration          time.Duration
	sessionCache             SessionCache
	webIdentityTokenProvider WebIdentityTokenProvider
	transportCreds           credentials.TransportCredentials
	dialOpts                 []grpc.DialOption

	// Product-service clients use a separate transport stack from STS.
	// The STS dials above intentionally retain their
	// current mesh-internal transport defaults, while externally reachable
	// product clients default to TLS.
	clientTransportCreds  credentials.TransportCredentials
	clientDialOpts        []grpc.DialOption
	serviceEndpoints      map[string]string
	serviceOrigins        map[string]string
	serviceTLSServerNames map[string]string
	endpointResolver      EndpointResolver
	clientRuntime         *clientRuntime
	serviceGRPCProof      map[string]RequestProofOptions
	stsGRPCProof          RequestProofOptions

	logger *slog.Logger
	now    func() time.Time

	credsOnce sync.Once
	creds     *SessionCredentials
	credsErr  error

	closeOnce sync.Once
	closeErr  error
}

// Option customizes LoadDefaultConfig. Options take precedence over the
// environment.
type Option func(*Config)

// WithRoleURN overrides IQ_ROLE_URN.
func WithRoleURN(roleURN string) Option {
	return func(c *Config) { c.RoleURN = roleURN }
}

// WithWebIdentityTokenFile overrides IQ_WEB_IDENTITY_TOKEN_FILE.
func WithWebIdentityTokenFile(path string) Option {
	return func(c *Config) { c.WebIdentityTokenFile = path }
}

// WithSTSEndpoint overrides IQ_STS_ENDPOINT.
func WithSTSEndpoint(endpoint string) Option {
	return func(c *Config) { c.STSEndpoint = endpoint }
}

// WithSTSProofOrigin overrides IQ_STS_PROOF_ORIGIN (and the
// DefaultSTSProofOrigin fallback). The value must be a canonical HTTPS origin,
// without a path, query, or fragment.
func WithSTSProofOrigin(origin string) Option {
	return func(c *Config) { c.STSProofOrigin = origin }
}

// WithSessionName sets the session name requested from STS, overriding
// IQ_SESSION_NAME (which the M6 webhook injects with the pod name via
// the downward API). Empty lets STS generate one. Constrained to
// [A-Za-z0-9._-]{1,64} server-side.
func WithSessionName(name string) Option {
	return func(c *Config) { c.sessionName = name }
}

// WithSessionDuration sets the session duration requested from STS. Zero
// (the default) requests the role's maximum. STS rejects requests above the
// role's ceiling.
func WithSessionDuration(d time.Duration) Option {
	return func(c *Config) { c.sessionDuration = d }
}

// WithSessionCache adds an optional backend beyond the Config's in-memory
// credentials. Nil keeps the default of no external storage. The SDK handles
// session identity, encoding, and refresh; the backend handles transactions
// and storage. Native CLIs can opt into sessioncache.NewFile without adding
// filesystem persistence to other SDK consumers. The caller owns the backend's
// lifetime; Config.Close does not close an injected backend.
func WithSessionCache(cache SessionCache) Option {
	return func(c *Config) { c.sessionCache = cache }
}

// WithTransportCredentials sets the transport credentials for the SDK's STS
// and PDP connections. The default is an insecure (plaintext) transport,
// matching the mesh-internal deployment posture — see the SessionCredentials
// security note. Supply TLS credentials here for any dial that leaves the
// mesh.
func WithTransportCredentials(tc credentials.TransportCredentials) Option {
	return func(c *Config) { c.transportCreds = tc }
}

// WithDialOptions appends extra gRPC dial options to the SDK's STS
// connections (after the transport credentials).
func WithDialOptions(opts ...grpc.DialOption) Option {
	return func(c *Config) { c.dialOpts = append(c.dialOpts, opts...) }
}

// WithClientTransportCredentials sets transport credentials for product
// service clients. Their default is TLS 1.2 or newer, independently of the
// mesh-internal STS transport configured by WithTransportCredentials.
func WithClientTransportCredentials(tc credentials.TransportCredentials) Option {
	return func(c *Config) { c.clientTransportCreds = tc }
}

// WithClientDialOptions appends gRPC dial options used only by product-service
// clients constructed from Config.
func WithClientDialOptions(opts ...grpc.DialOption) Option {
	return func(c *Config) { c.clientDialOpts = append(c.clientDialOpts, opts...) }
}

// WithServiceEndpoint overrides one service package's default endpoint. The
// service key is an SDK routing key owned by that package, not an authentication
// claim or a value supplied at an operation call site.
func WithServiceEndpoint(serviceKey, endpoint string) Option {
	return func(c *Config) {
		if c.serviceEndpoints == nil {
			c.serviceEndpoints = make(map[string]string)
		}
		c.serviceEndpoints[serviceKey] = endpoint
	}
}

// WithServiceOrigin supplies the trusted HTTPS origin signed into proofs for
// one product service. When omitted, the SDK safely derives an origin from a
// conventional DNS or host:port gRPC endpoint. Custom resolver schemes must
// provide an explicit origin.
func WithServiceOrigin(serviceKey, origin string) Option {
	return func(c *Config) {
		if c.serviceOrigins == nil {
			c.serviceOrigins = make(map[string]string)
		}
		c.serviceOrigins[serviceKey] = origin
	}
}

// WithEndpointResolver installs the resolver consulted after explicit
// WithServiceEndpoint overrides and before a service package's production
// default. It is primarily for deployment profiles and service discovery.
func WithEndpointResolver(resolver EndpointResolver) Option {
	return func(c *Config) { c.endpointResolver = resolver }
}

// WithLogger sets the logger for SDK-internal events (credential refresh
// failures). Defaults to slog.Default().
func WithLogger(logger *slog.Logger) Option {
	return func(c *Config) { c.logger = logger }
}

// WithClock overrides the SDK's time source. Tests drive credential-refresh
// state machines with a fake clock; production code never needs this.
func WithClock(now func() time.Time) Option {
	return func(c *Config) { c.now = now }
}

// LoadDefaultConfig resolves SDK configuration from the environment (see
// the package documentation for the variable contract) and then applies
// opts. It performs no I/O and dials nothing; components are built on first
// use. The context is accepted for interface stability (mirroring the AWS
// SDK shape) and future credential-source probing; it is not currently used.
func LoadDefaultConfig(_ context.Context, opts ...Option) (*Config, error) {
	cfg := &Config{
		RoleURN:              envconfig.Get(os.Getenv, EnvRoleURN),
		WebIdentityTokenFile: envconfig.Get(os.Getenv, EnvWebIdentityTokenFile),
		STSEndpoint:          envconfig.Get(os.Getenv, EnvSTSEndpoint),
		STSProofOrigin:       envconfig.Get(os.Getenv, EnvSTSProofOrigin),
		sessionName:          envconfig.Get(os.Getenv, EnvSessionName),
		serviceEndpoints:     make(map[string]string),
		serviceOrigins:       make(map[string]string),
		serviceGRPCProof:     make(map[string]RequestProofOptions),
	}
	for _, opt := range opts {
		opt(cfg)
	}
	for key, options := range cfg.serviceGRPCProof {
		if strings.TrimSpace(key) == "" || key != strings.TrimSpace(key) {
			return nil, fmt.Errorf("motiveiq: invalid proof service key")
		}
		if err := options.Validate(); err != nil {
			return nil, fmt.Errorf("motiveiq: service %s proof: %w", key, err)
		}
		if err := sdktransport.ValidateGRPCMetadata(options.SignedMetadata); err != nil {
			return nil, err
		}
	}
	if err := cfg.stsGRPCProof.Validate(); err != nil {
		return nil, fmt.Errorf("motiveiq: STS proof: %w", err)
	}
	if len(cfg.stsGRPCProof.SignedMetadata) != 0 {
		return nil, fmt.Errorf("motiveiq: STS does not support application metadata")
	}
	if cfg.STSProofOrigin == "" {
		cfg.STSProofOrigin = DefaultSTSProofOrigin
	}
	normalizedProofOrigin, err := normalizeHTTPSOrigin(cfg.STSProofOrigin)
	if err != nil {
		return nil, fmt.Errorf("motiveiq: %s: %w", EnvSTSProofOrigin, err)
	}
	cfg.STSProofOrigin = normalizedProofOrigin
	if cfg.transportCreds == nil {
		cfg.transportCreds = insecure.NewCredentials()
	}
	if cfg.clientTransportCreds == nil {
		cfg.clientTransportCreds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	if cfg.logger == nil {
		cfg.logger = slog.Default()
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	cfg.clientRuntime = newClientRuntime(cfg)
	// Validate what is present; absence is legal (the component
	// constructors demand their own inputs).
	if cfg.RoleURN != "" {
		parsed, err := urn.Parse(cfg.RoleURN)
		if err != nil {
			return nil, fmt.Errorf("motiveiq: %s: %w", EnvRoleURN, err)
		}
		cfg.RoleURN = parsed.String()
	}
	return cfg, nil
}

// Credentials returns the process-wide session credential provider,
// building it on first call. It requires RoleURN, STSEndpoint, and either a
// WebIdentityTokenProvider or WebIdentityTokenFile.
func (c *Config) Credentials() (*SessionCredentials, error) {
	c.credsOnce.Do(func() {
		c.creds, c.credsErr = newSessionCredentials(c)
	})
	return c.creds, c.credsErr
}

// Close releases gRPC transports owned by Config. Service clients are
// lightweight views over those transports and must not close them. Most
// long-running processes keep one Config for their lifetime; short-lived
// tools should defer Close after LoadDefaultConfig.
//
// Close is idempotent and should be called only after users of the Config
// have stopped.
func (c *Config) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		var errs []error
		if c.clientRuntime != nil {
			errs = append(errs, c.clientRuntime.close())
		}
		if c.creds != nil && c.creds.conn != nil {
			errs = append(errs, c.creds.conn.Close())
		}
		c.closeErr = errors.Join(errs...)
	})
	return c.closeErr
}

// dialOptions assembles the gRPC dial options shared by the STS
// connections.
func (c *Config) dialOptions() []grpc.DialOption {
	opts := []grpc.DialOption{grpc.WithTransportCredentials(c.transportCreds)}
	return append(opts, c.dialOpts...)
}

// WithServiceTLSServerName sets the verified backend certificate name when an
// internal dial address differs from it. It does not change the proof origin.
// This option requires TLS transport credentials; it never disables validation.
func WithServiceTLSServerName(serviceKey, name string) Option {
	return func(c *Config) {
		if c.serviceTLSServerNames == nil {
			c.serviceTLSServerNames = make(map[string]string)
		}
		c.serviceTLSServerNames[serviceKey] = name
	}
}
