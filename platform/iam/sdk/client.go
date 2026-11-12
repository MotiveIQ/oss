package motiveiq

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	sdktransport "go.motiveiq.dev/platform/iam/sdk/internal/transport"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"go.motiveiq.dev/platform/iam/internal/proof"
	"go.motiveiq.dev/platform/iam/internal/proofgrpc"
	"go.motiveiq.dev/platform/iam/internal/proofhttp"
)

// EndpointResolver resolves a stable SDK service key to a gRPC target.
// Implementations may consult a deployment profile or service catalog. An
// empty endpoint with a nil error delegates to the service package's compiled
// default.
type EndpointResolver interface {
	ResolveEndpoint(context.Context, string) (string, error)
}

// EndpointResolverFunc adapts a function to EndpointResolver.
type EndpointResolverFunc func(context.Context, string) (string, error)

// ResolveEndpoint implements EndpointResolver.
func (f EndpointResolverFunc) ResolveEndpoint(ctx context.Context, serviceKey string) (string, error) {
	return f(ctx, serviceKey)
}

// GRPCClientConn returns a lazy gRPC transport for a service-specific
// NewFromConfig constructor. It is an SDK extension point, not the ordinary
// application API: application code should construct the typed service client.
//
// Endpoint resolution order is endpointOverride, WithServiceEndpoint,
// EndpointResolver, then defaultEndpoint. Proof-origin resolution is
// WithServiceOrigin, then defaultOrigin, then safe derivation from the resolved
// endpoint. A typed service package must supply its stable logical origin when
// it differs from its transport endpoint. No endpoint is resolved and no
// connection is created until the first Invoke or NewStream. Connections are
// shared by Config for the process lifetime.
func (c *Config) GRPCClientConn(serviceKey, defaultEndpoint, defaultOrigin, endpointOverride string) grpc.ClientConnInterface {
	return &lazyClientConn{
		cfg:              c,
		serviceKey:       strings.TrimSpace(serviceKey),
		defaultEndpoint:  strings.TrimSpace(defaultEndpoint),
		defaultOrigin:    strings.TrimSpace(defaultOrigin),
		endpointOverride: strings.TrimSpace(endpointOverride),
	}
}

// lazyClientConn gives service constructors AWS's no-error NewFromConfig
// shape. Configuration and dial-construction failures surface from the first
// operation, where gRPC already has an error return path.
type lazyClientConn struct {
	cfg              *Config
	serviceKey       string
	defaultEndpoint  string
	defaultOrigin    string
	endpointOverride string

	mu   sync.Mutex
	conn grpc.ClientConnInterface
}

func (c *lazyClientConn) resolve(ctx context.Context) (grpc.ClientConnInterface, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn, nil
	}
	if c.cfg == nil {
		return nil, fmt.Errorf("motiveiq: service client: nil config")
	}
	if c.serviceKey == "" {
		return nil, fmt.Errorf("motiveiq: service client: empty service key")
	}
	endpoint, err := c.cfg.resolveServiceEndpoint(ctx, c.serviceKey, c.defaultEndpoint, c.endpointOverride)
	if err != nil {
		return nil, err
	}
	origin, err := c.cfg.resolveServiceOrigin(c.serviceKey, endpoint, c.defaultOrigin)
	if err != nil {
		return nil, err
	}
	c.conn, err = c.cfg.clientRuntime.connection(c.serviceKey, endpoint, origin)
	if err != nil {
		return nil, err
	}
	return c.conn, nil
}

// Invoke implements grpc.ClientConnInterface.
func (c *lazyClientConn) Invoke(ctx context.Context, method string, args, reply any, opts ...grpc.CallOption) error {
	conn, err := c.resolve(ctx)
	if err != nil {
		return err
	}
	return conn.Invoke(ctx, method, args, reply, opts...)
}

// NewStream implements grpc.ClientConnInterface.
func (c *lazyClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	conn, err := c.resolve(ctx)
	if err != nil {
		return nil, err
	}
	return conn.NewStream(ctx, desc, method, opts...)
}

func (c *Config) resolveServiceEndpoint(ctx context.Context, serviceKey, defaultEndpoint, endpointOverride string) (string, error) {
	if endpoint := strings.TrimSpace(endpointOverride); endpoint != "" {
		return endpoint, nil
	}
	if endpoint := strings.TrimSpace(c.serviceEndpoints[serviceKey]); endpoint != "" {
		return endpoint, nil
	}
	if c.endpointResolver != nil {
		endpoint, err := c.endpointResolver.ResolveEndpoint(ctx, serviceKey)
		if err != nil {
			return "", fmt.Errorf("motiveiq: resolve endpoint for %s: %w", serviceKey, err)
		}
		if endpoint = strings.TrimSpace(endpoint); endpoint != "" {
			return endpoint, nil
		}
	}
	if endpoint := strings.TrimSpace(defaultEndpoint); endpoint != "" {
		return endpoint, nil
	}
	return "", fmt.Errorf("motiveiq: no endpoint configured for service %s", serviceKey)
}

func (c *Config) resolveServiceOrigin(serviceKey, endpoint, defaultOrigin string) (string, error) {
	if origin := strings.TrimSpace(c.serviceOrigins[serviceKey]); origin != "" {
		normalized, err := normalizeHTTPSOrigin(origin)
		if err != nil {
			return "", fmt.Errorf("motiveiq: proof origin for %s: %w", serviceKey, err)
		}
		return normalized, nil
	}
	if origin := strings.TrimSpace(defaultOrigin); origin != "" {
		normalized, err := normalizeHTTPSOrigin(origin)
		if err != nil {
			return "", fmt.Errorf("motiveiq: default proof origin for %s: %w", serviceKey, err)
		}
		return normalized, nil
	}

	target := strings.TrimSpace(endpoint)
	switch {
	case strings.HasPrefix(target, "dns:///"):
		target = strings.TrimPrefix(target, "dns:///")
	case strings.Contains(target, "://"):
		return "", fmt.Errorf("motiveiq: proof origin for %s cannot be safely derived from endpoint %q; use WithServiceOrigin", serviceKey, endpoint)
	}
	if target == "" || strings.ContainsAny(target, "/?#") {
		return "", fmt.Errorf("motiveiq: proof origin for %s cannot be safely derived from endpoint %q; use WithServiceOrigin", serviceKey, endpoint)
	}
	normalized, err := normalizeHTTPSOrigin("https://" + target)
	if err != nil {
		return "", fmt.Errorf("motiveiq: proof origin for %s: %w", serviceKey, err)
	}
	return normalized, nil
}

// proofTargetURI joins a trusted HTTPS origin to a generated gRPC full method.
// Both STS issuance proofs and product-service proofs use this exact form.
func proofTargetURI(origin, operation string) (string, error) {
	origin, err := normalizeHTTPSOrigin(origin)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(operation, "/") || strings.ContainsAny(operation, "?#") {
		return "", fmt.Errorf("invalid gRPC operation %q", operation)
	}
	return origin + operation, nil
}

func normalizeHTTPSOrigin(raw string) (string, error) {
	return proofhttp.NormalizeOrigin(strings.TrimSpace(raw))
}

type clientRuntime struct {
	cfg *Config

	mu     sync.Mutex
	conns  map[string]*grpc.ClientConn
	closed bool
}

func newClientRuntime(cfg *Config) *clientRuntime {
	return &clientRuntime{cfg: cfg, conns: make(map[string]*grpc.ClientConn)}
}

func (r *clientRuntime) connection(serviceKey, endpoint, origin string) (*grpc.ClientConn, error) {
	key := serviceKey + "\x00" + endpoint + "\x00" + origin

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, fmt.Errorf("motiveiq: service client %s: config is closed", serviceKey)
	}
	if conn := r.conns[key]; conn != nil {
		return conn, nil
	}

	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(r.cfg.clientTransportCreds),
	}
	// Application interceptors run before SDK authentication. This makes the
	// SDK interceptor the innermost one: it signs the final request state and
	// sees authentication metadata introduced anywhere earlier in the chain.
	dialOpts = append(dialOpts, r.cfg.clientDialOpts...)
	if name := r.cfg.serviceTLSServerNames[serviceKey]; name != "" {
		tc := r.cfg.clientTransportCreds.Clone()
		if tc.Info().SecurityProtocol != "tls" {
			return nil, fmt.Errorf("motiveiq: service TLS server name requires TLS credentials")
		}
		if err := tc.OverrideServerName(name); err != nil {
			return nil, fmt.Errorf("motiveiq: TLS server name: %w", err)
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(tc))
	}
	creds, err := r.cfg.Credentials()
	if err != nil {
		return nil, fmt.Errorf("motiveiq: service client %s: credentials: %w", serviceKey, err)
	}
	dialOpts = append(dialOpts,
		// A proof is generated once by the logical-call interceptor. Disable
		// configured retries so gRPC cannot reuse it for another processed
		// attempt behind the SDK's back.
		grpc.WithDisableRetry(),
		grpc.WithChainUnaryInterceptor(r.proofUnaryInterceptor(origin, creds, r.cfg.serviceGRPCProof[serviceKey])),
		grpc.WithChainStreamInterceptor(r.proofStreamInterceptor(serviceKey, origin, creds, r.cfg.serviceGRPCProof[serviceKey])),
	)
	conn, err := grpc.NewClient(endpoint, dialOpts...)
	if err != nil {
		return nil, fmt.Errorf("motiveiq: service client %s: create transport for %s: %w", serviceKey, endpoint, err)
	}
	r.conns[key] = conn
	return conn, nil
}

func (r *clientRuntime) proofUnaryInterceptor(origin string, creds *SessionCredentials, options RequestProofOptions) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		delegated, hasDelegation := sdktransport.DelegationFromContext(ctx)
		var generation *credentialGeneration
		var err error
		if hasDelegation {
			generation = &credentialGeneration{token: delegated.Token, signer: delegated.Signer, expiresAt: delegated.ExpiresAt}
		} else {
			generation, err = creds.retrieve(ctx)
			if err != nil {
				return err
			}
		}
		if generation == nil || generation.signer == nil {
			return status.Error(codes.Unauthenticated, "motiveiq: credentials are not proof-bound")
		}
		message, ok := req.(proto.Message)
		if !ok || message == nil {
			return status.Error(codes.Internal, "motiveiq: proof signing requires a protobuf request")
		}
		wireRequest, requestDigest, wireOptions, err := proofgrpc.Encode(message, options.VersionNumber())
		if hasDelegation {
			if method != delegated.Method || origin != delegated.Origin || req != delegated.Request || options.VersionNumber() != proof.Version3 {
				return status.Error(codes.InvalidArgument, "delegated request does not match prepared scope")
			}
			wireRequest, requestDigest, wireOptions = proofgrpc.EncodePayload(delegated.Payload)
			err = nil
		}
		if err != nil {
			return status.Errorf(codes.Internal, "motiveiq: request encoding: %v", err)
		}
		targetURI, err := proofTargetURI(origin, method)
		if err != nil {
			return status.Errorf(codes.Internal, "motiveiq: proof target: %v", err)
		}
		md, _ := metadata.FromOutgoingContext(ctx)
		fields, err := sdktransport.SignedGRPCMetadata(md, options.SignedMetadata)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		if hasDelegation {
			fields[proof.DelegationTokenDigestMetadata] = fmt.Sprintf("%x", proof.Digest([]byte(delegated.Token)))
		}
		issuedAt := r.cfg.now()
		proofExpiresAt := issuedAt.UTC().Truncate(time.Second).Add(proof.MaxLifetime)
		if generation.expiresAt.Before(proofExpiresAt) {
			proofExpiresAt = generation.expiresAt
		}
		compact, err := generation.signer.SignUntil(proof.Binding{
			Version:     options.VersionNumber(),
			Metadata:    fields,
			Transport:   proof.TransportGRPC,
			Operation:   method,
			Method:      "POST",
			TargetURI:   targetURI,
			RequestHash: requestDigest,
			BindToken:   true,
			TokenHash:   proof.Digest([]byte(generation.token)),
		}, issuedAt, proofExpiresAt)
		if err != nil {
			return status.Errorf(codes.Internal, "motiveiq: sign request proof: %v", err)
		}
		ctx, err = withRequestAuthentication(ctx, generation.token, compact)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		if hasDelegation {
			md, _ := metadata.FromOutgoingContext(ctx)
			md = md.Copy()
			md.Set(proof.DelegationTokenDigestMetadata, fields[proof.DelegationTokenDigestMetadata])
			ctx = metadata.NewOutgoingContext(ctx, md)
		}
		return invoker(ctx, method, wireRequest, reply, cc, append(opts, wireOptions...)...)
	}
}

func withRequestAuthentication(ctx context.Context, token, compactProof string) (context.Context, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("motiveiq: empty session token")
	}
	if strings.TrimSpace(compactProof) == "" {
		return nil, fmt.Errorf("motiveiq: empty request proof")
	}
	return withExclusiveOutgoingMetadata(ctx,
		"authorization", "DPoP "+token,
		"dpop", compactProof,
	)
}

// withExclusiveOutgoingMetadata refuses to overwrite authentication values
// already supplied by application code. It copies the outgoing metadata and
// writes each requested key exactly once.
func withExclusiveOutgoingMetadata(ctx context.Context, keyValues ...string) (context.Context, error) {
	if len(keyValues)%2 != 0 {
		return nil, fmt.Errorf("motiveiq: invalid metadata key/value list")
	}
	if err := sdktransport.EnsureNoOutgoingAuthentication(ctx); err != nil {
		return nil, err
	}
	md, _ := metadata.FromOutgoingContext(ctx)
	md = md.Copy()
	for i := 0; i < len(keyValues); i += 2 {
		key := strings.ToLower(strings.TrimSpace(keyValues[i]))
		value := strings.TrimSpace(keyValues[i+1])
		if key == "" || value == "" {
			return nil, fmt.Errorf("motiveiq: empty authentication metadata")
		}
		md.Set(key, value)
	}
	return metadata.NewOutgoingContext(ctx, md), nil
}

func (r *clientRuntime) close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	conns := r.conns
	r.conns = make(map[string]*grpc.ClientConn)
	r.mu.Unlock()

	var errs []error
	for _, conn := range conns {
		if err := conn.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
