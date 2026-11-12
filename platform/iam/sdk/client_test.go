package motiveiq

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/MotiveIQ/public/platform/iam/internal/proof"
)

func TestServiceEndpointPrecedence(t *testing.T) {
	clearEnv(t)
	resolverCalls := 0
	cfg, err := LoadDefaultConfig(context.Background(),
		WithServiceEndpoint("roboship", "dns:///configured:443"),
		WithEndpointResolver(EndpointResolverFunc(func(context.Context, string) (string, error) {
			resolverCalls++
			return "dns:///resolved:443", nil
		})),
	)
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}

	got, err := cfg.resolveServiceEndpoint(context.Background(), "roboship", "dns:///default:443", "dns:///local:443")
	if err != nil || got != "dns:///local:443" {
		t.Fatalf("local override resolved to %q, %v", got, err)
	}
	got, err = cfg.resolveServiceEndpoint(context.Background(), "roboship", "dns:///default:443", "")
	if err != nil || got != "dns:///configured:443" {
		t.Fatalf("config override resolved to %q, %v", got, err)
	}
	if resolverCalls != 0 {
		t.Fatalf("resolver called %d times before configured endpoints were exhausted", resolverCalls)
	}

	got, err = cfg.resolveServiceEndpoint(context.Background(), "other", "dns:///default:443", "")
	if err != nil || got != "dns:///resolved:443" {
		t.Fatalf("profile resolver resolved to %q, %v", got, err)
	}
	if resolverCalls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolverCalls)
	}
}

func TestGRPCClientConnIsLazyAndRetriesResolverError(t *testing.T) {
	clearEnv(t)
	wantErr := errors.New("catalog unavailable")
	resolverCalls := 0
	clock := newFakeClock()
	_, stsAddr := startFakeSTS(t, clock.Now, 15*time.Minute)
	cfg := newCredentialsConfig(t, clock, stsAddr, writeTokenFile(t, "web-token"),
		WithClientTransportCredentials(insecure.NewCredentials()),
		WithEndpointResolver(EndpointResolverFunc(func(context.Context, string) (string, error) {
			resolverCalls++
			if resolverCalls == 1 {
				return "", wantErr
			}
			return "passthrough:///resolved", nil
		})),
	)

	conn := cfg.GRPCClientConn("roboship", "dns:///default:443", "https://roboship.test", "").(*lazyClientConn)
	if resolverCalls != 0 {
		t.Fatalf("client transport resolved eagerly; calls = %d", resolverCalls)
	}
	_, err := conn.resolve(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("first resolve error = %v, want resolver error", err)
	}
	if resolverCalls != 1 {
		t.Fatalf("resolver calls = %d, want 1", resolverCalls)
	}

	// A transient catalog failure or canceled first request must not poison
	// this typed client for the rest of the process.
	if _, err := conn.resolve(context.Background()); err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	if resolverCalls != 2 {
		t.Fatalf("resolver calls after retry = %d, want 2", resolverCalls)
	}
}

func TestConfigCloseReleasesAndRejectsNewTransports(t *testing.T) {
	clearEnv(t)
	clock := newFakeClock()
	_, stsAddr := startFakeSTS(t, clock.Now, 15*time.Minute)
	cfg := newCredentialsConfig(t, clock, stsAddr, writeTokenFile(t, "web-token"),
		WithClientTransportCredentials(insecure.NewCredentials()))
	conn := cfg.GRPCClientConn("roboship", "passthrough:///resolved", "https://roboship.test", "").(*lazyClientConn)
	if _, err := conn.resolve(context.Background()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(cfg.clientRuntime.conns) != 1 {
		t.Fatalf("pooled conns = %d, want 1", len(cfg.clientRuntime.conns))
	}
	if err := cfg.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := cfg.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if !cfg.clientRuntime.closed || len(cfg.clientRuntime.conns) != 0 {
		t.Fatalf("runtime after Close = closed %v, conns %d", cfg.clientRuntime.closed, len(cfg.clientRuntime.conns))
	}
	fresh := cfg.GRPCClientConn("other", "passthrough:///other", "https://other.test", "").(*lazyClientConn)
	if _, err := fresh.resolve(context.Background()); err == nil || !strings.Contains(err.Error(), "config is closed") {
		t.Fatalf("resolve after Close = %v, want config-is-closed error", err)
	}
}

func TestProductClientTransportDefaultsToTLS(t *testing.T) {
	clearEnv(t)
	cfg, err := LoadDefaultConfig(context.Background())
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}
	if got := cfg.clientTransportCreds.Info().SecurityProtocol; got != "tls" {
		t.Fatalf("product client security protocol = %q, want tls", got)
	}

	cfg, err = LoadDefaultConfig(context.Background(), WithClientTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("LoadDefaultConfig(insecure): %v", err)
	}
	if got := cfg.clientTransportCreds.Info().SecurityProtocol; got != "insecure" {
		t.Fatalf("explicit test transport protocol = %q, want insecure", got)
	}
}

func TestServiceProofOriginResolution(t *testing.T) {
	clearEnv(t)
	cfg, err := LoadDefaultConfig(context.Background(), WithServiceOrigin("roboship", "https://override.test:443/"))
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}
	if got, err := cfg.resolveServiceOrigin("roboship", "dns:///ignored.test:443", "https://default.test"); err != nil || got != "https://override.test" {
		t.Fatalf("configured origin = %q, %v", got, err)
	}
	if got, err := cfg.resolveServiceOrigin("other", "dns:///ignored.test:443", "https://default.test:443/"); err != nil || got != "https://default.test" {
		t.Fatalf("typed default origin = %q, %v", got, err)
	}
	if got, err := cfg.resolveServiceOrigin("derived", "dns:///deploy.platform.motiveiq.net:443", ""); err != nil || got != "https://deploy.platform.motiveiq.net" {
		t.Fatalf("derived origin = %q, %v", got, err)
	}
	if _, err := cfg.resolveServiceOrigin("custom", "passthrough:///bufnet", ""); err == nil || !strings.Contains(err.Error(), "WithServiceOrigin") {
		t.Fatalf("custom resolver origin error = %v", err)
	}
	if _, err := cfg.resolveServiceOrigin("invalid", "dns:///ignored.test:443", "http://not-secure.test"); err == nil || !strings.Contains(err.Error(), "default proof origin") {
		t.Fatalf("invalid typed default origin error = %v", err)
	}
}

func TestProofUnaryInterceptorBindsBodyMethodURIAndToken(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
	sts.returnProofTokens()
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"))
	creds := mustCredentials(t, cfg)

	const (
		origin = "https://deploy.platform.motiveiq.net"
		method = "/motiveiq.roboship.v1.Roboship/TriggerDeploy"
	)
	request := &emptypb.Empty{}
	var received metadata.MD
	invoker := func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
		received, _ = metadata.FromOutgoingContext(ctx)
		return nil
	}
	if err := cfg.clientRuntime.proofUnaryInterceptor(origin, creds, RequestProofOptions{})(
		context.Background(), method, request, &emptypb.Empty{}, nil, invoker,
	); err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	authorization, dpop := received.Get("authorization"), received.Get("dpop")
	if len(authorization) != 1 || authorization[0] != "DPoP session-token-1" || len(dpop) != 1 {
		t.Fatalf("authentication metadata = authorization %v, dpop values %d", authorization, len(dpop))
	}
	requestBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	expected := proof.Binding{
		Transport:   proof.TransportGRPC,
		Operation:   method,
		Method:      "POST",
		TargetURI:   origin + method,
		RequestHash: proof.Digest(requestBytes),
		BindToken:   true,
		TokenHash:   proof.Digest([]byte("session-token-1")),
	}
	verification, err := proof.NewVerifier(clock.Now).Verify(dpop[0], expected)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	generation := mustGeneration(t, creds)
	if generation.signer == nil {
		t.Fatal("credential generation has no proof signer")
	}
	if verification.KeyThumbprint != generation.signer.Thumbprint() {
		t.Fatalf("proof thumbprint = %q, generation = %q", verification.KeyThumbprint, generation.signer.Thumbprint())
	}
	for name, mutate := range map[string]func(*proof.Binding){
		"body":   func(binding *proof.Binding) { binding.RequestHash = proof.Digest([]byte("other")) },
		"method": func(binding *proof.Binding) { binding.Operation = "/other.Service/Call" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := expected
			mutate(&changed)
			if _, err := proof.NewVerifier(clock.Now).Verify(dpop[0], changed); !errors.Is(err, proof.ErrBinding) {
				t.Fatalf("Verify changed binding = %v, want ErrBinding", err)
			}
		})
	}
}

func TestProofUnaryInterceptorDoesNotOutliveSession(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 10*time.Second)
	sts.returnProofTokens()
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"))
	creds := mustCredentials(t, cfg)
	request := &emptypb.Empty{}
	const (
		origin = "https://deploy.platform.motiveiq.net"
		method = "/motiveiq.roboship.v1.Roboship/TriggerDeploy"
	)
	var received metadata.MD
	err := cfg.clientRuntime.proofUnaryInterceptor(origin, creds, RequestProofOptions{})(
		context.Background(), method, request, &emptypb.Empty{}, nil,
		func(ctx context.Context, _ string, _, _ any, _ *grpc.ClientConn, _ ...grpc.CallOption) error {
			received, _ = metadata.FromOutgoingContext(ctx)
			return nil
		},
	)
	if err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	generation := mustGeneration(t, creds)
	requestBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	verification, err := proof.NewVerifier(clock.Now).Verify(received.Get("dpop")[0], proof.Binding{
		Transport:   proof.TransportGRPC,
		Operation:   method,
		Method:      "POST",
		TargetURI:   origin + method,
		RequestHash: proof.Digest(requestBytes),
		BindToken:   true,
		TokenHash:   proof.Digest([]byte(generation.token)),
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verification.ExpiresAt.Equal(generation.expiresAt) {
		t.Fatalf("proof expiry = %v, session expiry = %v", verification.ExpiresAt, generation.expiresAt)
	}
}

func TestProofUnaryInterceptorRejectsConflictingAuthentication(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
	sts.returnProofTokens()
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"))
	creds := mustCredentials(t, cfg)
	interceptor := cfg.clientRuntime.proofUnaryInterceptor("https://deploy.test", creds, RequestProofOptions{})

	for _, key := range []string{"authorization", "dpop"} {
		t.Run(key, func(t *testing.T) {
			called := false
			ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs(key, "application-value"))
			err := interceptor(ctx, "/test.Service/Call", &emptypb.Empty{}, &emptypb.Empty{}, nil,
				func(context.Context, string, any, any, *grpc.ClientConn, ...grpc.CallOption) error {
					called = true
					return nil
				})
			if status.Code(err) != codes.InvalidArgument || called {
				t.Fatalf("interceptor error = %v, invoker called = %v", err, called)
			}
		})
	}
}
