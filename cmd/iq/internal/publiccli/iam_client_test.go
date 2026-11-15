package publiccli

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pelletier/go-toml/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "go.motiveiq.dev/platform/iam/api/v1"
	motiveiq "go.motiveiq.dev/platform/iam/sdk"
	sdkconfig "go.motiveiq.dev/platform/iam/sdk/config"
)

type proofConfigTestServer struct {
	iamv1.UnimplementedIAMServer
	iamv1.UnimplementedSTSServer

	issuanceMetadata  metadata.MD
	iamMetadata       metadata.MD
	identityMetadata  metadata.MD
	issuanceCalls     atomic.Int64
	webIdentity, role string
}

func (s *proofConfigTestServer) AssumeRoleWithWebIdentity(ctx context.Context, request *iamv1.AssumeRoleWithWebIdentityRequest) (*iamv1.AssumeRoleWithWebIdentityResponse, error) {
	s.webIdentity, s.role = request.GetWebIdentityToken(), request.GetRoleUrn()
	s.issuanceCalls.Add(1)
	s.issuanceMetadata, _ = metadata.FromIncomingContext(ctx)
	proofs := s.issuanceMetadata.Get("dpop")
	if len(proofs) != 1 {
		return nil, fmt.Errorf("issuance dpop values = %d, want 1", len(proofs))
	}
	thumbprint, err := proofThumbprint(proofs[0])
	if err != nil {
		return nil, err
	}
	return &iamv1.AssumeRoleWithWebIdentityResponse{
		SessionToken:       "session-token",
		SessionId:          "session_1",
		SessionUrn:         "urn:motiveiq:sts:assumed-role/human/test",
		RoleUrn:            request.GetRoleUrn(),
		ExpireTime:         timestamppb.New(time.Now().Add(15 * time.Minute)),
		SessionTokenType:   iamv1.SessionTokenType_SESSION_TOKEN_TYPE_PROOF_OF_POSSESSION,
		ProofKeyThumbprint: thumbprint,
	}, nil
}

func (s *proofConfigTestServer) ListRoles(ctx context.Context, _ *iamv1.ListRolesRequest) (*iamv1.ListRolesResponse, error) {
	s.iamMetadata, _ = metadata.FromIncomingContext(ctx)
	return &iamv1.ListRolesResponse{}, nil
}

func (s *proofConfigTestServer) GetCallerIdentity(ctx context.Context, _ *iamv1.GetCallerIdentityRequest) (*iamv1.GetCallerIdentityResponse, error) {
	s.identityMetadata, _ = metadata.FromIncomingContext(ctx)
	return &iamv1.GetCallerIdentityResponse{SessionId: "session_1"}, nil
}

func TestIQSharedConfigSignsV3ForIAMAndSTS(t *testing.T) {
	listener := bufconn.Listen(1024 * 1024)
	server := grpc.NewServer()
	service := &proofConfigTestServer{}
	iamv1.RegisterIAMServer(server, service)
	iamv1.RegisterSTSServer(server, service)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	dialer := func(context.Context, string) (net.Conn, error) { return listener.Dial() }

	command := NewCommand()
	// bufconn tests must not resolve a production hostname before dialing.
	t.Setenv(IAMEndpointEnv, "passthrough:///bufconn")
	credentialDirectory := t.TempDir()
	tokenFile := filepath.Join(credentialDirectory, "token")
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv(IAMSessionCacheDirEnv, "")
	cacheDirectory := filepath.Join(os.Getenv("XDG_CACHE_HOME"), "iq", "sts")
	if err := os.WriteFile(tokenFile, []byte("external-web-identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(credentialDirectory, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(credentialDirectory, 0o700) })
	providerCalls := 0
	useTestIdentity(command, func(ctx context.Context) (string, error) {
		providerCalls++
		data, err := os.ReadFile(tokenFile)
		return string(data), err
	})
	options := []motiveiq.Option{
		motiveiq.WithTransportCredentials(insecure.NewCredentials()),
		motiveiq.WithClientTransportCredentials(insecure.NewCredentials()),
		motiveiq.WithDialOptions(grpc.WithContextDialer(dialer)),
		motiveiq.WithClientDialOptions(grpc.WithContextDialer(dialer)),
	}
	config, err := command.loadSDKConfigWithOptions(context.Background(), testRoleURN, options...)
	if err != nil {
		t.Fatalf("loadSDKConfig: %v", err)
	}
	t.Cleanup(func() { _ = config.Close() })
	if providerCalls != 0 {
		t.Fatal("web identity provider was called before the first operation")
	}

	iam := iamv1.NewFromConfig(config)
	if _, err := iam.ListRoles(context.Background(), &iamv1.ListRolesRequest{}); err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if providerCalls != 1 {
		t.Fatalf("web identity provider calls = %d, want 1", providerCalls)
	}
	assertProofMetadata(t, service.issuanceMetadata, "", iamv1.STS_AssumeRoleWithWebIdentity_FullMethodName, iamv1.STSServiceOrigin)
	if got := service.issuanceMetadata.Get("authorization"); len(got) != 0 {
		t.Fatalf("issuance authorization metadata = %v, want none", got)
	}
	assertProofMetadata(t, service.iamMetadata, "DPoP session-token", iamv1.IAM_ListRoles_FullMethodName, iamv1.ServiceOrigin)

	sts := iamv1.NewSTSFromConfig(config)
	if _, err := sts.GetCallerIdentity(context.Background(), &iamv1.GetCallerIdentityRequest{}); err != nil {
		t.Fatalf("GetCallerIdentity: %v", err)
	}
	if providerCalls != 1 {
		t.Fatalf("web identity provider calls after credential reuse = %d, want 1", providerCalls)
	}
	assertProofMetadata(t, service.identityMetadata, "DPoP session-token", iamv1.STS_GetCallerIdentity_FullMethodName, iamv1.STSServiceOrigin)
	if info, err := os.Stat(cacheDirectory); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("private cache in user cache home: info=%v error=%v", info, err)
	}
	if entries, err := os.ReadDir(credentialDirectory); err != nil || len(entries) != 1 || entries[0].Name() != "token" {
		t.Fatalf("credential mount changed: entries=%v error=%v", entries, err)
	}
	firstProof := service.identityMetadata.Get("dpop")[0]
	if err := config.Close(); err != nil {
		t.Fatal(err)
	}

	// A fresh command/config must use the persisted session and proof key.
	// The explicit override resolves the same cache as the default above.
	nextCommand := NewCommand()
	nextCommand.Env = func(name string) string {
		if name == IAMEndpointEnv {
			return "passthrough:///bufconn"
		}
		if name == IAMSessionCacheDirEnv {
			return cacheDirectory
		}
		return ""
	}
	nextCommand.ResolveIdentity = command.ResolveIdentity
	nextConfig, err := nextCommand.loadSDKConfigWithOptions(context.Background(), testRoleURN, options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nextConfig.Close() })
	if _, err := iamv1.NewSTSFromConfig(nextConfig).GetCallerIdentity(context.Background(), &iamv1.GetCallerIdentityRequest{}); err != nil {
		t.Fatalf("GetCallerIdentity with restored session: %v", err)
	}
	if calls := service.issuanceCalls.Load(); calls != 1 {
		t.Fatalf("STS exchanges across commands = %d, want 1", calls)
	}
	if providerCalls != 2 {
		t.Fatalf("each command must resolve its current web identity: %d calls", providerCalls)
	}
	assertProofMetadata(t, service.identityMetadata, "DPoP session-token", iamv1.STS_GetCallerIdentity_FullMethodName, iamv1.STSServiceOrigin)
	nextProof := service.identityMetadata.Get("dpop")[0]
	firstThumbprint, err := proofThumbprint(firstProof)
	if err != nil {
		t.Fatal(err)
	}
	nextThumbprint, err := proofThumbprint(nextProof)
	if err != nil {
		t.Fatal(err)
	}
	if firstProof == nextProof || firstThumbprint != nextThumbprint {
		t.Fatal("new command must sign a fresh proof using the persisted proof key")
	}
}

func TestSessionCacheDirectory(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "config"))
	for _, tc := range []struct {
		name, override, cacheHome, want string
	}{
		{"home", "", "", filepath.Join(home, ".cache", "iq", "sts")},
		{"xdg", "", "/cache", "/cache/iq/sts"},
		{"override", "/explicit", "/cache", "/explicit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewCommand()
			c.Env = func(name string) string {
				switch name {
				case IAMSessionCacheDirEnv:
					return tc.override
				case "XDG_CACHE_HOME":
					return tc.cacheHome
				default:
					return os.Getenv(name)
				}
			}
			got, err := c.sessionCacheDirectory()
			if err != nil || got != tc.want {
				t.Fatalf("cache directory = %q, error=%v; want %q", got, err, tc.want)
			}
		})
	}
}

func assertProofMetadata(t *testing.T, md metadata.MD, authorization, operation, origin string) {
	t.Helper()
	if got := md.Get("authorization"); strings.Join(got, "\x00") != authorization {
		t.Fatalf("authorization metadata = %v, want %q", got, authorization)
	}
	proofs := md.Get("dpop")
	if len(proofs) != 1 {
		t.Fatalf("dpop values = %d, want 1", len(proofs))
	}
	claims, err := proofClaims(proofs[0])
	if err != nil {
		t.Fatal(err)
	}
	if claims.Version != 3 || claims.Operation != operation || claims.TargetURI != origin+operation {
		t.Fatalf("proof binding = version %d operation %q URI %q", claims.Version, claims.Operation, claims.TargetURI)
	}
	if authorization != "" && claims.TokenHash == "" {
		t.Fatal("authenticated request proof has no token hash")
	}
	if authorization == "" && claims.TokenHash != "" {
		t.Fatalf("issuance proof unexpectedly binds token hash %q", claims.TokenHash)
	}
}

type decodedProofClaims struct {
	Version   int    `json:"mqi_v"`
	Operation string `json:"mqi_operation"`
	TargetURI string `json:"htu"`
	TokenHash string `json:"ath"`
}

func proofClaims(compact string) (decodedProofClaims, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return decodedProofClaims{}, fmt.Errorf("proof has %d segments", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return decodedProofClaims{}, err
	}
	var claims decodedProofClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return decodedProofClaims{}, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return decodedProofClaims{}, err
	}
	if _, ok := members["mqi_"+"target"]; ok {
		return decodedProofClaims{}, fmt.Errorf("proof contains removed target claim")
	}
	return claims, nil
}

func proofThumbprint(compact string) (string, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("proof has %d segments", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", err
	}
	var header struct {
		JWK struct {
			Curve   string `json:"crv"`
			KeyType string `json:"kty"`
			X       string `json:"x"`
		} `json:"jwk"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return "", err
	}
	canonical := []byte(fmt.Sprintf(`{"crv":%q,"kty":%q,"x":%q}`, header.JWK.Curve, header.JWK.KeyType, header.JWK.X))
	digest := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func TestExternalTokenHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--" {
		return
	}
	data, err := os.ReadFile(os.Args[len(os.Args)-1])
	if err != nil {
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(sdkconfig.ProcessToken{Version: 1, Token: string(data)}); err != nil {
		os.Exit(2)
	}
	os.Exit(0)
}

func TestConfiguredSourcesEstablishNormalIAMSession(t *testing.T) {
	for _, kind := range []string{"file", "process"} {
		t.Run(kind, func(t *testing.T) {
			listener := bufconn.Listen(1024 * 1024)
			server := grpc.NewServer()
			service := &proofConfigTestServer{}
			iamv1.RegisterSTSServer(server, service)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(func() { server.Stop(); _ = listener.Close() })
			directory := t.TempDir()
			tokenPath := filepath.Join(directory, "external-token")
			sourceConfig := sdkconfig.SourceConfig{"path": tokenPath}
			if kind == "process" {
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				sourceConfig = sdkconfig.SourceConfig{"command": []string{executable, "-test.run=^TestExternalTokenHelper$", "--", tokenPath}}
			}
			profilePath := filepath.Join(directory, "config.toml")
			data, _ := toml.Marshal(sdkconfig.FileConfig{
				Profiles:           map[string]sdkconfig.Profile{"selected": {RoleURN: testRoleURN, WebIdentitySource: "external", STSEndpoint: "passthrough:///bufconn"}},
				WebIdentitySources: map[string]sdkconfig.Source{"external": {Type: kind, Config: sourceConfig}},
			})
			if err := os.WriteFile(profilePath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			command := NewCommand()
			command.Stdout, command.Stderr = &strings.Builder{}, &strings.Builder{}
			command.Env = func(key string) string {
				switch key {
				case sdkconfig.ConfigFileEnv:
					return profilePath
				case IAMSessionCacheDirEnv:
					return filepath.Join(directory, "sessions")
				case sdkconfig.RoleURNEnv:
					return "urn:motiveiq:iam:role/wrong"
				case sdkconfig.WebIdentityTokenFileEnv:
					return "/wrong-token"
				}
				return ""
			}
			command.LoadSDKConfig = func(ctx context.Context, role string) (*motiveiq.Config, error) {
				return command.loadSDKConfigWithOptions(ctx, role,
					motiveiq.WithTransportCredentials(insecure.NewCredentials()),
					motiveiq.WithClientTransportCredentials(insecure.NewCredentials()),
					motiveiq.WithDialOptions(grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() })),
					motiveiq.WithClientDialOptions(grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() })),
				)
			}
			for _, external := range []string{"first-external-token", "rotated-external-token"} {
				if err := os.WriteFile(tokenPath, []byte(external), 0o600); err != nil {
					t.Fatal(err)
				}
				if code := command.Run(t.Context(), []string{"--profile", "selected", "sts", "get-caller-identity"}); code != 0 {
					t.Fatalf("source %s: %s", kind, command.Stderr)
				}
				if service.webIdentity != external || service.role != testRoleURN {
					t.Fatalf("STS received wrong identity/role: %q/%q", service.webIdentity, service.role)
				}
				assertProofMetadata(t, service.identityMetadata, "DPoP session-token", iamv1.STS_GetCallerIdentity_FullMethodName, iamv1.STSServiceOrigin)
			}
			if calls := service.issuanceCalls.Load(); calls != 2 {
				t.Fatalf("rotated identity should establish a new session: %d", calls)
			}
			if err := os.Remove(tokenPath); err != nil {
				t.Fatal(err)
			}
			if code := command.Run(t.Context(), []string{"--profile", "selected", "sts", "get-caller-identity"}); code == 0 {
				t.Fatal("failed source used a cached session or fallback")
			}
			if calls := service.issuanceCalls.Load(); calls != 2 {
				t.Fatalf("failed source reached STS: %d", calls)
			}
		})
	}
}
