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

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "go.motiveiq.dev/platform/iam/api/v1"
	"go.motiveiq.dev/platform/iam/oauth"
	motiveiq "go.motiveiq.dev/platform/iam/sdk"
)

type proofConfigTestServer struct {
	iamv1.UnimplementedControlPlaneServer
	iamv1.UnimplementedSTSServer

	issuanceMetadata metadata.MD
	iamMetadata      metadata.MD
	identityMetadata metadata.MD
	issuanceCalls    atomic.Int64
}

func (s *proofConfigTestServer) AssumeRoleWithWebIdentity(ctx context.Context, request *iamv1.AssumeRoleWithWebIdentityRequest) (*iamv1.AssumeRoleWithWebIdentityResponse, error) {
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
	iamv1.RegisterControlPlaneServer(server, service)
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
	t.Setenv(oauth.TokenFileEnv, filepath.Join(credentialDirectory, "credentials.json"))
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv(IAMSessionCacheDirEnv, "")
	cacheDirectory := filepath.Join(os.Getenv("XDG_CACHE_HOME"), "iq", "sts")
	if _, err := oauth.SaveCredentials(oauth.Credentials{
		"access_token": "oauth-web-identity", "audience": oauth.PlatformAudience,
		"expires_at": time.Now().Add(time.Hour).Unix(),
	}, ""); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(credentialDirectory, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(credentialDirectory, 0o700) })
	providerCalls := 0
	command.WebIdentityToken = func(ctx context.Context) (string, error) {
		providerCalls++
		return webIdentityTokenFromStore(ctx)
	}
	options := []motiveiq.Option{
		motiveiq.WithTransportCredentials(insecure.NewCredentials()),
		motiveiq.WithClientTransportCredentials(insecure.NewCredentials()),
		motiveiq.WithDialOptions(grpc.WithContextDialer(dialer)),
		motiveiq.WithClientDialOptions(grpc.WithContextDialer(dialer)),
	}
	config, err := command.loadSDKConfigWithOptions(context.Background(), IAMHumanRoleURN, options...)
	if err != nil {
		t.Fatalf("loadSDKConfig: %v", err)
	}
	t.Cleanup(func() { _ = config.Close() })
	if providerCalls != 0 {
		t.Fatal("web identity provider was called before the first operation")
	}

	iam := iamv1.NewControlPlaneFromConfig(config)
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
	assertProofMetadata(t, service.iamMetadata, "DPoP session-token", iamv1.ControlPlane_ListRoles_FullMethodName, iamv1.ControlPlaneServiceOrigin)

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
	if entries, err := os.ReadDir(credentialDirectory); err != nil || len(entries) != 1 || entries[0].Name() != "credentials.json" {
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
	nextCommand.WebIdentityToken = command.WebIdentityToken
	nextConfig, err := nextCommand.loadSDKConfigWithOptions(context.Background(), IAMHumanRoleURN, options...)
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
	t.Setenv(oauth.TokenFileEnv, "/mounted/credentials.json")
	t.Setenv(oauth.BazelTokenFileEnv, "/other/credentials.json")
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
