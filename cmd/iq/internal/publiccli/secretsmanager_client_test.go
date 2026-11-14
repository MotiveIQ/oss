package publiccli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/proto"

	iamv1 "go.motiveiq.dev/platform/iam/api/v1"
	motiveiq "go.motiveiq.dev/platform/iam/sdk"
	sm "go.motiveiq.dev/platform/secretsmanager/api/v1"
)

func TestIQSecretsManagerSignsRequestsWithStableOrigin(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	type received struct {
		method  string
		md      metadata.MD
		request proto.Message
	}
	var calls []received
	var targets []string
	var mu sync.Mutex
	server := grpc.NewServer(grpc.UnaryInterceptor(func(ctx context.Context, q any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !strings.HasPrefix(info.FullMethod, "/motiveiq.secretsmanager.v1.") {
			return handler(ctx, q)
		}
		md, _ := metadata.FromIncomingContext(ctx)
		mu.Lock()
		calls = append(calls, received{info.FullMethod, md, proto.Clone(q.(proto.Message))})
		mu.Unlock()
		if info.FullMethod == sm.SecretsManager_PutSecretValue_FullMethodName {
			return &sm.PutSecretValueResponse{Secret: secretTestMetadata()}, nil
		}
		return &sm.GetSecretValueResponse{SecretUrn: secretTestURN, VersionId: secretTestVersion, Value: secretTestValue("synthetic")}, nil
	}))
	iamv1.RegisterSTSServer(server, new(proofConfigTestServer))
	sm.RegisterSecretsManagerServer(server, &sm.UnimplementedSecretsManagerServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	c := NewCommand()
	out, errout := new(bytes.Buffer), new(bytes.Buffer)
	c.Stdout, c.Stderr = out, errout
	cache := filepath.Join(t.TempDir(), "sts-cache")
	c.Env = func(name string) string {
		switch name {
		case IAMSessionCacheDirEnv:
			return cache
		case IAMEndpointEnv:
			return "passthrough:///iam-test"
		case SecretsManagerEndpointEnv:
			return "https://127.0.0.1:8443"
		}
		return ""
	}
	useTestIdentity(c, func(context.Context) (string, error) { return "web-identity", nil })
	dialer := func(_ context.Context, target string) (net.Conn, error) {
		mu.Lock()
		targets = append(targets, target)
		mu.Unlock()
		return listener.Dial()
	}
	c.LoadSDKConfig = func(ctx context.Context, role string) (*motiveiq.Config, error) {
		return c.loadSDKConfigWithOptions(ctx, role, motiveiq.WithTransportCredentials(insecure.NewCredentials()), motiveiq.WithClientTransportCredentials(insecure.NewCredentials()), motiveiq.WithDialOptions(grpc.WithContextDialer(dialer)), motiveiq.WithClientDialOptions(grpc.WithContextDialer(dialer)))
	}
	for _, args := range [][]string{
		{"secretsmanager", "get-secret-value", "--secret-id", secretTestURN},
		{"secretsmanager", "put-secret-value", "--secret-id", secretTestURN, "--expected-revision", "7", "--secret-string", "synthetic", "--endpoint-url", "https://127.0.0.2:9443"},
	} {
		if code := c.Run(context.Background(), args); code != 0 {
			t.Fatalf("exit=%d %s", code, errout)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("calls=%d", len(calls))
	}
	for _, call := range calls {
		assertProofMetadata(t, call.md, "DPoP session-token", call.method, sm.ServiceOrigin)
		proof := strings.Split(call.md.Get("dpop")[0], ".")
		raw, err := base64.RawURLEncoding.DecodeString(proof[1])
		if err != nil {
			t.Fatal(err)
		}
		var claims struct {
			Hash string `json:"mqi_request_hash"`
		}
		if err := json.Unmarshal(raw, &claims); err != nil {
			t.Fatal(err)
		}
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(call.request)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(payload)
		if claims.Hash != base64.RawURLEncoding.EncodeToString(hash[:]) {
			t.Fatal("proof did not bind the secret URN and request body")
		}
	}
	joined := strings.Join(targets, ",")
	if !strings.Contains(joined, "127.0.0.1:8443") || !strings.Contains(joined, "127.0.0.2:9443") {
		t.Fatalf("endpoint overrides not used: %v", targets)
	}
	if _, err := newSecretsManagerFromConfig(nil, ""); err == nil {
		t.Fatal("nil config accepted")
	}
}
