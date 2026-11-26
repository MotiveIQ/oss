package motiveiq

// In-process client fakes: a clock and proof-aware STS exercise credential
// exchange without private server code or production credentials.

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	iamv1 "go.motiveiq.dev/platform/iam/api/v1"
	"go.motiveiq.dev/platform/iam/internal/proof"
	"go.motiveiq.dev/platform/iam/internal/proofgrpc"
)

// testIssuer is the session-token issuer the unit tests use.
const testIssuer = "https://sts.unit.test"

// testRoleURN is a syntactically valid role URN.
const testRoleURN = "urn:iq:iam:role/unit-test"

// fakeClock is a manually advanced time source.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeSTS implements iamv1.STSServer in-process. Each successful exchange
// mints "session-token-<n>" expiring lifetime after now().
type fakeSTS struct {
	iamv1.UnimplementedSTSServer

	now      func() time.Time
	lifetime time.Duration

	mu                     sync.Mutex
	failWith               error // non-nil: exchanges fail with this error
	failNextWith           error // non-nil: the next failNext exchanges fail with this error
	failNext               int
	block                  chan struct{} // non-nil: exchanges wait until closed
	calls                  int
	started                int
	lastWebIdentity        string
	lastSessionName        string
	lastDuration           int64
	lastRequestedTokenType iamv1.SessionTokenType
	lastDPoP               []string
	dpopHistory            []string
	responseTokenType      iamv1.SessionTokenType
	responseThumbprint     string
	deriveProofThumbprint  bool
}

func (f *fakeSTS) AssumeRoleWithWebIdentity(ctx context.Context, req *iamv1.AssumeRoleWithWebIdentityRequest) (*iamv1.AssumeRoleWithWebIdentityResponse, error) {
	f.mu.Lock()
	f.started++
	block := f.block
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastWebIdentity = req.GetWebIdentityToken()
	f.lastSessionName = req.GetSessionName()
	f.lastDuration = req.GetDurationSeconds()
	f.lastRequestedTokenType = req.GetRequestedTokenType()
	md, _ := metadata.FromIncomingContext(ctx)
	f.lastDPoP = append([]string(nil), md.Get("dpop")...)
	if len(f.lastDPoP) == 1 {
		f.dpopHistory = append(f.dpopHistory, f.lastDPoP[0])
	}
	if f.failNext > 0 {
		f.failNext--
		return nil, f.failNextWith
	}
	if f.failWith != nil {
		return nil, f.failWith
	}
	now := f.now()
	thumbprint := f.responseThumbprint
	if f.deriveProofThumbprint {
		if len(f.lastDPoP) != 1 {
			return nil, status.Errorf(codes.InvalidArgument, "dpop values = %d, want 1", len(f.lastDPoP))
		}
		version, digest, err := proofgrpc.RequestDigest(ctx, req, f.lastDPoP[0])
		if err != nil {
			return nil, status.Errorf(codes.Internal, "request digest: %v", err)
		}
		verification, err := proof.NewVerifier(f.now).Verify(f.lastDPoP[0], proof.Binding{
			Version:     version,
			Transport:   proof.TransportGRPC,
			Operation:   iamv1.STS_AssumeRoleWithWebIdentity_FullMethodName,
			Method:      "POST",
			TargetURI:   testIssuer + iamv1.STS_AssumeRoleWithWebIdentity_FullMethodName,
			RequestHash: digest,
			BindToken:   false,
		})
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "verify dpop: %v", err)
		}
		thumbprint = verification.KeyThumbprint
	}
	return &iamv1.AssumeRoleWithWebIdentityResponse{
		SessionToken:       fmt.Sprintf("session-token-%d", f.calls),
		SessionId:          fmt.Sprintf("session_%d", f.calls),
		SessionUrn:         "urn:iq:sts:assumed-role/unit-test/pod-1",
		RoleUrn:            req.GetRoleUrn(),
		ExpireTime:         timestamppb.New(now.Add(f.lifetime)),
		SessionTokenType:   f.responseTokenType,
		ProofKeyThumbprint: thumbprint,
	}, nil
}

func (f *fakeSTS) snapshot() (calls int, web, name string, duration int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls, f.lastWebIdentity, f.lastSessionName, f.lastDuration
}

func (f *fakeSTS) setFail(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failWith = err
}

func (f *fakeSTS) setFailNext(count int, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext = count
	f.failNextWith = err
}

func (f *fakeSTS) setBlock(ch chan struct{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.block = ch
}

func (f *fakeSTS) returnProofTokens() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responseTokenType = iamv1.SessionTokenType_SESSION_TOKEN_TYPE_PROOF_OF_POSSESSION
	f.responseThumbprint = ""
	f.deriveProofThumbprint = true
}

func (f *fakeSTS) setTokenResponse(tokenType iamv1.SessionTokenType, thumbprint string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responseTokenType = tokenType
	f.responseThumbprint = thumbprint
	f.deriveProofThumbprint = false
}

func (f *fakeSTS) proofSnapshot() (requested iamv1.SessionTokenType, dpop []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastRequestedTokenType, append([]string(nil), f.lastDPoP...)
}

func (f *fakeSTS) proofHistorySnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.dpopHistory...)
}

func (f *fakeSTS) startedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.started
}

// startGRPC serves the given registrations on a loopback listener and
// returns its address.
func startGRPC(t *testing.T, register func(*grpc.Server)) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(proofgrpc.ServerOption())
	register(srv)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	return lis.Addr().String()
}

// startFakeSTS boots a fake STS and returns it with its address. now is
// the fake's time source for minted expiries (a fake clock's Now method,
// or time.Now for wall-clock tests).
func startFakeSTS(t *testing.T, now func() time.Time, lifetime time.Duration) (*fakeSTS, string) {
	t.Helper()
	f := &fakeSTS{
		now:                   now,
		lifetime:              lifetime,
		responseTokenType:     iamv1.SessionTokenType_SESSION_TOKEN_TYPE_PROOF_OF_POSSESSION,
		deriveProofThumbprint: true,
	}
	addr := startGRPC(t, func(s *grpc.Server) { iamv1.RegisterSTSServer(proofgrpc.Registrar(s), f) })
	return f, addr
}

func writeTokenFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	rewriteTokenFile(t, path, contents)
	return path
}

func rewriteTokenFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents+"\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
}

// newCredentialsConfig builds a Config wired to the fake STS.
func newCredentialsConfig(t *testing.T, clock *fakeClock, stsAddr, tokenFile string, opts ...Option) *Config {
	t.Helper()
	base := []Option{
		WithRoleURN(testRoleURN),
		WithWebIdentityTokenFile(tokenFile),
		WithSTSEndpoint(stsAddr),
		WithSTSProofOrigin(testIssuer),
		WithClock(clock.Now),
	}
	cfg, err := LoadDefaultConfig(context.Background(), append(base, opts...)...)
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}
	return cfg
}

func testRequestProofSigner(t *testing.T) *proof.Signer {
	t.Helper()
	signer, err := proof.GenerateSigner(nil)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
