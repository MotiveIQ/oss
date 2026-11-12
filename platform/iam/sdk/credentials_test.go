package motiveiq

// Credential-provider state machine tests against a fake clock and an
// in-process fake STS: initial exchange, jittered ~70% refresh,
// single-flight collapse, last-good retention through an STS outage with
// fail-closed after expiry, and token-file rotation pickup.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "go.motiveiq.dev/platform/iam/api/v1"
	"go.motiveiq.dev/platform/iam/internal/proof"
)

// mustCredentials builds the provider from cfg.
func mustCredentials(t *testing.T, cfg *Config) *SessionCredentials {
	t.Helper()
	creds, err := cfg.Credentials()
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	return creds
}

// mustToken calls Token and fails the test on error.
func mustToken(t *testing.T, creds *SessionCredentials) string {
	t.Helper()
	tok, err := creds.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	return tok
}

// refreshWindow reads the provider's cached-token timing under its lock.
func refreshWindow(creds *SessionCredentials) (refreshAt, expiresAt time.Time) {
	creds.mu.Lock()
	defer creds.mu.Unlock()
	if creds.generation == nil {
		return time.Time{}, time.Time{}
	}
	return creds.generation.refreshAt, creds.generation.expiresAt
}

func mustGeneration(t *testing.T, creds *SessionCredentials) *credentialGeneration {
	t.Helper()
	generation, err := creds.retrieve(context.Background())
	if err != nil {
		t.Fatalf("retrieve: %v", err)
	}
	return generation
}

// waitForTokenChange polls Token until it returns something other than
// previous (refreshes are asynchronous while the cached token is valid).
func waitForTokenChange(t *testing.T, creds *SessionCredentials, previous string) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := mustToken(t, creds)
		if got != previous {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for the background refresh to swap the token")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitForExchanges polls until the fake STS has served at least n exchanges.
func waitForExchanges(t *testing.T, sts *fakeSTS, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if calls, _, _, _ := sts.snapshot(); calls >= n {
			return
		}
		if time.Now().After(deadline) {
			calls, _, _, _ := sts.snapshot()
			t.Fatalf("timed out waiting for %d exchanges (have %d)", n, calls)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// waitForIdleExchange polls until no exchange is in flight (its outcome —
// token swap or backoff — is published).
func waitForIdleExchange(t *testing.T, creds *SessionCredentials) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		creds.mu.Lock()
		idle := creds.inflight == nil
		creds.mu.Unlock()
		if idle {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the in-flight exchange to finish")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestCredentialsInitialExchange(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
	file := writeTokenFile(t, "web-token-1")
	cfg := newCredentialsConfig(t, clock, addr, file,
		WithSessionName("pod-1"), WithSessionDuration(10*time.Minute))
	creds := mustCredentials(t, cfg)

	if got := mustToken(t, creds); got != "session-token-1" {
		t.Fatalf("Token = %q, want session-token-1", got)
	}
	calls, web, name, duration := sts.snapshot()
	if calls != 1 {
		t.Errorf("exchanges = %d, want 1", calls)
	}
	if web != "web-token-1" {
		t.Errorf("web identity sent = %q, want the file contents", web)
	}
	if name != "pod-1" {
		t.Errorf("session name sent = %q, want pod-1", name)
	}
	if duration != 600 {
		t.Errorf("duration_seconds sent = %d, want 600", duration)
	}
	requested, dpop := sts.proofSnapshot()
	if requested != iamv1.SessionTokenType_SESSION_TOKEN_TYPE_PROOF_OF_POSSESSION || len(dpop) != 1 {
		t.Fatalf("STS request token type = %v, dpop values = %d; want proof-bound issuance", requested, len(dpop))
	}
	if version, err := proof.UnverifiedVersion(dpop[0]); err != nil || version != proof.Version3 {
		t.Fatalf("default STS proof version = %d, %v; want v3", version, err)
	}

	// Cached: no second exchange while fresh.
	if got := mustToken(t, creds); got != "session-token-1" {
		t.Fatalf("cached Token = %q, want session-token-1", got)
	}
	if calls, _, _, _ := sts.snapshot(); calls != 1 {
		t.Errorf("exchanges after cached call = %d, want 1", calls)
	}
}

func TestCredentialsRejectsOldSTS(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
	sts.setTokenResponse(iamv1.SessionTokenType_SESSION_TOKEN_TYPE_BEARER, "")
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"))
	creds := mustCredentials(t, cfg)

	if _, err := creds.retrieve(context.Background()); err == nil || !strings.Contains(err.Error(), "required proof-bound") {
		t.Fatalf("retrieve error = %v, want proof-bound rejection", err)
	}
	requested, dpop := sts.proofSnapshot()
	if requested != iamv1.SessionTokenType_SESSION_TOKEN_TYPE_PROOF_OF_POSSESSION || len(dpop) != 1 {
		t.Fatalf("STS request token type = %v, dpop values = %d", requested, len(dpop))
	}
}

func TestCredentialsExchangeUsesConfiguredProofOrigin(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
	sts.returnProofTokens()
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"),
		WithSTSProofOrigin(testIssuer),
	)
	generation := mustGeneration(t, mustCredentials(t, cfg))
	if generation.signer == nil {
		t.Fatal("STS exchange did not return a proof-bound generation")
	}
}

func TestCredentialsProofExchangeDisablesConfiguredRetries(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
	sts.setFail(status.Error(codes.Unavailable, "retryable"))
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"),
		WithDialOptions(grpc.WithDefaultServiceConfig(`{
			"methodConfig": [{
				"name": [{"service": "motiveiq.iam.v1.STS", "method": "AssumeRoleWithWebIdentity"}],
				"retryPolicy": {
					"MaxAttempts": 4,
					"InitialBackoff": "0.001s",
					"MaxBackoff": "0.001s",
					"BackoffMultiplier": 1.0,
					"RetryableStatusCodes": ["UNAVAILABLE"]
				}
			}]
		}`)),
	)
	if _, err := mustCredentials(t, cfg).retrieve(context.Background()); status.Code(err) != codes.Unavailable {
		t.Fatalf("retrieve error = %v, want Unavailable", err)
	}
	if calls, _, _, _ := sts.snapshot(); calls != 1 {
		t.Fatalf("STS calls = %d, want one attempt with proof retries disabled", calls)
	}
}

func TestCredentialsApplicationRetryMintsFreshSTSProof(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
	sts.returnProofTokens()
	sts.setFailNext(1, status.Error(codes.Unavailable, "retryable"))
	retryOnce := grpc.WithChainUnaryInterceptor(func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		err := invoker(ctx, method, req, reply, cc, opts...)
		if status.Code(err) == codes.Unavailable {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		return err
	})
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"),
		WithDialOptions(retryOnce))
	generation := mustGeneration(t, mustCredentials(t, cfg))
	if generation.signer == nil {
		t.Fatal("retried STS exchange did not return a proof-bound generation")
	}
	if calls, _, _, _ := sts.snapshot(); calls != 2 {
		t.Fatalf("STS calls = %d, want two application-managed attempts", calls)
	}
	proofs := sts.proofHistorySnapshot()
	if len(proofs) != 2 {
		t.Fatalf("STS proofs = %d, want one per attempt", len(proofs))
	}
	if proofs[0] == proofs[1] {
		t.Fatal("application-managed STS retry reused a request proof")
	}
}

func TestCredentialsProofGenerationIsAtomic(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 100*time.Second)
	sts.returnProofTokens()
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"))
	creds := mustCredentials(t, cfg)

	first := mustGeneration(t, creds)
	if first.signer == nil || first.signer.Thumbprint() == "" {
		t.Fatalf("first proof generation is inconsistent: %+v", first)
	}
	firstThumbprint := first.signer.Thumbprint()
	clock.Advance(first.refreshAt.Sub(clock.Now()) + time.Second)
	if got := mustToken(t, creds); got != first.token {
		t.Fatalf("refresh trigger returned %q, want current %q", got, first.token)
	}
	secondToken := waitForTokenChange(t, creds, first.token)
	second := mustGeneration(t, creds)
	if second.token != secondToken || second.signer == nil || second.signer.Thumbprint() == "" {
		t.Fatalf("second proof generation is inconsistent: %+v", second)
	}
	if second == first || second.signer == first.signer || second.signer.Thumbprint() == firstThumbprint {
		t.Fatal("refresh did not atomically replace the token and proof key generation")
	}
	if first.signer.Thumbprint() != firstThumbprint {
		t.Fatal("published first generation was mutated during refresh")
	}
}

func TestCredentialsRejectInconsistentProofResponse(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
	sts.setTokenResponse(iamv1.SessionTokenType_SESSION_TOKEN_TYPE_PROOF_OF_POSSESSION, "wrong-thumbprint")
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"))
	if _, err := mustCredentials(t, cfg).retrieve(context.Background()); err == nil || !strings.Contains(err.Error(), "thumbprint") {
		t.Fatalf("retrieve error = %v, want thumbprint mismatch", err)
	}
}

func TestCredentialsRefreshAtJitteredSeventyPercent(t *testing.T) {
	const lifetime = 100 * time.Second
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, lifetime)
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"))
	creds := mustCredentials(t, cfg)

	// Several refresh cycles: every scheduled refresh point must fall in
	// the jitter window [60%, 80%] of the lifetime.
	previous := mustToken(t, creds)
	for cycle := 0; cycle < 12; cycle++ {
		refreshAt, expiresAt := refreshWindow(creds)
		issued := clock.Now()
		frac := float64(refreshAt.Sub(issued)) / float64(lifetime)
		if frac < 0.60 || frac > 0.80 {
			t.Fatalf("cycle %d: refresh scheduled at %.3f of lifetime, want [0.60, 0.80]", cycle, frac)
		}
		if got := expiresAt.Sub(issued); got != lifetime {
			t.Fatalf("cycle %d: expiry %v after issue, want %v", cycle, got, lifetime)
		}

		// Just before the refresh point: cached token, no exchange.
		clock.Advance(refreshAt.Sub(issued) - time.Millisecond)
		if got := mustToken(t, creds); got != previous {
			t.Fatalf("cycle %d: token refreshed before the refresh point", cycle)
		}

		// At the refresh point: the still-valid cached token returns
		// immediately while the exchange runs in the background, well
		// before expiry.
		clock.Advance(time.Millisecond)
		if got := mustToken(t, creds); got != previous {
			t.Fatalf("cycle %d: Token did not serve the cached token at the refresh point", cycle)
		}
		previous = waitForTokenChange(t, creds, previous)
	}
	if calls, _, _, _ := sts.snapshot(); calls != 13 {
		t.Errorf("exchanges = %d, want 13 (1 initial + 12 refreshes)", calls)
	}
}

func TestCredentialsSingleflight(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
	release := make(chan struct{})
	sts.setBlock(release)
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"))
	creds := mustCredentials(t, cfg)

	const callers = 24
	tokens := make([]string, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tokens[i], errs[i] = creds.Token(context.Background())
		}(i)
	}

	// Wait until the one exchange is on the wire, then let it finish. If
	// more than one starts, the counter says so below.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if sts.startedCount() >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no exchange started")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	wg.Wait()

	for i := 0; i < callers; i++ {
		if errs[i] != nil {
			t.Fatalf("caller %d: %v", i, errs[i])
		}
		if tokens[i] != "session-token-1" {
			t.Fatalf("caller %d got %q, want the single shared token", i, tokens[i])
		}
	}
	if calls, _, _, _ := sts.snapshot(); calls != 1 {
		t.Errorf("exchanges = %d, want 1 (single flight)", calls)
	}
}

func TestCredentialsOutageHoldsLastGoodThenFailsClosed(t *testing.T) {
	const lifetime = 100 * time.Second
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, lifetime)
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"))
	creds := mustCredentials(t, cfg)

	first := mustToken(t, creds)
	refreshAt, expiresAt := refreshWindow(creds)
	sts.setFail(status.Error(codes.Unavailable, "sts down"))

	// Past the refresh point with STS down: the caller gets the last-good
	// token immediately; the background probe fails and arms the backoff.
	clock.Advance(refreshAt.Sub(clock.Now()) + time.Second)
	if got := mustToken(t, creds); got != first {
		t.Fatalf("Token during outage = %q, want last-good %q", got, first)
	}
	waitForExchanges(t, sts, 2)
	waitForIdleExchange(t, creds)
	calls, _, _, _ := sts.snapshot()
	if calls != 2 {
		t.Errorf("exchanges = %d, want 2 (initial + failed probe)", calls)
	}

	// Inside the backoff window: last-good again, no new probe.
	if got := mustToken(t, creds); got != first {
		t.Fatalf("Token inside backoff = %q, want last-good", got)
	}
	if c, _, _, _ := sts.snapshot(); c != calls {
		t.Errorf("exchanges inside backoff = %d, want %d (no new probe)", c, calls)
	}

	// After the backoff: another background probe, still failing, still
	// last-good. (initialBackoff was the first failure's backoff; advancing
	// just past it keeps the cached token comfortably inside its 100s
	// lifetime.)
	clock.Advance(initialBackoff + 500*time.Millisecond)
	if got := mustToken(t, creds); got != first {
		t.Fatalf("Token after backoff = %q, want last-good", got)
	}
	waitForExchanges(t, sts, calls+1)
	waitForIdleExchange(t, creds)
	if c, _, _, _ := sts.snapshot(); c != calls+1 {
		t.Errorf("exchanges after backoff = %d, want %d", c, calls+1)
	}

	// Past the real expiry: fail closed with the STS error.
	clock.Advance(expiresAt.Sub(clock.Now()) + time.Second)
	_, err := creds.Token(context.Background())
	if err == nil {
		t.Fatal("Token after expiry during outage: got nil error, want fail closed")
	}
	if status.Code(err) != codes.Unavailable {
		t.Errorf("fail-closed error = %v, want the underlying Unavailable STS error", err)
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("fail-closed error %q does not mention expiry", err)
	}

	// Recovery: STS back, next attempt succeeds.
	sts.setFail(nil)
	clock.Advance(maxBackoff + time.Second)
	recovered := mustToken(t, creds)
	if recovered == first || recovered == "" {
		t.Fatalf("recovered token = %q, want a fresh session", recovered)
	}
}

func TestCredentialsTokenFileRotation(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 100*time.Second)
	file := writeTokenFile(t, "web-token-1")
	cfg := newCredentialsConfig(t, clock, addr, file)
	creds := mustCredentials(t, cfg)

	mustToken(t, creds)
	if _, web, _, _ := sts.snapshot(); web != "web-token-1" {
		t.Fatalf("first exchange sent %q", web)
	}

	// The kubelet rotates the projected file; the next (background)
	// exchange must read the fresh contents.
	rewriteTokenFile(t, file, "web-token-2")
	refreshAt, _ := refreshWindow(creds)
	clock.Advance(refreshAt.Sub(clock.Now()) + time.Second)
	mustToken(t, creds)
	waitForExchanges(t, sts, 2)
	if _, web, _, _ := sts.snapshot(); web != "web-token-2" {
		t.Errorf("post-rotation exchange sent %q, want web-token-2", web)
	}
}

func TestCredentialsWebIdentityProviderTakesPrecedenceAndRefreshes(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
	var mu sync.Mutex
	current := "provider-token-1"
	calls := 0
	provider := WebIdentityTokenProviderFunc(func(context.Context) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		return current, nil
	})
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "stale-file-token"),
		WithWebIdentityTokenProvider(provider))
	creds := mustCredentials(t, cfg)

	mustToken(t, creds)
	if _, web, _, _ := sts.snapshot(); web != "provider-token-1" {
		t.Fatalf("first exchange sent %q, want provider token", web)
	}
	mu.Lock()
	current = "provider-token-2"
	mu.Unlock()
	if _, err := creds.exchangeOnce(context.Background()); err != nil {
		t.Fatalf("second exchange: %v", err)
	}
	if _, web, _, _ := sts.snapshot(); web != "provider-token-2" {
		t.Fatalf("second exchange sent %q, want refreshed provider token", web)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 2 {
		t.Fatalf("provider calls = %d, want one per exchange", calls)
	}
}

func TestCredentialsWebIdentityProviderReplacesMissingFile(t *testing.T) {
	clock := newFakeClock()
	_, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
	cfg, err := LoadDefaultConfig(context.Background(),
		WithRoleURN(testRoleURN),
		WithWebIdentityTokenFile(""),
		WithWebIdentityTokenProvider(WebIdentityTokenProviderFunc(func(context.Context) (string, error) {
			return "human-web-token", nil
		})),
		WithSTSEndpoint(addr),
		WithSTSProofOrigin(testIssuer),
		WithClock(clock.Now),
	)
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}
	if got := mustToken(t, mustCredentials(t, cfg)); got != "session-token-1" {
		t.Fatalf("Token = %q, want session-token-1", got)
	}
}

func TestCredentialsMissingTokenFileFailsExchange(t *testing.T) {
	clock := newFakeClock()
	_, addr := startFakeSTS(t, clock.Now, 100*time.Second)
	cfg := newCredentialsConfig(t, clock, addr, "/nonexistent/motiveiq-token")
	creds := mustCredentials(t, cfg)
	if _, err := creds.Token(context.Background()); err == nil {
		t.Fatal("Token with missing web-identity file: want error")
	}
}

func TestCredentialsRunKeepsWarm(t *testing.T) {
	// Run uses wall-clock timers, so this test runs in real time with a
	// short session lifetime.
	sts, addr := startFakeSTS(t, time.Now, 400*time.Millisecond)
	cfg := newCredentialsConfig(t, nil, addr, writeTokenFile(t, "web-token-1"), WithClock(time.Now))
	creds := mustCredentials(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { creds.Run(ctx); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if calls, _, _, _ := sts.snapshot(); calls >= 2 {
			break // refreshed at least once without any Token caller
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not refresh the session")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop on context cancellation")
	}
}

func TestCredentialsValidTokenNeverBlocksOnRefresh(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"))
	creds := mustCredentials(t, cfg)

	first := mustToken(t, creds)

	// The refresh point passes while STS hangs. Token must return the
	// still-valid cached token immediately, not join the stuck exchange.
	release := make(chan struct{})
	sts.setBlock(release)
	refreshAt, _ := refreshWindow(creds)
	clock.Advance(refreshAt.Sub(clock.Now()) + time.Second)

	began := time.Now()
	if got := mustToken(t, creds); got != first {
		t.Fatalf("Token during hung refresh = %q, want the cached %q", got, first)
	}
	if elapsed := time.Since(began); elapsed > 2*time.Second {
		t.Fatalf("Token took %v during a hung exchange, want an immediate return", elapsed)
	}

	// Releasing the exchange lets the background refresh swap the token,
	// and the single flight winds down (no leaked in-flight state).
	close(release)
	next := waitForTokenChange(t, creds, first)
	if next == "" || next == first {
		t.Fatalf("background refresh produced %q", next)
	}
	waitForIdleExchange(t, creds)
	if calls, _, _, _ := sts.snapshot(); calls != 2 {
		t.Errorf("exchanges = %d, want 2 (initial + one background refresh)", calls)
	}
}

func TestCredentialsExpiredTokenBlocksAndFailsClosed(t *testing.T) {
	const lifetime = 100 * time.Second
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, lifetime)
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"))
	creds := mustCredentials(t, cfg)

	mustToken(t, creds)
	_, expiresAt := refreshWindow(creds)

	// Past the hard expiry with STS failing: no valid token exists, so
	// Token must block on the exchange and fail closed with its error —
	// the SDK never fabricates validity.
	sts.setFail(status.Error(codes.Unavailable, "sts down"))
	clock.Advance(expiresAt.Sub(clock.Now()) + time.Second)
	_, err := creds.Token(context.Background())
	if err == nil {
		t.Fatal("Token past expiry with STS failing: got nil error, want fail closed")
	}
	if status.Code(err) != codes.Unavailable {
		t.Errorf("fail-closed error = %v, want the underlying Unavailable STS error", err)
	}

	// Recovery still works: the next attempt past the backoff succeeds and
	// blocks only as long as the exchange itself.
	sts.setFail(nil)
	clock.Advance(maxBackoff + time.Second)
	if got := mustToken(t, creds); got == "" {
		t.Fatal("Token after recovery is empty")
	}
}

func TestCredentialsCallerCancellation(t *testing.T) {
	clock := newFakeClock()
	sts, addr := startFakeSTS(t, clock.Now, 15*time.Minute)
	release := make(chan struct{})
	sts.setBlock(release)
	defer close(release)
	cfg := newCredentialsConfig(t, clock, addr, writeTokenFile(t, "web-token-1"))
	creds := mustCredentials(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := creds.Token(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Token with canceled ctx = %v, want context.Canceled", err)
	}
}
