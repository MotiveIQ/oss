package motiveiq

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"go.motiveiq.dev/platform/iam/internal/proof"
	"go.motiveiq.dev/platform/iam/sdk/sessioncache"
)

// This backend has no filesystem or SDK credential knowledge. Sharing it
// across Configs exercises the public composition contract independently of
// the optional file adapter. A Config also keeps its own memory generation.
type memorySessionCache struct {
	lock    chan struct{}
	records map[string][]byte
}

func newMemorySessionCache() *memorySessionCache {
	return &memorySessionCache{lock: make(chan struct{}, 1), records: make(map[string][]byte)}
}

func (c *memorySessionCache) Update(ctx context.Context, key string, update func([]byte) ([]byte, error)) error {
	select {
	case c.lock <- struct{}{}:
		defer func() { <-c.lock }()
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	next, err := update(slices.Clone(c.records[key]))
	if err == nil && next != nil {
		c.records[key] = slices.Clone(next)
	}
	return err
}

func cachedTestConfig(t *testing.T, clock *fakeClock, address, tokenFile string, cache SessionCache, options ...Option) *Config {
	t.Helper()
	options = append([]Option{WithSessionCache(cache)}, options...)
	config := newCredentialsConfig(t, clock, address, tokenFile, options...)
	t.Cleanup(func() { _ = config.Close() })
	return config
}

func TestSessionCacheReuseAndRefresh(t *testing.T) {
	clock := newFakeClock()
	sts, address := startFakeSTS(t, clock.Now, 15*time.Minute)
	cache, tokenFile := newMemorySessionCache(), writeTokenFile(t, "web-token")
	load := func() *credentialGeneration {
		return mustGeneration(t, mustCredentials(t, cachedTestConfig(t, clock, address, tokenFile, cache)))
	}
	first := load()
	for i := 0; i < 3; i++ {
		clock.Advance(time.Second)
		next := load()
		if next.token != first.token || next.signer.Thumbprint() != first.signer.Thumbprint() || !next.refreshAt.Equal(first.refreshAt) {
			t.Fatal("new config did not restore the same token, proof key and refresh deadline")
		}
	}
	if calls, _, _, _ := sts.snapshot(); calls != 1 {
		t.Fatalf("exchanges = %d, want 1", calls)
	}
	clock.Advance(first.refreshAt.Sub(clock.Now()))
	second := load()
	if second.token == first.token || second.signer.Thumbprint() == first.signer.Thumbprint() {
		t.Fatal("due refresh did not replace the token and proof key together")
	}
	if third := load(); third.token != second.token {
		t.Fatal("refresh was not persisted before returning")
	}
	clock.Advance(second.expiresAt.Sub(clock.Now()))
	if expired := load(); expired.token == second.token {
		t.Fatal("expired session was reused")
	}
	if calls, _, _, _ := sts.snapshot(); calls != 3 {
		t.Fatalf("exchanges = %d, want 3", calls)
	}
}

func TestSessionCacheIsOptIn(t *testing.T) {
	clock := newFakeClock()
	sts, address := startFakeSTS(t, clock.Now, 15*time.Minute)
	file := writeTokenFile(t, "web-token")
	for i := 0; i < 2; i++ {
		config := newCredentialsConfig(t, clock, address, file)
		mustToken(t, mustCredentials(t, config))
		_ = config.Close()
	}
	if calls, _, _, _ := sts.snapshot(); calls != 2 {
		t.Fatalf("default SDK unexpectedly shared sessions: %d exchanges", calls)
	}
}

func TestSessionCacheScopeIsolation(t *testing.T) {
	clock := newFakeClock()
	sts, address := startFakeSTS(t, clock.Now, 15*time.Minute)
	cache, tokenFile := newMemorySessionCache(), writeTokenFile(t, "web-token")
	firstConfig := cachedTestConfig(t, clock, address, tokenFile, cache)
	first := mustToken(t, mustCredentials(t, firstConfig))
	for _, option := range []Option{
		WithRoleURN("urn:iq:iam:role/other"),
		WithSessionName("different-name"),
		WithSessionDuration(time.Minute),
		WithSTSEndpoint("dns:///" + address),
	} {
		config := cachedTestConfig(t, clock, address, tokenFile, cache, option)
		if got := mustToken(t, mustCredentials(t, config)); got == first {
			t.Fatal("changed session options reused a cached session")
		}
	}
	// A different proof origin must also partition the cache, even though
	// this fake STS only accepts proofs for its fixed test origin.
	otherOrigin := cachedTestConfig(t, clock, address, tokenFile, cache, WithSTSProofOrigin("https://other-sts.test"))
	if newSessionCache(otherOrigin).key("web-token") == newSessionCache(firstConfig).key("web-token") {
		t.Fatal("proof origins share a cache key")
	}
	rewriteTokenFile(t, tokenFile, "new-account-or-scopes")
	if got := mustToken(t, mustCredentials(t, cachedTestConfig(t, clock, address, tokenFile, cache))); got == first {
		t.Fatal("different web identity reused a cached session")
	}
	if calls, _, _, _ := sts.snapshot(); calls != 6 {
		t.Fatalf("exchanges = %d, want 6", calls)
	}
	if err := os.Remove(tokenFile); err != nil {
		t.Fatal(err)
	}
	if _, err := mustCredentials(t, cachedTestConfig(t, clock, address, tokenFile, cache)).Token(t.Context()); err == nil {
		t.Fatal("cached session bypassed missing login credentials")
	}
}

func TestSessionCacheRefreshFailure(t *testing.T) {
	clock := newFakeClock()
	sts, address := startFakeSTS(t, clock.Now, 15*time.Minute)
	cache, tokenFile := newMemorySessionCache(), writeTokenFile(t, "web-token")
	load := func() *SessionCredentials {
		return mustCredentials(t, cachedTestConfig(t, clock, address, tokenFile, cache))
	}
	first := mustGeneration(t, load())
	clock.Advance(first.refreshAt.Sub(clock.Now()))
	sts.setFail(status.Error(codes.Unavailable, "STS unavailable"))
	if got := mustToken(t, load()); got != first.token {
		t.Fatal("refresh failure discarded a still-valid cached session")
	}
	if got := mustToken(t, load()); got != first.token {
		t.Fatal("cached fallback was not reusable by another invocation")
	}
	if calls, _, _, _ := sts.snapshot(); calls != 2 {
		t.Fatalf("cache retry delay did not prevent repeated refresh: %d calls", calls)
	}
	clock.Advance(first.expiresAt.Sub(clock.Now()))
	if _, err := load().Token(t.Context()); status.Code(err) != codes.Unavailable {
		t.Fatalf("expired cache must fail closed: %v", err)
	}
}

func TestSessionCacheRepairsCorruptEntries(t *testing.T) {
	for _, corruption := range []string{"invalid JSON", "wrong key", "missing seed", "wrong thumbprint", "oversized", "unknown version"} {
		t.Run(corruption, func(t *testing.T) {
			clock := newFakeClock()
			sts, address := startFakeSTS(t, clock.Now, 15*time.Minute)
			cache, tokenFile := newMemorySessionCache(), writeTokenFile(t, "web-token")
			config := cachedTestConfig(t, clock, address, tokenFile, cache)
			first := mustToken(t, mustCredentials(t, config))
			key := newSessionCache(config).key("web-token")
			payload := cache.records[key]
			var record sessionCacheRecord
			if err := json.Unmarshal(payload, &record); err != nil {
				t.Fatal(err)
			}
			switch corruption {
			case "wrong key":
				record.Key = "different-request"
			case "missing seed":
				record.ProofSeed = nil
			case "wrong thumbprint":
				record.Thumbprint = "different-key"
			case "unknown version":
				record.Version++
			}
			payload, _ = json.Marshal(record)
			if corruption == "invalid JSON" {
				payload = []byte(`{"token":"sensitive-unfinished`)
			} else if corruption == "oversized" {
				payload = []byte(strings.Repeat("x", sessionCacheMaxSize+1))
			}
			cache.records[key] = payload
			if got := mustToken(t, mustCredentials(t, cachedTestConfig(t, clock, address, tokenFile, cache))); got == first {
				t.Fatal("corrupt entry was reused")
			}
			if calls, _, _, _ := sts.snapshot(); calls != 2 {
				t.Fatalf("exchanges = %d, want one repair", calls)
			}
		})
	}
}

func TestSessionCacheSharesMemoryAcrossConfigs(t *testing.T) {
	clock := newFakeClock()
	sts, address := startFakeSTS(t, clock.Now, 15*time.Minute)
	cache, tokenFile := newMemorySessionCache(), writeTokenFile(t, "web-token")
	const callers = 6
	generations := make([]*credentialGeneration, callers)
	errs := make([]error, callers)
	var group sync.WaitGroup
	for i := range callers {
		credentials := mustCredentials(t, cachedTestConfig(t, clock, address, tokenFile, cache))
		group.Go(func() {
			generations[i], errs[i] = credentials.retrieve(t.Context())
		})
	}
	group.Wait()
	for i, generation := range generations {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		if generation.token != generations[0].token || generation.signer.Thumbprint() != generations[0].signer.Thumbprint() {
			t.Fatal("configs did not share one session and proof key through the memory backend")
		}
	}
	if calls, _, _, _ := sts.snapshot(); calls != 1 {
		t.Fatalf("concurrent configs issued %d sessions, want 1", calls)
	}
}

type sessionCacheFunc func(context.Context, string, func([]byte) ([]byte, error)) error

func (f sessionCacheFunc) Update(ctx context.Context, key string, update func([]byte) ([]byte, error)) error {
	return f(ctx, key, update)
}

func TestSessionCacheBackendFailure(t *testing.T) {
	for _, afterCallback := range []bool{false, true} {
		t.Run(fmt.Sprintf("after_callback=%t", afterCallback), func(t *testing.T) {
			clock := newFakeClock()
			sts, address := startFakeSTS(t, clock.Now, 15*time.Minute)
			failure := errors.New("backend unavailable")
			cache := sessionCacheFunc(func(_ context.Context, _ string, update func([]byte) ([]byte, error)) error {
				if afterCallback {
					if _, err := update(nil); err != nil {
						return err
					}
				}
				return failure
			})
			config := cachedTestConfig(t, clock, address, writeTokenFile(t, "web-token"), cache)
			credentials := mustCredentials(t, config)
			if _, err := credentials.Token(t.Context()); !errors.Is(err, failure) {
				t.Fatalf("backend failure was ignored: %v", err)
			}
			credentials.mu.Lock()
			published := credentials.generation
			credentials.mu.Unlock()
			if published != nil {
				t.Fatal("published credentials from an unsuccessful cache transaction")
			}
			wantCalls := 0
			if afterCallback {
				wantCalls = 1
			}
			if calls, _, _, _ := sts.snapshot(); calls != wantCalls {
				t.Fatalf("STS calls = %d, want %d", calls, wantCalls)
			}
		})
	}
}

type cacheProcessResult struct {
	Token string
	Proof string
}

func cacheTestBinding(token string) proof.Binding {
	return proof.Binding{
		Version: proof.Version3, Transport: proof.TransportGRPC,
		Operation: "/test.Service/Read", Method: "POST", TargetURI: "https://service.test/test.Service/Read",
		RequestHash: proof.Digest([]byte("request")), BindToken: true, TokenHash: proof.Digest([]byte(token)),
	}
}

// Invoked in separate OS processes by TestSessionCacheAcrossProcesses.
func TestSessionCacheProcessHelper(t *testing.T) {
	if os.Getenv("IQ_TEST_SESSION_CACHE_HELPER") != "1" {
		return
	}
	config, err := LoadDefaultConfig(t.Context(),
		WithRoleURN(testRoleURN), WithSTSEndpoint(os.Getenv("IQ_TEST_STS_ADDRESS")),
		WithSTSProofOrigin(testIssuer),
		WithWebIdentityTokenFile(os.Getenv("IQ_TEST_TOKEN_FILE")),
		WithSessionCache(sessioncache.NewFile(os.Getenv("IQ_TEST_CACHE_DIRECTORY"))),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer config.Close()
	generation := mustGeneration(t, mustCredentials(t, config))
	compact, err := generation.signer.Sign(cacheTestBinding(generation.token), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(cacheProcessResult{Token: generation.token, Proof: compact})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("cache-result:" + string(payload))
}

func TestSessionCacheAcrossProcesses(t *testing.T) {
	sts, address := startFakeSTS(t, time.Now, 15*time.Minute)
	directory, tokenFile := filepath.Join(t.TempDir(), "cache"), writeTokenFile(t, "web-token")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const processes = 6
	outputs := make([][]byte, processes)
	errors := make([]error, processes)
	var group sync.WaitGroup
	for i := range processes {
		group.Go(func() {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, executable, "-test.run=^TestSessionCacheProcessHelper$")
			command.Env = append(os.Environ(),
				"IQ_TEST_SESSION_CACHE_HELPER=1", "IQ_TEST_STS_ADDRESS="+address,
				"IQ_TEST_TOKEN_FILE="+tokenFile, "IQ_TEST_CACHE_DIRECTORY="+directory,
			)
			outputs[i], errors[i] = command.CombinedOutput()
		})
	}
	group.Wait()
	var thumbprint string
	proofs := make(map[string]bool)
	for i, output := range outputs {
		if errors[i] != nil {
			t.Fatalf("process %d: %v\n%s", i, errors[i], output)
		}
		var result cacheProcessResult
		found := false
		for _, line := range strings.Split(string(output), "\n") {
			if payload, ok := strings.CutPrefix(line, "cache-result:"); ok {
				if err := json.Unmarshal([]byte(payload), &result); err != nil {
					t.Fatal(err)
				}
				found = true
			}
		}
		if !found || result.Token != "session-token-1" {
			t.Fatalf("process %d did not reuse the single issued session", i)
		}
		verification, err := proof.NewVerifier(time.Now).Verify(result.Proof, cacheTestBinding(result.Token))
		if err != nil {
			t.Fatalf("process %d restored an unusable signing key: %v", i, err)
		}
		if thumbprint != "" && verification.KeyThumbprint != thumbprint {
			t.Fatal("processes used different proof keys")
		}
		thumbprint = verification.KeyThumbprint
		if proofs[result.Proof] {
			t.Fatal("separate processes reused a request proof")
		}
		proofs[result.Proof] = true
	}
	if calls, _, _, _ := sts.snapshot(); calls != 1 {
		t.Fatalf("concurrent processes issued %d sessions, want 1", calls)
	}
}
