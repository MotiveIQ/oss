package motiveiq

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	iamv1 "github.com/MotiveIQ/public/platform/iam/api/v1"
	"github.com/MotiveIQ/public/platform/iam/internal/proof"
	"github.com/MotiveIQ/public/platform/iam/internal/proofgrpc"
)

// Credential-provider tuning. These are deliberately unexported constants:
// the refresh shape (early refresh with jitter, last-good retention,
// fail-closed after expiry) is contract, the numbers are not.
const (
	// refreshFractionBase / refreshFractionJitter: a fresh token's refresh
	// point is drawn uniformly from [60%, 80%] of its lifetime — "~70% with
	// ±10% jitter" — so a fleet of pods assuming at the same instant does
	// not stampede STS at the same instant either.
	refreshFractionBase   = 0.70
	refreshFractionJitter = 0.10
	// exchangeTimeout bounds one AssumeRoleWithWebIdentity round trip
	// (wall clock, independent of any injected test clock).
	exchangeTimeout = 10 * time.Second
	// initialBackoff/maxBackoff pace retries while STS is failing. Between
	// attempts, callers holding a still-valid token get it back instantly.
	initialBackoff = time.Second
	maxBackoff     = 30 * time.Second
	// runMinWait keeps the Run loop from spinning.
	runMinWait = 50 * time.Millisecond
)

// SessionCredentials is the default workload credential provider (DESIGN.md
// "Kubernetes integration"): it exchanges the projected web-identity token
// for an assumed-role session via STS AssumeRoleWithWebIdentity, caches one
// immutable token-and-proof-key generation, and refreshes it before expiry.
//
// Behavior, in order of what matters:
//
//   - The web-identity provider is called on every exchange. Kubernetes uses
//     a file-backed provider so kubelet rotation is picked up; human tools may
//     supply an OAuth-backed provider without writing that token to disk.
//   - Refresh is lazy: the first Token call at or past the refresh point
//     (a jittered ~70% of the session lifetime) kicks off the exchange in
//     the background and returns the still-valid cached token immediately —
//     holders of a valid token never wait on STS. Concurrent callers share
//     one in-flight exchange (single flight); nobody stampedes STS. Only an
//     expired or absent token blocks on the exchange.
//   - STS failure is absorbed while the cached token is still valid: Token
//     keeps returning the last-good token and retries the exchange with
//     exponential backoff. Once the token's real expiry passes, Token fails
//     closed and returns the STS error — the SDK never fabricates validity.
//   - WithSessionCache optionally shares tokens and proof keys through an
//     injected backend. The first load checks the current web identity and
//     completes any due refresh within the backend transaction before returning.
//   - No periodic refresh loop exists unless the caller opts in via Run.
//
// SessionCredentials deliberately does not implement
// credentials.PerRPCCredentials: that hook cannot see the protobuf request and
// therefore cannot produce a request-bound proof. Construct product clients
// through their NewFromConfig constructor, or use NewAuthenticatedRoundTripper
// for HTTPS REST, so the SDK can sign the exact request.
type SessionCredentials struct {
	roleURN     string
	webIdentity WebIdentityTokenProvider
	sessionName string
	duration    time.Duration
	conn        *grpc.ClientConn
	sts         iamv1.STSClient
	now         func() time.Time
	logger      *slog.Logger
	cache       *sessionCache

	mu         sync.Mutex
	generation *credentialGeneration // immutable; atomically replaced under mu
	inflight   *flight               // the single in-flight exchange, nil when idle
	retryAt    time.Time             // no new exchange before this after a failure
	backoff    time.Duration
	lastErr    error // last exchange error; nil after a success
}

// credentialGeneration is one indivisible authentication generation. A
// proof-bound token is never observable without the exact signer used during
// its STS exchange, and refresh swaps the whole value at once.
type credentialGeneration struct {
	token     string
	signer    *proof.Signer
	expiresAt time.Time
	refreshAt time.Time
}

// flight is one in-progress exchange; waiters block on done.
type flight struct {
	done chan struct{}
}

// newSessionCredentials builds the provider for cfg, validating the
// client-side settings it needs. The gRPC connection is created lazily by
// grpc.NewClient; no I/O happens here.
func newSessionCredentials(cfg *Config) (*SessionCredentials, error) {
	var missing []string
	if cfg.RoleURN == "" {
		missing = append(missing, EnvRoleURN)
	}
	if cfg.webIdentityTokenProvider == nil && cfg.WebIdentityTokenFile == "" {
		missing = append(missing, EnvWebIdentityTokenFile)
	}
	if cfg.STSEndpoint == "" {
		missing = append(missing, EnvSTSEndpoint)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("motiveiq: credentials: missing configuration: %s (set the environment variables or use options)", strings.Join(missing, ", "))
	}
	dialOptions := append(cfg.dialOptions(),
		// Disable grpc-go's configured retries and append the SDK signer after
		// application interceptors. If an application interceptor deliberately
		// retries the logical exchange, the innermost signer mints a distinct
		// proof for every attempt instead of replaying one proof-bearing context.
		grpc.WithDisableRetry(),
		grpc.WithChainUnaryInterceptor(stsProofUnaryInterceptor(cfg.STSProofOrigin, cfg.now, cfg.stsGRPCProof)),
	)
	conn, err := grpc.NewClient(cfg.STSEndpoint, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("motiveiq: credentials: dial STS %s: %w", cfg.STSEndpoint, err)
	}
	webIdentity := cfg.webIdentityTokenProvider
	if webIdentity == nil {
		webIdentity = webIdentityTokenFileProvider(cfg.WebIdentityTokenFile)
	}
	return &SessionCredentials{
		roleURN:     cfg.RoleURN,
		webIdentity: webIdentity,
		sessionName: cfg.sessionName,
		duration:    cfg.sessionDuration,
		conn:        conn,
		sts:         iamv1.NewSTSClient(conn),
		now:         cfg.now,
		logger:      cfg.logger,
		cache:       newSessionCache(cfg),
	}, nil
}

// Token returns a currently valid session token, exchanging or refreshing
// as needed. It is safe for concurrent use; concurrent refreshes collapse
// into one STS call. While the in-memory token is valid Token never blocks: a
// due refresh is kicked off in the background and the cached token returns
// immediately. While STS is unreachable it returns the last-good token
// until that token's real expiry, then fails closed with the STS error.
func (p *SessionCredentials) Token(ctx context.Context) (string, error) {
	generation, err := p.retrieve(ctx)
	if err != nil {
		return "", err
	}
	return generation.token, nil
}

// retrieve returns one immutable, currently valid credential generation.
// Callers that need proof material must retain this exact pointer for the
// whole request rather than separately fetching a token and signer.
func (p *SessionCredentials) retrieve(ctx context.Context) (*credentialGeneration, error) {
	for {
		p.mu.Lock()
		now := p.now()
		generation := p.generation
		valid := generation != nil && generation.token != "" && now.Before(generation.expiresAt)

		// Valid cached token: return it immediately. If the refresh point
		// has passed, kick the exchange asynchronously (single flight,
		// paced by the failure backoff) — the caller never waits on STS
		// while holding minutes of validity.
		if valid {
			if !now.Before(generation.refreshAt) && p.inflight == nil && !now.Before(p.retryAt) {
				fl := &flight{done: make(chan struct{})}
				p.inflight = fl
				go p.runExchange(fl)
			}
			p.mu.Unlock()
			return generation, nil
		}

		// Expired or absent token: only now may Token block. Join an
		// exchange already in flight rather than starting another.
		if fl := p.inflight; fl != nil {
			p.mu.Unlock()
			select {
			case <-fl.done:
				continue // re-evaluate the fresh state
			case <-ctx.Done():
				return nil, fmt.Errorf("motiveiq: credentials: %w", ctx.Err())
			}
		}

		// Failure backoff: while inside the retry-wait window, fail closed
		// with the sticky exchange error.
		if now.Before(p.retryAt) {
			err := p.lastErr
			p.mu.Unlock()
			if err == nil { // unreachable by construction; belt and braces
				err = fmt.Errorf("no valid session token")
			}
			return nil, fmt.Errorf("motiveiq: credentials: session expired and STS exchange failing: %w", err)
		}

		// Start the exchange. It runs detached from any single caller's
		// context (bounded by exchangeTimeout) so one canceled caller
		// cannot poison the shared refresh.
		fl := &flight{done: make(chan struct{})}
		p.inflight = fl
		p.mu.Unlock()
		go p.runExchange(fl)
	}
}

// runExchange performs one exchange and publishes its outcome.
func (p *SessionCredentials) runExchange(fl *flight) {
	ctx, cancel := context.WithTimeout(context.Background(), exchangeTimeout)
	defer cancel()
	generation, err := p.exchangeOnce(ctx)

	p.mu.Lock()
	now := p.now()
	if err != nil {
		p.lastErr = err
		if p.backoff == 0 {
			p.backoff = initialBackoff
		} else {
			p.backoff *= 2
			if p.backoff > maxBackoff {
				p.backoff = maxBackoff
			}
		}
		p.retryAt = now.Add(p.backoff)
		p.logger.Warn("motiveiq: session token exchange failed",
			"role_urn", p.roleURN, "retry_in", p.backoff.String(), "error", err.Error())
	} else {
		published := *generation
		if published.refreshAt.IsZero() {
			published.refreshAt = sessionRefreshTime(now, published.expiresAt)
		}
		p.generation = &published
		p.backoff = 0
		p.retryAt = time.Time{}
		p.lastErr = nil
	}
	p.inflight = nil
	close(fl.done)
	p.mu.Unlock()
}

func sessionRefreshTime(now, expiresAt time.Time) time.Time {
	frac := refreshFractionBase + refreshFractionJitter*(2*rand.Float64()-1)
	return now.Add(time.Duration(frac * float64(expiresAt.Sub(now))))
}

// exchangeOnce retrieves the current web identity, then loads its persisted
// session or performs one AssumeRoleWithWebIdentity call.
func (p *SessionCredentials) exchangeOnce(ctx context.Context) (*credentialGeneration, error) {
	web, err := p.webIdentity.RetrieveWebIdentityToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("retrieve web identity token: %w", err)
	}
	web = strings.TrimSpace(web)
	if web == "" {
		return nil, fmt.Errorf("web identity token provider returned an empty token")
	}
	if p.cache != nil {
		return p.cache.retrieve(ctx, p, web)
	}
	return p.exchangeWebIdentity(ctx, web)
}

func (p *SessionCredentials) exchangeWebIdentity(ctx context.Context, web string) (*credentialGeneration, error) {
	req := &iamv1.AssumeRoleWithWebIdentityRequest{
		RoleUrn:          p.roleURN,
		WebIdentityToken: web,
		SessionName:      p.sessionName,
		DurationSeconds:  int64(p.duration / time.Second),
	}
	requestSigner, err := proof.GenerateSigner(nil)
	if err != nil {
		return nil, fmt.Errorf("motiveiq: credentials: generate proof key: %w", err)
	}
	req.RequestedTokenType = iamv1.SessionTokenType_SESSION_TOKEN_TYPE_PROOF_OF_POSSESSION
	ctx = context.WithValue(ctx, stsProofSigningContextKey{}, requestSigner)
	resp, err := p.sts.AssumeRoleWithWebIdentity(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("AssumeRoleWithWebIdentity(%s): %w", p.roleURN, err)
	}
	tok := resp.GetSessionToken()
	expiresAt := resp.GetExpireTime().AsTime()
	if tok == "" || !expiresAt.After(p.now()) {
		return nil, fmt.Errorf("AssumeRoleWithWebIdentity(%s): response carries no usable session (expiry %v)", p.roleURN, expiresAt)
	}
	return p.validateGeneration(tok, expiresAt, resp.GetSessionTokenType(), resp.GetProofKeyThumbprint(), requestSigner)
}

// stsProofSigningContextKey carries only the private signer for one STS
// exchange. Proof serialization remains in the innermost transport
// interceptor so every application-managed retry gets a fresh proof over the
// exact request passed to that attempt.
type stsProofSigningContextKey struct{}

func stsProofUnaryInterceptor(origin string, now func() time.Time, options RequestProofOptions) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		signer, ok := ctx.Value(stsProofSigningContextKey{}).(*proof.Signer)
		if !ok {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		if signer == nil {
			return fmt.Errorf("motiveiq: credentials: STS proof signer is missing")
		}
		if method != iamv1.STS_AssumeRoleWithWebIdentity_FullMethodName {
			return fmt.Errorf("motiveiq: credentials: cannot sign unsupported STS method %q", method)
		}
		message, ok := req.(proto.Message)
		if !ok || message == nil {
			return fmt.Errorf("motiveiq: credentials: STS proof signing requires a protobuf request")
		}
		wireRequest, requestDigest, wireOptions, err := proofgrpc.Encode(message, options.VersionNumber())
		if err != nil {
			return fmt.Errorf("motiveiq: credentials: marshal STS request: %w", err)
		}
		targetURI, err := proofTargetURI(origin, method)
		if err != nil {
			return fmt.Errorf("motiveiq: credentials: STS proof origin: %w", err)
		}
		issuedAt := now()
		compact, err := signer.Sign(proof.Binding{
			Version:     options.VersionNumber(),
			Transport:   proof.TransportGRPC,
			Operation:   method,
			Method:      "POST",
			TargetURI:   targetURI,
			RequestHash: requestDigest,
			BindToken:   false,
		}, issuedAt)
		if err != nil {
			return fmt.Errorf("motiveiq: credentials: sign STS request: %w", err)
		}
		ctx, err = withExclusiveOutgoingMetadata(ctx, "dpop", compact)
		if err != nil {
			return fmt.Errorf("motiveiq: credentials: STS proof metadata: %w", err)
		}
		return invoker(ctx, method, wireRequest, reply, cc, append(opts, wireOptions...)...)
	}
}

func (p *SessionCredentials) validateGeneration(token string, expiresAt time.Time, tokenType iamv1.SessionTokenType, thumbprint string, signer *proof.Signer) (*credentialGeneration, error) {
	thumbprint = strings.TrimSpace(thumbprint)
	switch tokenType {
	case iamv1.SessionTokenType_SESSION_TOKEN_TYPE_PROOF_OF_POSSESSION:
		if signer == nil {
			return nil, fmt.Errorf("motiveiq: credentials: STS returned a proof-bound token without a requested proof key")
		}
		if thumbprint == "" || thumbprint != signer.Thumbprint() {
			return nil, fmt.Errorf("motiveiq: credentials: STS proof key thumbprint does not match the requested key")
		}
		return &credentialGeneration{
			token:     token,
			signer:    signer,
			expiresAt: expiresAt,
		}, nil

	case iamv1.SessionTokenType_SESSION_TOKEN_TYPE_UNSPECIFIED,
		iamv1.SessionTokenType_SESSION_TOKEN_TYPE_BEARER:
		return nil, fmt.Errorf("motiveiq: credentials: STS did not return the required proof-bound session token")

	default:
		return nil, fmt.Errorf("motiveiq: credentials: STS returned unsupported session token type %d", tokenType)
	}
}

// Run keeps the session warm until ctx is canceled: it refreshes ahead of
// the refresh point instead of imposing the exchange latency on the first
// unlucky Token caller. It is optional — Token alone is fully correct — and
// is the only place the provider runs a goroutine on the caller's behalf.
// Call it from your own goroutine:
//
//	go creds.Run(ctx)
func (p *SessionCredentials) Run(ctx context.Context) {
	for {
		_, _ = p.Token(ctx) // refresh if due; errors already paced by backoff
		p.mu.Lock()
		now := p.now()
		var wait time.Duration
		switch {
		case p.generation != nil && now.Before(p.generation.expiresAt) && now.Before(p.generation.refreshAt):
			wait = p.generation.refreshAt.Sub(now)
		case now.Before(p.retryAt):
			wait = p.retryAt.Sub(now)
		default:
			wait = runMinWait
		}
		p.mu.Unlock()
		if wait < runMinWait {
			wait = runMinWait
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
