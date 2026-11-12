package motiveiq

import (
	"fmt"
	"net/http"
	"time"

	sdktransport "github.com/MotiveIQ/public/platform/iam/sdk/internal/transport"

	"github.com/MotiveIQ/public/platform/iam/internal/proof"
	"github.com/MotiveIQ/public/platform/iam/internal/proofhttp"
)

// HTTPOperationResolver derives the logical REST operation from trusted
// server routing state and the request. Client and server must use equivalent
// resolvers. A nil resolver uses the exact escaped URL path without its query.
type HTTPOperationResolver func(*http.Request) (string, error)

// HTTPClientAuthenticationOptions configures an authenticated HTTP transport.
// Origin is trusted service configuration. MaxBodyBytes is an explicit bound
// for proof-signed bodies; zero permits only empty bodies.
type HTTPClientAuthenticationOptions struct {
	Proof RequestProofOptions
	// Base performs one transport attempt. Semantic retry middleware must wrap
	// the authenticated RoundTripper returned by NewAuthenticatedRoundTripper,
	// so every retry re-enters the signer and receives a fresh proof ID.
	Base              http.RoundTripper
	Credentials       *SessionCredentials
	Origin            string
	MaxBodyBytes      int64
	OperationResolver HTTPOperationResolver
}

type authenticatedRoundTripper struct {
	proofOptions RequestProofOptions
	base         http.RoundTripper
	credentials  *SessionCredentials
	canonical    *proofhttp.Canonicalizer
	operation    HTTPOperationResolver
	maxBodyBytes int64
}

// NewAuthenticatedRoundTripper returns an HTTP transport that obtains one
// immutable proof-bound SessionCredentials generation per request, uses the
// DPoP authorization scheme, adds a fresh DPoP proof, and adds a canonical
// Content-Digest over the exact transmitted bytes.
func NewAuthenticatedRoundTripper(options HTTPClientAuthenticationOptions) (http.RoundTripper, error) {
	if err := options.Proof.Validate(); err != nil {
		return nil, err
	}
	if err := sdktransport.ValidateHTTPMetadata(options.Proof.SignedMetadata); err != nil {
		return nil, err
	}
	if options.Credentials == nil {
		return nil, fmt.Errorf("motiveiq: HTTP client authentication: credentials are required")
	}
	canonical, err := proofhttp.New(proofhttp.Config{
		Origin:       options.Origin,
		MaxBodyBytes: options.MaxBodyBytes,
	})
	if err != nil {
		return nil, fmt.Errorf("motiveiq: HTTP client authentication: %w", err)
	}
	base := options.Base
	if base == nil {
		base = defaultSingleAttemptTransport()
	}
	operation := options.OperationResolver
	if operation == nil {
		operation = sdktransport.EscapedPathOperation
	}
	return &authenticatedRoundTripper{
		proofOptions: sdktransport.CopyProofOptions(options.Proof),
		base:         base,
		credentials:  options.Credentials,
		canonical:    canonical,
		operation:    operation,
		maxBodyBytes: options.MaxBodyBytes,
	}, nil
}

func (t *authenticatedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil {
		return nil, fmt.Errorf("motiveiq: HTTP client authentication: nil request")
	}
	if req.URL == nil || req.URL.Scheme == "" || req.URL.Host == "" {
		return nil, fmt.Errorf("motiveiq: HTTP client authentication: request URL must be absolute")
	}
	if err := ensureExclusiveHTTPHeaders(req.Header); err != nil {
		return nil, err
	}
	if _, err := t.canonical.RequestTarget(req); err != nil {
		return nil, fmt.Errorf("motiveiq: HTTP client authentication: validate request target: %w", err)
	}
	generation, err := t.credentials.retrieve(req.Context())
	if err != nil {
		return nil, err
	}

	if generation == nil || generation.signer == nil {
		return nil, fmt.Errorf("motiveiq: HTTP client authentication: credentials are not proof-bound")
	}
	request, err := cloneProofHTTPRequest(req, t.maxBodyBytes)
	if err != nil {
		return nil, fmt.Errorf("motiveiq: HTTP client authentication: clone request body: %w", err)
	}
	operation, err := t.operation(request)
	if err != nil {
		return nil, fmt.Errorf("motiveiq: HTTP client authentication: resolve operation: %w", err)
	}
	canonical, err := t.canonical.Canonicalize(request, proofhttp.RequestOptions{
		Operation:   operation,
		AccessToken: generation.token,
		BindToken:   true,
	})
	if err != nil {
		return nil, fmt.Errorf("motiveiq: HTTP client authentication: canonicalize request: %w", err)
	}
	canonical.Binding.Version = t.proofOptions.VersionNumber()
	canonical.Binding.Metadata, err = sdktransport.SignedHTTPMetadata(request.Header, t.proofOptions.SignedMetadata)
	if err != nil {
		return nil, err
	}
	issuedAt := t.credentials.now()
	expiresAt := issuedAt.UTC().Truncate(time.Second).Add(proof.MaxLifetime)
	if generation.expiresAt.Before(expiresAt) {
		expiresAt = generation.expiresAt
	}
	compact, err := generation.signer.SignUntil(canonical.Binding, issuedAt, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("motiveiq: HTTP client authentication: sign request proof: %w", err)
	}
	request.Header.Set("Authorization", "DPoP "+generation.token)
	request.Header.Set("DPoP", compact)
	request.Header.Set("Content-Digest", canonical.ContentDigest)
	return t.base.RoundTrip(request)
}

func ensureExclusiveHTTPHeaders(header http.Header) error {
	for _, name := range []string{"Authorization", "DPoP", "Content-Digest", proof.DelegationTokenMetadata, proof.DelegationTokenDigestMetadata, sdktransport.DelegationSubjectMetadata} {
		if len(sdktransport.HeaderValues(header, name)) != 0 {
			return fmt.Errorf("motiveiq: HTTP client authentication: existing %s header conflicts with SDK authentication", name)
		}
	}
	return nil
}

// defaultSingleAttemptTransport avoids net/http's transparent retry path by
// never reusing a connection. Callers that provide Base must likewise provide
// a one-attempt RoundTripper; semantic retry middleware belongs outside the
// authenticated transport so every attempt receives a fresh proof.
func defaultSingleAttemptTransport() http.RoundTripper {
	if transport, ok := http.DefaultTransport.(*http.Transport); ok {
		clone := transport.Clone()
		clone.DisableKeepAlives = true
		return clone
	}
	return http.DefaultTransport
}

func cloneProofHTTPRequest(req *http.Request, maxBodyBytes int64) (*http.Request, error) {
	request := req.Clone(req.Context())
	request.Header = req.Header.Clone()
	if request.Header == nil {
		request.Header = make(http.Header)
	}
	if req.Body == nil || req.Body == http.NoBody {
		return request, nil
	}
	if req.GetBody == nil {
		if _, err := proofhttp.ReadAndRestoreBody(req, maxBodyBytes); err != nil {
			return nil, err
		}
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	request.Body = body
	request.GetBody = req.GetBody
	return request, nil
}
