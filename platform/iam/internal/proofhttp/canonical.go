// Package proofhttp implements the HTTP transport adapter for MotiveIQ
// request proofs. It derives every signed request value from a configured
// HTTPS origin and the request itself; Host and forwarding headers are never
// authentication inputs.
package proofhttp

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/MotiveIQ/public/platform/iam/internal/proof"
)

var (
	// ErrInvalidOrigin reports a configured origin that is not a bare HTTPS
	// origin.
	ErrInvalidOrigin = errors.New("proofhttp: invalid HTTPS origin")
	// ErrCrossOrigin reports an absolute client request URL whose origin does
	// not match the configured trusted origin.
	ErrCrossOrigin = errors.New("proofhttp: cross-origin request URL")
	// ErrInvalidRequest reports a request that cannot be represented by the
	// HTTP proof profile.
	ErrInvalidRequest = errors.New("proofhttp: invalid request")
	// ErrInvalidMethod reports an empty, non-token, or non-uppercase method.
	ErrInvalidMethod = errors.New("proofhttp: HTTP method must be an uppercase token")
	// ErrInvalidBodyLimit reports a negative or overflowing body bound.
	ErrInvalidBodyLimit = errors.New("proofhttp: invalid body limit")
)

// Config fixes the trusted, service-level values used by both a client
// RoundTripper and server middleware. MaxBodyBytes is an explicit bound; zero
// permits only empty bodies.
type Config struct {
	Origin       string
	MaxBodyBytes int64
}

// RequestOptions supplies the per-route values used to construct a proof
// binding. AccessToken is hashed immediately and is never retained in the
// returned CanonicalRequest. BindToken is false for an issuance request and
// true for a protected request presenting a session token.
type RequestOptions struct {
	Operation   string
	AccessToken string
	BindToken   bool
	Nonce       string
}

// CanonicalRequest is the authenticated HTTP meaning of one request.
// ContentDigest is the canonical RFC 9530 field value that a client emits and
// a server compares to the independently read request body.
type CanonicalRequest struct {
	Binding       proof.Binding
	ContentDigest string
	BodySize      int64
}

// Canonicalizer is immutable after construction and safe for concurrent use.
type Canonicalizer struct {
	origin       string
	maxBodyBytes int64
}

// New validates config and returns an HTTP request canonicalizer.
func New(config Config) (*Canonicalizer, error) {
	origin, err := NormalizeOrigin(config.Origin)
	if err != nil {
		return nil, err
	}
	if config.MaxBodyBytes < 0 || config.MaxBodyBytes == math.MaxInt64 {
		return nil, fmt.Errorf("%w: %d", ErrInvalidBodyLimit, config.MaxBodyBytes)
	}
	return &Canonicalizer{
		origin:       origin,
		maxBodyBytes: config.MaxBodyBytes,
	}, nil
}

// Canonicalize reads and restores req.Body, then constructs the HTTP proof
// binding. For an absolute client URL, the URL origin must match the configured
// origin. For an origin-form server URL, the configured origin is used without
// consulting req.Host, Forwarded, or X-Forwarded-* headers.
func (c *Canonicalizer) Canonicalize(req *http.Request, options RequestOptions) (CanonicalRequest, error) {
	if options.Operation == "" || strings.TrimSpace(options.Operation) != options.Operation {
		return CanonicalRequest{}, fmt.Errorf("%w: operation must be non-empty and canonical", ErrInvalidRequest)
	}
	if options.BindToken && options.AccessToken == "" {
		return CanonicalRequest{}, fmt.Errorf("%w: bound request has an empty access token", ErrInvalidRequest)
	}
	if !options.BindToken && options.AccessToken != "" {
		return CanonicalRequest{}, fmt.Errorf("%w: unbound request includes an access token", ErrInvalidRequest)
	}

	targetURI, err := c.RequestTarget(req)
	if err != nil {
		return CanonicalRequest{}, err
	}
	body, err := ReadAndRestoreBody(req, c.maxBodyBytes)
	if err != nil {
		return CanonicalRequest{}, err
	}
	bodyDigest := proof.Digest(body)
	binding := proof.Binding{
		Transport:   proof.TransportHTTP,
		Operation:   options.Operation,
		Method:      req.Method,
		TargetURI:   targetURI,
		RequestHash: bodyDigest,
		BindToken:   options.BindToken,
		Nonce:       options.Nonce,
	}
	if options.BindToken {
		binding.TokenHash = proof.Digest([]byte(options.AccessToken))
	}
	return CanonicalRequest{
		Binding:       binding,
		ContentDigest: FormatContentDigest(bodyDigest),
		BodySize:      int64(len(body)),
	}, nil
}

// RequestTarget validates the method and request URL and returns the canonical
// target URI without reading or changing the request body. Proof-only client
// transports call it before acquiring credentials or signing so no session
// token or proof can be attached to a cross-origin request.
func (c *Canonicalizer) RequestTarget(req *http.Request) (string, error) {
	if c == nil || c.origin == "" {
		return "", fmt.Errorf("%w: canonicalizer is not initialized", ErrInvalidRequest)
	}
	if req == nil {
		return "", fmt.Errorf("%w: nil HTTP request", ErrInvalidRequest)
	}
	if err := validateMethod(req.Method); err != nil {
		return "", err
	}
	return c.targetURI(req.URL)
}

func (c *Canonicalizer) targetURI(requestURL *url.URL) (string, error) {
	if requestURL == nil {
		return "", fmt.Errorf("%w: nil request URL", ErrInvalidRequest)
	}
	if requestURL.Opaque != "" || requestURL.User != nil || requestURL.Fragment != "" || requestURL.RawFragment != "" {
		return "", fmt.Errorf("%w: unsupported request URL form", ErrInvalidRequest)
	}
	hasScheme, hasHost := requestURL.Scheme != "", requestURL.Host != ""
	if hasScheme != hasHost {
		return "", fmt.Errorf("%w: request URL has only one of scheme and host", ErrCrossOrigin)
	}
	if hasScheme {
		requestOrigin, err := NormalizeOrigin(requestURL.Scheme + "://" + requestURL.Host)
		if err != nil {
			return "", fmt.Errorf("%w: %v", ErrCrossOrigin, err)
		}
		if requestOrigin != c.origin {
			return "", fmt.Errorf("%w: got %q, want %q", ErrCrossOrigin, requestOrigin, c.origin)
		}
	}

	escapedPath := requestURL.EscapedPath()
	if escapedPath == "" {
		escapedPath = "/"
	}
	targetURI := c.origin + escapedPath
	if requestURL.RawQuery != "" || requestURL.ForceQuery {
		targetURI += "?" + requestURL.RawQuery
	}
	return targetURI, nil
}

// NormalizeOrigin validates a trusted origin and returns its canonical form.
// It accepts only https://host[:port] with no credentials, path, query, or
// fragment. Host names are lowercased, IP literals are canonicalized, and the
// default HTTPS port is removed.
func NormalizeOrigin(raw string) (string, error) {
	if raw == "" || raw != strings.TrimSpace(raw) || strings.Contains(raw, "#") {
		return "", fmt.Errorf("%w: empty, padded, or fragmented value", ErrInvalidOrigin)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidOrigin, err)
	}
	if !strings.EqualFold(u.Scheme, "https") || u.Opaque != "" || u.Host == "" || u.User != nil {
		return "", fmt.Errorf("%w: must be an absolute HTTPS origin without credentials", ErrInvalidOrigin)
	}
	if (u.Path != "" && u.Path != "/") || (u.RawPath != "" && u.EscapedPath() != "/") ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return "", fmt.Errorf("%w: paths, queries, and fragments are not allowed", ErrInvalidOrigin)
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("%w: empty port", ErrInvalidOrigin)
	}

	hostname := u.Hostname()
	if hostname == "" || strings.Contains(hostname, "%") {
		return "", fmt.Errorf("%w: empty hostname or scoped IP literal", ErrInvalidOrigin)
	}
	for i := 0; i < len(hostname); i++ {
		if hostname[i] <= 0x20 || hostname[i] >= 0x7f {
			return "", fmt.Errorf("%w: hostname must be printable ASCII", ErrInvalidOrigin)
		}
	}
	hostname = strings.ToLower(hostname)
	if ip := net.ParseIP(hostname); ip != nil {
		hostname = ip.String()
	}

	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("%w: invalid port %q", ErrInvalidOrigin, port)
		}
		if n == 443 {
			port = ""
		}
	}

	host := hostname
	if strings.Contains(hostname, ":") || port != "" {
		if port == "" {
			host = "[" + hostname + "]"
		} else {
			host = net.JoinHostPort(hostname, port)
		}
	}
	return "https://" + host, nil
}

func validateMethod(method string) error {
	if method == "" || strings.ToUpper(method) != method {
		return ErrInvalidMethod
	}
	for i := 0; i < len(method); i++ {
		c := method[i]
		if !isTokenCharacter(c) {
			return ErrInvalidMethod
		}
	}
	return nil
}

func isTokenCharacter(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))
}
