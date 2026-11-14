package motiveiq

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// WebIdentityTokenProvider returns the current OIDC credential exchanged at
// STS. The SDK calls it for every exchange so short-lived human and workload
// credentials may rotate independently of the resulting IAM session.
type WebIdentityTokenProvider interface {
	RetrieveWebIdentityToken(context.Context) (string, error)
}

// WebIdentityTokenProviderFunc adapts a function to WebIdentityTokenProvider.
type WebIdentityTokenProviderFunc func(context.Context) (string, error)

// RetrieveWebIdentityToken implements WebIdentityTokenProvider.
func (f WebIdentityTokenProviderFunc) RetrieveWebIdentityToken(ctx context.Context) (string, error) {
	if f == nil {
		return "", fmt.Errorf("web identity token provider function is nil")
	}
	return f(ctx)
}

// WithWebIdentityTokenProvider supplies a dynamic web-identity source. It
// takes precedence over IQ_WEB_IDENTITY_TOKEN_FILE and
// WithWebIdentityTokenFile, allowing non-Kubernetes callers such as IQ to use
// the same proof-aware SessionCredentials implementation without writing an
// OAuth token to a temporary file.
func WithWebIdentityTokenProvider(provider WebIdentityTokenProvider) Option {
	return func(c *Config) { c.webIdentityTokenProvider = provider }
}

type webIdentityTokenFileProvider string

func (p webIdentityTokenFileProvider) RetrieveWebIdentityToken(_ context.Context) (string, error) {
	raw, err := os.ReadFile(string(p))
	if err != nil {
		return "", fmt.Errorf("read %s: %w", p, err)
	}
	web := strings.TrimSpace(string(raw))
	if web == "" {
		return "", fmt.Errorf("file %s is empty", p)
	}
	return web, nil
}
