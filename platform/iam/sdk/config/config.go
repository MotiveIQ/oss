// Package config resolves shared profiles and external web identities for SDK clients.
// Loading configuration and retrieving tokens never starts interactive login
// or interprets identity-provider claims.
package config

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	motiveiq "go.motiveiq.dev/platform/iam/sdk"
	"google.golang.org/grpc/credentials"
)

const DefaultSTSEndpoint = "api.motiveiq.net:443"

// Load resolves the selected profile or environment identity. Applications may
// use Resolver to register additional sources.
func Load(ctx context.Context, role string, options ...motiveiq.Option) (*motiveiq.Config, error) {
	return (Resolver{}).Load(ctx, role, options...)
}

func (r Resolver) Load(ctx context.Context, role string, options ...motiveiq.Option) (*motiveiq.Config, error) {
	identity, err := r.Resolve(role)
	if err != nil {
		return nil, err
	}
	return LoadIdentity(ctx, identity, options...)
}

// LoadIdentity composes a resolved source with the SDK's normal STS session
// provider. No token is retrieved until the first authenticated operation.
func LoadIdentity(ctx context.Context, identity Identity, options ...motiveiq.Option) (*motiveiq.Config, error) {
	if identity.RoleURN == "" || identity.Provider == nil {
		return nil, fmt.Errorf("a role and web identity source are required")
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if path := os.Getenv("SSL_CERT_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read TLS trust bundle: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("TLS trust bundle contains no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	endpoint := identity.STSEndpoint
	if endpoint == "" {
		endpoint = DefaultSTSEndpoint
	}
	base := []motiveiq.Option{
		motiveiq.WithRoleURN(identity.RoleURN),
		motiveiq.WithWebIdentityTokenFile(""),
		motiveiq.WithWebIdentityTokenProvider(identity.Provider),
		motiveiq.WithSTSEndpoint(endpoint),
		motiveiq.WithSTSProofOrigin(identity.STSProofOrigin),
		motiveiq.WithSessionName(identity.SessionName),
		motiveiq.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		motiveiq.WithClientTransportCredentials(credentials.NewTLS(tlsConfig.Clone())),
	}
	return motiveiq.LoadDefaultConfig(ctx, append(base, options...)...)
}
