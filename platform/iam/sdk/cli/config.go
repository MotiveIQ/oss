// Package cli shares MotiveIQ credential discovery with native command-line clients.
package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"google.golang.org/grpc/credentials"

	"github.com/MotiveIQ/public/platform/iam/oauth"
	motiveiq "github.com/MotiveIQ/public/platform/iam/sdk"
)

const HumanRole = "urn:motiveiq:iam:role/human"

// Load uses explicitly configured workload identity, otherwise the existing
// human login store. Discovery performs no network I/O or interactive login.
// Callers own the returned config and its refreshable, in-memory sessions.
func Load(ctx context.Context, role string, options ...motiveiq.Option) (*motiveiq.Config, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	// Honor an explicitly configured trust bundle on macOS as well as Linux.
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
	base := []motiveiq.Option{
		motiveiq.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		motiveiq.WithClientTransportCredentials(credentials.NewTLS(tlsConfig.Clone())),
	}
	if strings.TrimSpace(os.Getenv(motiveiq.EnvSTSEndpoint)) == "" {
		base = append(base, motiveiq.WithSTSEndpoint("iam.platform.motiveiq.net:443"))
	}
	if strings.TrimSpace(os.Getenv(motiveiq.EnvWebIdentityTokenFile)) == "" {
		base = append(base, motiveiq.WithWebIdentityTokenProvider(motiveiq.WebIdentityTokenProviderFunc(HumanToken)))
		if role == "" && strings.TrimSpace(os.Getenv(motiveiq.EnvRoleURN)) == "" {
			role = HumanRole
		}
	}
	if role != "" {
		base = append(base, motiveiq.WithRoleURN(role))
	}
	return motiveiq.LoadDefaultConfig(ctx, append(base, options...)...)
}

func HumanToken(ctx context.Context) (string, error) {
	return oauth.AccessTokenFromStore(ctx, oauth.AccessTokenOptions{RequiredAudience: oauth.PlatformAudience, AnyScopes: true})
}
