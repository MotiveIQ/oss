package motiveiq

import (
	"fmt"

	sdktransport "github.com/MotiveIQ/public/platform/iam/sdk/internal/transport"
	"google.golang.org/grpc"
)

// UnaryClientInterceptor signs unary requests on a caller-owned transport.
// Place it last in the chain and disable gRPC retries so each attempt gets a fresh proof.
func (c *Config) UnaryClientInterceptor(origin string, options RequestProofOptions) (grpc.UnaryClientInterceptor, error) {
	origin, err := validateClientProof(origin, options)
	if err != nil {
		return nil, err
	}
	creds, err := c.Credentials()
	if err != nil {
		return nil, err
	}
	return c.clientRuntime.proofUnaryInterceptor(origin, creds, sdktransport.CopyProofOptions(options)), nil
}

// StreamClientInterceptor authenticates supported streams on a caller-owned
// transport. Place it last in the chain and disable gRPC retries.
func (c *Config) StreamClientInterceptor(serviceKey, origin string, options RequestProofOptions) (grpc.StreamClientInterceptor, error) {
	origin, err := validateClientProof(origin, options)
	if err != nil {
		return nil, err
	}
	creds, err := c.Credentials()
	if err != nil {
		return nil, err
	}
	return c.clientRuntime.proofStreamInterceptor(serviceKey, origin, creds, sdktransport.CopyProofOptions(options)), nil
}
func validateClientProof(origin string, options RequestProofOptions) (string, error) {
	if err := options.Validate(); err != nil {
		return "", err
	}
	if err := sdktransport.ValidateGRPCMetadata(options.SignedMetadata); err != nil {
		return "", err
	}
	normalized, err := normalizeHTTPSOrigin(origin)
	if err != nil {
		return "", fmt.Errorf("motiveiq: request proof origin: %w", err)
	}
	return normalized, nil
}
