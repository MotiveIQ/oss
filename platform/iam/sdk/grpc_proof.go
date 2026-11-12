package motiveiq

import (
	sdktransport "go.motiveiq.dev/platform/iam/sdk/internal/transport"
)

// WithServiceGRPCProof selects the sending profile for one SDK service key.
// It defaults to v3; every replica of the destination must support it.
func WithServiceGRPCProof(serviceKey string, options RequestProofOptions) Option {
	options = sdktransport.CopyProofOptions(options)
	return func(c *Config) { c.serviceGRPCProof[serviceKey] = sdktransport.CopyProofOptions(options) }
}

// WithSTSGRPCProof selects the STS issuance profile; it defaults to v3.
func WithSTSGRPCProof(options RequestProofOptions) Option {
	options = sdktransport.CopyProofOptions(options)
	return func(c *Config) { c.stsGRPCProof = sdktransport.CopyProofOptions(options) }
}
