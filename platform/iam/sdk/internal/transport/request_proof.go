package transport

import (
	"fmt"

	"go.motiveiq.dev/platform/iam/internal/proof"
)

// ProofVersion selects a transport-independent request-proof profile.
type ProofVersion int

const ProofV3 ProofVersion = proof.Version3

// RequestProofOptions controls signing for one destination. Zero Version means v3.
// SignedMetadata lists required singleton ASCII gRPC metadata fields or HTTP
// headers. Both peers configure the same set. Values are compared exactly;
// surrounding whitespace is rejected. Metadata binding requires v3. An
// authentication failure never triggers a retry with another profile.
type RequestProofOptions struct {
	Version        ProofVersion
	SignedMetadata []string
}

func CopyProofOptions(options RequestProofOptions) RequestProofOptions {
	options.SignedMetadata = append([]string(nil), options.SignedMetadata...)
	return options
}

func (options RequestProofOptions) VersionNumber() int {
	if options.Version == 0 {
		return proof.ProtocolVersion
	}
	return int(options.Version)
}

func (options RequestProofOptions) Validate() error {
	if !proof.SupportedVersion(options.VersionNumber()) {
		return fmt.Errorf("unsupported request proof version %d", options.Version)
	}
	fields := make(map[string]string, len(options.SignedMetadata))
	for _, name := range options.SignedMetadata {
		if _, exists := fields[name]; exists {
			return fmt.Errorf("duplicate signed metadata field %q", name)
		}
		fields[name] = ""
	}
	return proof.ValidateMetadata(fields)
}
