package transport

import (
	"fmt"

	"google.golang.org/grpc/metadata"

	"go.motiveiq.dev/platform/iam/internal/proof"
)

// ValidateGRPCMetadata excludes transport-owned and binary fields from this adapter.
func ValidateGRPCMetadata(names []string) error {
	return proof.ValidateApplicationMetadataNames(proof.TransportGRPC, names)
}

func SignedGRPCMetadata(md metadata.MD, names []string) (map[string]string, error) {
	fields := make(map[string]string, len(names))
	for _, name := range names {
		values := md.Get(name)
		if len(values) != 1 {
			return nil, fmt.Errorf("signed metadata %q requires exactly one value", name)
		}
		fields[name] = values[0]
	}
	if err := proof.ValidateMetadata(fields); err != nil {
		return nil, err
	}
	return fields, nil
}
