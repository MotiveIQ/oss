package transport

import (
	"context"
	"fmt"

	"go.motiveiq.dev/platform/iam/internal/proof"
	"google.golang.org/grpc/metadata"
)

func EnsureNoOutgoingAuthentication(ctx context.Context) error {
	md, _ := metadata.FromOutgoingContext(ctx)
	for _, key := range []string{"authorization", "dpop", proof.DelegationTokenMetadata, proof.DelegationTokenDigestMetadata, DelegationSubjectMetadata} {
		if len(md.Get(key)) != 0 {
			return fmt.Errorf("motiveiq: outgoing %s metadata conflicts with SDK authentication", key)
		}
	}
	return nil
}
