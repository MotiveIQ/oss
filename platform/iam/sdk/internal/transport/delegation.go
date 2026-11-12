package transport

import (
	"context"
	"time"

	"github.com/MotiveIQ/public/platform/iam/internal/proof"
	"google.golang.org/protobuf/proto"
)

// DelegationSubjectMetadata is a retired envelope marker. Reject it on ordinary requests.
const DelegationSubjectMetadata = "motiveiq-delegation-subject"

type outgoingDelegationKey struct{}

// OutgoingDelegation binds one invocation to its independently issued credential
// and frozen request bytes. It carries no inbound authentication or PDP assertions.
type OutgoingDelegation struct {
	Method, Origin, Token string
	Signer                *proof.Signer
	ExpiresAt             time.Time
	Request               proto.Message
	Payload               []byte
}

func WithOutgoingDelegation(ctx context.Context, d *OutgoingDelegation) context.Context {
	return context.WithValue(ctx, outgoingDelegationKey{}, d)
}
func DelegationFromContext(ctx context.Context) (*OutgoingDelegation, bool) {
	d, ok := ctx.Value(outgoingDelegationKey{}).(*OutgoingDelegation)
	return d, ok
}
