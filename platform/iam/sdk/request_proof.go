package motiveiq

import sdktransport "go.motiveiq.dev/platform/iam/sdk/internal/transport"

// ProofVersion selects a transport-independent request-proof profile.
type ProofVersion = sdktransport.ProofVersion

const ProofV3 = sdktransport.ProofV3

// RequestProofOptions controls the signing profile and required singleton metadata.
type RequestProofOptions = sdktransport.RequestProofOptions
