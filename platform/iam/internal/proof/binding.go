package proof

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Transport identifies the adapter that defines the request payload boundary.
// A proof is valid for exactly one transport, so a REST proof cannot be reused
// for a gRPC request with otherwise identical fields.
type Transport string

const (
	TransportGRPC Transport = "grpc"
	TransportHTTP Transport = "http"
)

// Binding is the transport-independent input to proof signing and
// verification. Transport adapters derive every field from trusted request
// state; callers must never copy these values out of an untrusted proof.
//
// RequestHash is SHA-256 over the adapter payload (exact bytes in v3). When
// BindToken is true, TokenHash is SHA-256 over the exact session-token string
// carried on the same request. Keeping only the digest here prevents a typed
// Authentication value from retaining the raw credential.
type Binding struct {
	// Version defaults to V3. Adapters must supply the digest of the exact
	// payload bytes and the configured set of signed application metadata.
	Version     int
	Transport   Transport
	Operation   string
	Method      string
	TargetURI   string
	RequestHash [sha256.Size]byte
	BindToken   bool
	TokenHash   [sha256.Size]byte
	Nonce       string
	Metadata    map[string]string
}

func (b Binding) version() int {
	if b.Version == 0 {
		return ProtocolVersion
	}
	return b.Version
}

const (
	maxOperationLength = 1024
	maxMethodLength    = 32
	maxTargetURILength = 4096
	maxNonceLength     = 1024
)

// Digest returns the SHA-256 digest of data in the representation Binding
// expects. Transport adapters use it for request content and session tokens.
func Digest(data []byte) [sha256.Size]byte { return sha256.Sum256(data) }

func validateBinding(b Binding) error {
	if !SupportedVersion(b.version()) {
		return fmt.Errorf("%w: unsupported version", ErrBinding)
	}
	if err := ValidateMetadata(b.Metadata); err != nil {
		return err
	}
	// The receiving adapter supplies its expected protocol identifier. A
	// well-formed new identifier is not an automatic adapter registration.
	name := string(b.Transport)
	if len(name) == 0 || len(name) > 64 || name[0] < 'a' || name[0] > 'z' {
		return fmt.Errorf("%w: invalid transport identifier", ErrBinding)
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return fmt.Errorf("%w: invalid transport identifier", ErrBinding)
		}
	}
	for _, field := range []struct {
		name  string
		value string
		limit int
	}{
		{"operation", b.Operation, maxOperationLength},
		{"method", b.Method, maxMethodLength},
		{"target URI", b.TargetURI, maxTargetURILength},
	} {
		if !utf8.ValidString(field.value) {
			return fmt.Errorf("%w: %s is not UTF-8", ErrBinding, field.name)
		}
		if field.value == "" {
			return fmt.Errorf("%w: %s is empty", ErrBinding, field.name)
		}
		if len(field.value) > field.limit {
			return fmt.Errorf("%w: %s exceeds %d bytes", ErrBinding, field.name, field.limit)
		}
	}
	if len(b.Nonce) > maxNonceLength {
		return fmt.Errorf("%w: nonce exceeds %d bytes", ErrBinding, maxNonceLength)
	}
	if !utf8.ValidString(b.Nonce) {
		return fmt.Errorf("%w: nonce is not UTF-8", ErrBinding)
	}
	var zeroDigest [sha256.Size]byte
	if b.RequestHash == zeroDigest {
		return fmt.Errorf("%w: request hash is unset", ErrBinding)
	}
	if b.BindToken && b.TokenHash == zeroDigest {
		return fmt.Errorf("%w: access-token hash is unset", ErrBinding)
	}
	if !b.BindToken && b.TokenHash != zeroDigest {
		return fmt.Errorf("%w: access-token hash is set without token binding", ErrBinding)
	}
	return nil
}

// ValidateMetadata bounds the v3 singleton ASCII application-metadata profile.
// Adapters additionally reject their transport-managed metadata names.
func ValidateMetadata(metadata map[string]string) error {
	if len(metadata) > 16 {
		return fmt.Errorf("%w: too many metadata fields", ErrBinding)
	}
	total := 0
	for name, value := range metadata {
		if len(name) == 0 || len(name) > 64 {
			return fmt.Errorf("%w: invalid metadata name", ErrBinding)
		}
		switch name {
		case "authorization", "dpop":
			return fmt.Errorf("%w: reserved metadata name", ErrBinding)
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
				return fmt.Errorf("%w: metadata name must be lowercase ASCII", ErrBinding)
			}
		}
		if value != strings.TrimSpace(value) {
			return fmt.Errorf("%w: metadata value has surrounding whitespace", ErrBinding)
		}
		if len(value) > 1024 {
			return fmt.Errorf("%w: metadata value too long", ErrBinding)
		}
		for _, c := range value {
			if c < 0x20 || c > 0x7e {
				return fmt.Errorf("%w: metadata value must be printable ASCII", ErrBinding)
			}
		}
		total += len(name) + len(value)
	}
	if total > 4096 {
		return fmt.Errorf("%w: metadata too large", ErrBinding)
	}
	return nil
}

// ValidateApplicationMetadataNames is the shared configuration vocabulary for
// transport adapters and delegation contracts. Reserved delegation fields are
// added only by a delegated adapter, never by application configuration.
func ValidateApplicationMetadataNames(transport Transport, names []string) error {
	if transport != TransportGRPC && transport != TransportHTTP {
		return fmt.Errorf("%w: unsupported metadata transport", ErrBinding)
	}
	fields := make(map[string]string, len(names))
	for _, name := range names {
		if name == DelegationTokenMetadata || name == DelegationTokenDigestMetadata || name == "motiveiq-delegation-subject" {
			return fmt.Errorf("%w: reserved delegation metadata", ErrBinding)
		}
		if _, exists := fields[name]; exists {
			return fmt.Errorf("%w: duplicate metadata name", ErrBinding)
		}
		fields[name] = ""
		switch transport {
		case TransportGRPC:
			if strings.HasPrefix(name, "grpc-") || strings.HasSuffix(name, "-bin") {
				return fmt.Errorf("%w: unsupported gRPC signed metadata %q", ErrBinding, name)
			}
			switch name {
			case "content-type", "te", "user-agent":
				return fmt.Errorf("%w: transport-owned gRPC metadata %q", ErrBinding, name)
			}
		case TransportHTTP:
			switch name {
			case "host", "content-digest", "content-length", "connection", "transfer-encoding", "trailer", "upgrade", "te", "proxy-authorization", "proxy-authenticate":
				return fmt.Errorf("%w: transport-owned HTTP metadata %q", ErrBinding, name)
			}
		}
	}
	return ValidateMetadata(fields)
}

// Reserved delegation envelope metadata. Ordinary authentication adapters must
// reject either marker; a delegated adapter must validate both and sign only
// the digest in v3 Metadata. These are never configurable application fields.
const DelegationTokenMetadata = "motiveiq-delegation-token"
const DelegationTokenDigestMetadata = "motiveiq-delegation-token-sha256"
