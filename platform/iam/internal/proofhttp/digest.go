package proofhttp

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidContentDigest reports a Content-Digest value outside the
	// canonical single-algorithm RFC 9530 profile used by MotiveIQ.
	ErrInvalidContentDigest = errors.New("proofhttp: invalid Content-Digest")
)

const (
	contentDigestPrefix = "sha-256=:"
	contentDigestSuffix = ":"
)

// FormatContentDigest serializes a SHA-256 digest as the canonical RFC 9530
// Content-Digest field used by the MotiveIQ HTTP proof profile.
func FormatContentDigest(digest [sha256.Size]byte) string {
	return contentDigestPrefix + base64.StdEncoding.EncodeToString(digest[:]) + contentDigestSuffix
}

// ParseContentDigest parses the canonical single-member
// "sha-256=:base64:" profile. Rejecting alternate spellings and additional
// dictionary members leaves one value for proof comparison and forwarding.
func ParseContentDigest(value string) ([sha256.Size]byte, error) {
	var digest [sha256.Size]byte
	if !strings.HasPrefix(value, contentDigestPrefix) || !strings.HasSuffix(value, contentDigestSuffix) {
		return digest, ErrInvalidContentDigest
	}
	encoded := value[len(contentDigestPrefix) : len(value)-len(contentDigestSuffix)]
	decoded, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(decoded) != sha256.Size {
		return digest, fmt.Errorf("%w: malformed SHA-256 byte sequence", ErrInvalidContentDigest)
	}
	copy(digest[:], decoded)
	if FormatContentDigest(digest) != value {
		return [sha256.Size]byte{}, fmt.Errorf("%w: non-canonical serialization", ErrInvalidContentDigest)
	}
	return digest, nil
}
