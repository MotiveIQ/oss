// Package resourceurn translates the two platform namespace spellings. Only
// callers that own a URN-valued field should apply these functions.
package resourceurn

import "strings"

const (
	Prefix       = "urn:iq:"
	LegacyPrefix = "urn:motiveiq:"
)

// Canonical changes only the namespace. The rest of the identifier is opaque.
func Canonical(value string) string {
	if tail, ok := strings.CutPrefix(value, LegacyPrefix); ok {
		return Prefix + tail
	}
	return value
}

// Legacy reproduces identifiers used in existing storage and authenticated data.
func Legacy(value string) string {
	if tail, ok := strings.CutPrefix(value, Prefix); ok {
		return LegacyPrefix + tail
	}
	return value
}

// Current gives the platform representation used for issuance, storage and
// policy compilation.
func Current(value string) string { return Canonical(value) }

// IsAttribute identifies service conditions whose documented value is a
// platform resource identity. Free-form tags, object keys and subjects are opaque.
func IsAttribute(key string) bool {
	switch key {
	case "secretsmanager:KmsKeyUrn", "kms:EncryptionContext:SecretURN", "kms:RequestAlias", "kms:ReEncryptSourceKey", "kms:ReEncryptDestinationKey":
		return true
	}
	return false
}
