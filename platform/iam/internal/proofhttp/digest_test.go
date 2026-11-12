package proofhttp_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"go.motiveiq.dev/platform/iam/internal/proofhttp"
)

func TestContentDigestRoundTrip(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("exact body bytes\n"))
	field := proofhttp.FormatContentDigest(digest)
	want := "sha-256=:" + base64.StdEncoding.EncodeToString(digest[:]) + ":"
	if field != want {
		t.Fatalf("FormatContentDigest = %q, want %q", field, want)
	}
	parsed, err := proofhttp.ParseContentDigest(field)
	if err != nil {
		t.Fatalf("ParseContentDigest: %v", err)
	}
	if parsed != digest {
		t.Errorf("parsed digest = %x, want %x", parsed, digest)
	}
}

func TestParseContentDigestRejectsMalformedValues(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("body"))
	valid := proofhttp.FormatContentDigest(digest)
	rawURL := base64.RawURLEncoding.EncodeToString(digest[:])
	for _, value := range []string{
		"",
		"SHA-256" + strings.TrimPrefix(valid, "sha-256"),
		"sha-512" + strings.TrimPrefix(valid, "sha-256"),
		strings.TrimSuffix(valid, ":"),
		strings.Replace(valid, "=:", "=", 1),
		"sha-256=:" + rawURL + ":",
		"sha-256=:YWJj:",
		valid + ", sha-512=:YWJj:",
		" " + valid,
		valid + " ",
		strings.Replace(valid, "=:", "==:", 1),
	} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := proofhttp.ParseContentDigest(value); !errors.Is(err, proofhttp.ErrInvalidContentDigest) {
				t.Errorf("ParseContentDigest(%q) error = %v, want ErrInvalidContentDigest", value, err)
			}
		})
	}
}
