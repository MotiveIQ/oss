// Package proof implements MotiveIQ's sender-bound per-request proof format.
// It supplies cryptographic request binding, not exact replay rejection: every
// proof carries a random ID that the PDP's future distributed admission layer
// can enforce, but this cryptographic core deliberately keeps no shared state.
package proof

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"strings"
	"time"
)

const (
	// Version3 binds exact payload bytes and singleton application metadata.
	Version3 = 3
	// ProtocolVersion is the default profile for new proofs.
	ProtocolVersion = Version3
	// MaxLifetime is the largest accepted exp-iat interval. Exact duplicate
	// rejection remains the transport adapter's stateful responsibility.
	MaxLifetime = 30 * time.Second
	// MaxClockSkew permits a caller's whole-second iat to be slightly ahead of
	// the verifier. Expiry itself receives no leeway, so skew cannot extend a
	// proof after its signed expiration.
	MaxClockSkew = 5 * time.Second
	// MaxEncodedSize bounds attacker-controlled compact proofs before parsing.
	MaxEncodedSize = 16 * 1024
	maxHeaderSize  = 2 * 1024
	maxPayloadSize = 10 * 1024
	proofIDBytes   = 16 // 128 random bits; verification accepts at least 96
)

var (
	ErrMalformed = errors.New("proof: malformed")
	ErrHeader    = errors.New("proof: invalid JOSE header")
	ErrJWK       = errors.New("proof: invalid public JWK")
	ErrSignature = errors.New("proof: signature verification failed")
	ErrClaims    = errors.New("proof: invalid claims")
	ErrExpired   = errors.New("proof: expired")
	ErrBinding   = errors.New("proof: request binding mismatch")
)

type wireHeader struct {
	Type      string          `json:"typ"`
	Algorithm string          `json:"alg"`
	JWK       json.RawMessage `json:"jwk"`
}

type signingHeader struct {
	Type      string    `json:"typ"`
	Algorithm string    `json:"alg"`
	JWK       publicJWK `json:"jwk"`
}

type wireClaims struct {
	ID          string             `json:"jti"`
	IssuedAt    int64              `json:"iat"`
	ExpiresAt   int64              `json:"exp"`
	Method      string             `json:"htm"`
	TargetURI   string             `json:"htu"`
	TokenHash   string             `json:"ath,omitempty"`
	Version     int                `json:"mqi_v"`
	Transport   string             `json:"mqi_transport"`
	Operation   string             `json:"mqi_operation"`
	RequestHash string             `json:"mqi_request_hash"`
	Nonce       string             `json:"nonce,omitempty"`
	Metadata    *map[string]string `json:"mqi_metadata,omitempty"`
}

// SupportedVersion is shared by signers, receivers, and delegated PDP evidence.
// Retired profiles are never accepted, including when explicitly configured.
func SupportedVersion(version int) bool { return version == Version3 }

// UnverifiedVersion selects a verification profile only. It authenticates
// nothing; callers must subsequently Verify with that exact expected version.
func UnverifiedVersion(compact string) (int, error) {
	if len(compact) == 0 || len(compact) > MaxEncodedSize {
		return 0, ErrMalformed
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return 0, ErrMalformed
	}
	payload, err := decodeCanonicalBase64URL(parts[1])
	if err != nil || len(payload) > maxPayloadSize {
		return 0, ErrMalformed
	}
	var claims wireClaims
	if err := unmarshalStrict(payload, &claims); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrClaims, err)
	}
	if !SupportedVersion(claims.Version) {
		return 0, fmt.Errorf("%w: unsupported mqi_v", ErrClaims)
	}
	return claims.Version, nil
}

// Verification is the authenticated, server-derived meaning of one proof.
// ProofID is exposed so a transport adapter can pass verified evidence through
// the typed authentication context to the PDP's future distributed admission
// layer.
type Verification struct {
	// PayloadVerified is false only for VerifyCommitment: the signature authenticates
	// a digest commitment, not receipt or inspection of the payload bytes.
	PayloadVerified bool
	ProtocolVersion int
	ProofID         string
	IssuedAt        time.Time
	ExpiresAt       time.Time
	KeyThumbprint   string
	RequestBinding  Binding
}

// Verifier verifies proofs at the time returned by now. Injecting the clock
// keeps validity-boundary tests deterministic. A nil clock uses time.Now.
type Verifier struct {
	now func() time.Time
}

func NewVerifier(now func() time.Time) *Verifier {
	if now == nil {
		now = time.Now
	}
	return &Verifier{now: now}
}

// Sign creates a fresh compact EdDSA JWS over binding with MaxLifetime.
// issuedAt is truncated to whole seconds because NumericDate claims have
// second precision here.
func (s *Signer) Sign(binding Binding, issuedAt time.Time) (string, error) {
	issuedAt = issuedAt.UTC().Truncate(time.Second)
	return s.SignUntil(binding, issuedAt, issuedAt.Add(MaxLifetime))
}

// SignUntil creates a fresh proof whose expiry is no later than expiresAt.
// Transport adapters use it when the bound session expires sooner than
// MaxLifetime, so the proof never claims validity beyond its credential.
func (s *Signer) SignUntil(binding Binding, issuedAt, expiresAt time.Time) (string, error) {
	return s.signUntil(binding, issuedAt, expiresAt)
}

func (s *Signer) signUntil(binding Binding, issuedAt, expiresAt time.Time) (string, error) {
	if s == nil || len(s.private) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("proof: sign: signer is not initialized")
	}
	if err := validateBinding(binding); err != nil {
		return "", err
	}
	if issuedAt.IsZero() {
		return "", fmt.Errorf("%w: issued time is zero", ErrClaims)
	}
	issuedAt = issuedAt.UTC().Truncate(time.Second)
	expiresAt = expiresAt.UTC().Truncate(time.Second)
	if !expiresAt.After(issuedAt) {
		return "", fmt.Errorf("%w: expiry must be after issuance", ErrClaims)
	}
	if expiresAt.Sub(issuedAt) > MaxLifetime {
		return "", fmt.Errorf("%w: lifetime exceeds %s", ErrClaims, MaxLifetime)
	}

	proofID := make([]byte, proofIDBytes)
	s.randomMu.Lock()
	_, err := io.ReadFull(s.random, proofID)
	s.randomMu.Unlock()
	if err != nil {
		return "", fmt.Errorf("proof: generate proof ID: %w", err)
	}

	headerJSON, err := json.Marshal(signingHeader{
		Type:      "dpop+jwt",
		Algorithm: "EdDSA",
		JWK:       s.jwk(),
	})
	if err != nil {
		return "", fmt.Errorf("proof: marshal JOSE header: %w", err)
	}
	claims := wireClaims{
		ID:          rawBase64URL.EncodeToString(proofID),
		IssuedAt:    issuedAt.Unix(),
		ExpiresAt:   expiresAt.Unix(),
		Method:      binding.Method,
		TargetURI:   binding.TargetURI,
		Version:     binding.version(),
		Transport:   string(binding.Transport),
		Operation:   binding.Operation,
		RequestHash: rawBase64URL.EncodeToString(binding.RequestHash[:]),
		Nonce:       binding.Nonce,
	}
	metadata := maps.Clone(binding.Metadata)
	if metadata == nil {
		metadata = map[string]string{}
	}
	claims.Metadata = &metadata
	if binding.BindToken {
		claims.TokenHash = rawBase64URL.EncodeToString(binding.TokenHash[:])
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("proof: marshal claims: %w", err)
	}
	if len(payloadJSON) > maxPayloadSize {
		return "", fmt.Errorf("proof: claims exceed %d bytes", maxPayloadSize)
	}
	headerSegment := rawBase64URL.EncodeToString(headerJSON)
	payloadSegment := rawBase64URL.EncodeToString(payloadJSON)
	signingInput := headerSegment + "." + payloadSegment
	signature := ed25519.Sign(s.private, []byte(signingInput))
	compact := signingInput + "." + rawBase64URL.EncodeToString(signature)
	if len(compact) > MaxEncodedSize {
		return "", fmt.Errorf("proof: encoded proof exceeds %d bytes", MaxEncodedSize)
	}
	return compact, nil
}

// Verify authenticates compact and compares every signed request-binding field
// against expected, which the transport adapter derived independently. It does
// not remember ProofID; exact duplicate rejection belongs to the PDP after it
// authenticates the enforcement point.
func (v *Verifier) Verify(compact string, expected Binding) (Verification, error) {
	return v.verify(compact, expected, false)
}

// VerifyCommitment verifies every request binding except payload equality. Only
// delegation issuance for contracts with no body mappings may use this method.
// The authenticated digest is exposed after signature, freshness and all other
// binding checks. Ordinary receive-side verification must continue using Verify.
func (v *Verifier) VerifyCommitment(compact string, expected Binding) (Verification, error) {
	if expected.RequestHash != ([32]byte{}) {
		return Verification{}, ErrBinding
	}
	expected.RequestHash = Digest(nil) // satisfy shape validation only
	return v.verify(compact, expected, true)
}
func (v *Verifier) verify(compact string, expected Binding, commitmentOnly bool) (Verification, error) {
	if v == nil || v.now == nil {
		return Verification{}, fmt.Errorf("proof: verifier is not initialized")
	}
	if err := validateBinding(expected); err != nil {
		return Verification{}, err
	}
	if compact == "" || len(compact) > MaxEncodedSize {
		return Verification{}, fmt.Errorf("%w: compact proof length", ErrMalformed)
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return Verification{}, fmt.Errorf("%w: compact proof has %d segments", ErrMalformed, len(parts))
	}
	headerJSON, err := decodeCanonicalBase64URL(parts[0])
	if err != nil || len(headerJSON) > maxHeaderSize {
		return Verification{}, fmt.Errorf("%w: header encoding or size", ErrMalformed)
	}
	payloadJSON, err := decodeCanonicalBase64URL(parts[1])
	if err != nil || len(payloadJSON) > maxPayloadSize {
		return Verification{}, fmt.Errorf("%w: payload encoding or size", ErrMalformed)
	}
	signature, err := decodeCanonicalBase64URL(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Verification{}, fmt.Errorf("%w: signature encoding or size", ErrMalformed)
	}

	var header wireHeader
	if err := unmarshalStrict(headerJSON, &header); err != nil {
		return Verification{}, fmt.Errorf("%w: %v", ErrHeader, err)
	}
	if header.Type != "dpop+jwt" {
		return Verification{}, fmt.Errorf("%w: typ must be dpop+jwt", ErrHeader)
	}
	if header.Algorithm != "EdDSA" {
		return Verification{}, fmt.Errorf("%w: alg must be EdDSA", ErrHeader)
	}
	public, thumbprint, err := parsePublicJWK(header.JWK)
	if err != nil {
		return Verification{}, err
	}
	if !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
		return Verification{}, ErrSignature
	}

	var claims wireClaims
	if err := unmarshalStrict(payloadJSON, &claims); err != nil {
		return Verification{}, fmt.Errorf("%w: %v", ErrClaims, err)
	}
	var claimMembers map[string]json.RawMessage
	if err := json.Unmarshal(payloadJSON, &claimMembers); err != nil {
		// unmarshalStrict already parsed the same bytes, so this is defensive.
		return Verification{}, fmt.Errorf("%w: %v", ErrClaims, err)
	}
	if !SupportedVersion(claims.Version) {
		return Verification{}, fmt.Errorf("%w: unsupported mqi_v", ErrClaims)
	}
	for _, name := range []string{"jti", "iat", "exp", "htm", "htu", "mqi_v", "mqi_transport", "mqi_operation", "mqi_request_hash", "mqi_metadata"} {
		value, present := claimMembers[name]
		if !present || string(value) == "null" {
			return Verification{}, fmt.Errorf("%w: missing or null %s", ErrClaims, name)
		}
	}
	// encoding/json matches struct field names case-insensitively. V3's
	// wire names are exact: reject aliases rather than allowing two names
	// with conflicting meanings in another implementation.
	if err := exactMembers(payloadJSON, "jti", "iat", "exp", "htm", "htu", "ath", "mqi_v", "mqi_transport", "mqi_operation", "mqi_request_hash", "nonce", "mqi_metadata"); err != nil {
		return Verification{}, err
	}
	if err := exactMembers(headerJSON, "typ", "alg", "jwk"); err != nil {
		return Verification{}, err
	}
	if err := exactMembers(header.JWK, "kty", "crv", "x"); err != nil {
		return Verification{}, err
	}
	_, tokenHashPresent := claimMembers["ath"]
	_, noncePresent := claimMembers["nonce"]
	_, metadataPresent := claimMembers["mqi_metadata"]

	if !metadataPresent || claims.Metadata == nil || *claims.Metadata == nil {
		return Verification{}, fmt.Errorf("%w: metadata does not match profile", ErrClaims)
	}
	if claims.Metadata != nil {
		var rawMetadata map[string]json.RawMessage
		if err := json.Unmarshal(claimMembers["mqi_metadata"], &rawMetadata); err != nil {
			return Verification{}, ErrClaims
		}
		for _, value := range rawMetadata {
			if len(value) == 0 || value[0] != '"' {
				return Verification{}, fmt.Errorf("%w: metadata values must be strings", ErrClaims)
			}
		}
		if err := ValidateMetadata(*claims.Metadata); err != nil {
			return Verification{}, err
		}
	}
	if err := validateClaims(claims, v.now(), tokenHashPresent, noncePresent); err != nil {
		return Verification{}, err
	}
	if commitmentOnly {
		digest, err := rawBase64URL.DecodeString(claims.RequestHash)
		if err != nil || len(digest) != 32 {
			return Verification{}, ErrClaims
		}
		copy(expected.RequestHash[:], digest)
	}
	if err := compareBinding(claims, expected, tokenHashPresent, noncePresent); err != nil {
		return Verification{}, err
	}
	return Verification{
		PayloadVerified: !commitmentOnly,
		ProtocolVersion: claims.Version,
		ProofID:         claims.ID,
		IssuedAt:        time.Unix(claims.IssuedAt, 0).UTC(),
		ExpiresAt:       time.Unix(claims.ExpiresAt, 0).UTC(),
		KeyThumbprint:   thumbprint,
		RequestBinding:  expected,
	}, nil
}

func validateClaims(c wireClaims, now time.Time, tokenHashPresent, noncePresent bool) error {
	proofID, err := decodeCanonicalBase64URL(c.ID)
	if err != nil || len(proofID) < 12 || len(proofID) > 64 {
		return fmt.Errorf("%w: jti must encode 96 to 512 bits", ErrClaims)
	}
	if !SupportedVersion(c.Version) {
		return fmt.Errorf("%w: unsupported mqi_v", ErrClaims)
	}
	issuedAt := time.Unix(c.IssuedAt, 0)
	expiresAt := time.Unix(c.ExpiresAt, 0)
	if !expiresAt.After(issuedAt) {
		return fmt.Errorf("%w: exp must be after iat", ErrClaims)
	}
	if expiresAt.Sub(issuedAt) > MaxLifetime {
		return fmt.Errorf("%w: lifetime exceeds %s", ErrClaims, MaxLifetime)
	}
	if issuedAt.After(now.Add(MaxClockSkew)) {
		return fmt.Errorf("%w: iat is in the future", ErrClaims)
	}
	if !now.Before(expiresAt) {
		return ErrExpired
	}
	requestHash, err := decodeCanonicalBase64URL(c.RequestHash)
	if err != nil || len(requestHash) != len(Binding{}.RequestHash) {
		return fmt.Errorf("%w: invalid request hash", ErrClaims)
	}
	if tokenHashPresent {
		if c.TokenHash == "" {
			return fmt.Errorf("%w: empty access-token hash", ErrClaims)
		}
		tokenHash, err := decodeCanonicalBase64URL(c.TokenHash)
		if err != nil || len(tokenHash) != len(Binding{}.TokenHash) {
			return fmt.Errorf("%w: invalid access-token hash", ErrClaims)
		}
	}
	if noncePresent && c.Nonce == "" {
		return fmt.Errorf("%w: empty nonce", ErrClaims)
	}
	return nil
}

func compareBinding(c wireClaims, expected Binding, tokenHashPresent, noncePresent bool) error {
	if c.Version != expected.version() {
		return fmt.Errorf("%w: version", ErrBinding)
	}
	if c.Metadata == nil || !maps.Equal(*c.Metadata, expected.Metadata) {
		return fmt.Errorf("%w: metadata", ErrBinding)
	}
	if c.Transport != string(expected.Transport) {
		return fmt.Errorf("%w: transport", ErrBinding)
	}
	if c.Operation != expected.Operation {
		return fmt.Errorf("%w: operation", ErrBinding)
	}
	if c.Method != expected.Method {
		return fmt.Errorf("%w: method", ErrBinding)
	}
	if c.TargetURI != expected.TargetURI {
		return fmt.Errorf("%w: target URI", ErrBinding)
	}
	if c.Nonce != expected.Nonce || noncePresent != (expected.Nonce != "") {
		return fmt.Errorf("%w: nonce", ErrBinding)
	}
	requestHash, _ := rawBase64URL.DecodeString(c.RequestHash)
	if subtle.ConstantTimeCompare(requestHash, expected.RequestHash[:]) != 1 {
		return fmt.Errorf("%w: request hash", ErrBinding)
	}
	if expected.BindToken {
		if !tokenHashPresent {
			return fmt.Errorf("%w: access-token hash missing", ErrBinding)
		}
		tokenHash, _ := rawBase64URL.DecodeString(c.TokenHash)
		if subtle.ConstantTimeCompare(tokenHash, expected.TokenHash[:]) != 1 {
			return fmt.Errorf("%w: access-token hash", ErrBinding)
		}
	} else if tokenHashPresent {
		return fmt.Errorf("%w: unexpected access-token hash", ErrBinding)
	}
	return nil
}
