package proof

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

const (
	jwkKeyType = "OKP"
	jwkCurve   = "Ed25519"
)

var rawBase64URL = base64.RawURLEncoding

// publicJWK is the only proof-key form accepted on the wire. Its fields are
// deliberately closed: private material (d) and optional JOSE metadata are
// rejected rather than ignored.
type publicJWK struct {
	KeyType string `json:"kty"`
	Curve   string `json:"crv"`
	X       string `json:"x"`
}

// Signer owns one caller proof key. It is safe for concurrent use. The
// private key never appears in a proof or a returned verification value.
type Signer struct {
	private    ed25519.PrivateKey
	public     ed25519.PublicKey
	thumbprint string
	random     io.Reader
	randomMu   sync.Mutex
}

// GenerateSigner creates a fresh Ed25519 proof key using random. A nil reader
// uses crypto/rand.Reader. The same reader generates future proof IDs.
func GenerateSigner(random io.Reader) (*Signer, error) {
	if random == nil {
		random = rand.Reader
	}
	_, private, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, fmt.Errorf("proof: generate Ed25519 key: %w", err)
	}
	return NewSigner(private, random)
}

// NewSigner builds a signer from an existing Ed25519 private key. This is the
// cache-restoration path for clients that persist a session and its proof key
// together. The key is copied so callers cannot mutate it after construction.
// A nil random reader uses crypto/rand.Reader.
func NewSigner(private ed25519.PrivateKey, random io.Reader) (*Signer, error) {
	if len(private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("proof: Ed25519 private key has %d bytes, want %d", len(private), ed25519.PrivateKeySize)
	}
	if random == nil {
		random = rand.Reader
	}
	privateCopy := append(ed25519.PrivateKey(nil), private...)
	public := privateCopy.Public().(ed25519.PublicKey)
	publicCopy := append(ed25519.PublicKey(nil), public...)
	thumbprint, err := Thumbprint(publicCopy)
	if err != nil {
		return nil, err
	}
	return &Signer{
		private:    privateCopy,
		public:     publicCopy,
		thumbprint: thumbprint,
		random:     random,
	}, nil
}

// Thumbprint returns this signer's RFC 7638 public-JWK thumbprint.
func (s *Signer) Thumbprint() string { return s.thumbprint }

// Seed returns a copy of the private Ed25519 seed for credential-cache
// persistence. It is secret material and must be stored with the same
// protections as the session token, never logged or included in a proof.
func (s *Signer) Seed() []byte { return s.private.Seed() }

func (s *Signer) jwk() publicJWK {
	return publicJWK{
		KeyType: jwkKeyType,
		Curve:   jwkCurve,
		X:       rawBase64URL.EncodeToString(s.public),
	}
}

// Thumbprint computes the RFC 7638 SHA-256 JWK thumbprint for an Ed25519
// public key. RFC 7638 requires lexicographic member order in the canonical
// JSON object: crv, kty, x.
func Thumbprint(public ed25519.PublicKey) (string, error) {
	if len(public) != ed25519.PublicKeySize {
		return "", fmt.Errorf("proof: Ed25519 public key has %d bytes, want %d", len(public), ed25519.PublicKeySize)
	}
	x := rawBase64URL.EncodeToString(public)
	canonical := []byte(`{"crv":"` + jwkCurve + `","kty":"` + jwkKeyType + `","x":"` + x + `"}`)
	digest := sha256.Sum256(canonical)
	return rawBase64URL.EncodeToString(digest[:]), nil
}

func parsePublicJWK(raw json.RawMessage) (ed25519.PublicKey, string, error) {
	if len(raw) == 0 {
		return nil, "", fmt.Errorf("%w: missing jwk", ErrJWK)
	}
	var jwk publicJWK
	if err := unmarshalStrict(raw, &jwk); err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrJWK, err)
	}
	if jwk.KeyType != jwkKeyType {
		return nil, "", fmt.Errorf("%w: kty must be %q", ErrJWK, jwkKeyType)
	}
	if jwk.Curve != jwkCurve {
		return nil, "", fmt.Errorf("%w: crv must be %q", ErrJWK, jwkCurve)
	}
	x, err := decodeCanonicalBase64URL(jwk.X)
	if err != nil {
		return nil, "", fmt.Errorf("%w: x: %v", ErrJWK, err)
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, "", fmt.Errorf("%w: x decodes to %d bytes, want %d", ErrJWK, len(x), ed25519.PublicKeySize)
	}
	public := ed25519.PublicKey(x)
	thumbprint, err := Thumbprint(public)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrJWK, err)
	}
	return public, thumbprint, nil
}

func decodeCanonicalBase64URL(encoded string) ([]byte, error) {
	if encoded == "" {
		return nil, fmt.Errorf("empty base64url value")
	}
	decoded, err := rawBase64URL.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64url: %w", err)
	}
	if rawBase64URL.EncodeToString(decoded) != encoded {
		return nil, fmt.Errorf("non-canonical base64url")
	}
	return decoded, nil
}
