package proof

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// RFC 8032 test vector 1 gives this seed/public-key pair. Reusing a published
// Ed25519 vector makes the JWK and RFC 7638 thumbprint assertion independent
// of key generation in this package.
const (
	rfc8032SeedHex   = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	rfc8032PublicHex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	wantPublicX      = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
	wantThumbprint   = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
)

func rfc8032Private(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(rfc8032SeedHex)
	if err != nil {
		t.Fatalf("decode RFC 8032 seed: %v", err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func TestRFC7638Thumbprint(t *testing.T) {
	publicBytes, err := hex.DecodeString(rfc8032PublicHex)
	if err != nil {
		t.Fatalf("decode RFC 8032 public key: %v", err)
	}
	got, err := Thumbprint(ed25519.PublicKey(publicBytes))
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}
	if got != wantThumbprint {
		t.Errorf("Thumbprint = %q, want %q", got, wantThumbprint)
	}

	signer, err := NewSigner(rfc8032Private(t), bytes.NewReader(make([]byte, proofIDBytes)))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if signer.Thumbprint() != wantThumbprint {
		t.Errorf("Signer.Thumbprint = %q, want %q", signer.Thumbprint(), wantThumbprint)
	}
	if signer.jwk().X != wantPublicX {
		t.Errorf("JWK x = %q, want %q", signer.jwk().X, wantPublicX)
	}
}

func TestStrictPublicJWK(t *testing.T) {
	valid := `{"kty":"OKP","crv":"Ed25519","x":"` + wantPublicX + `"}`
	public, thumbprint, err := parsePublicJWK([]byte(valid))
	if err != nil {
		t.Fatalf("parsePublicJWK(valid): %v", err)
	}
	if got := hex.EncodeToString(public); got != rfc8032PublicHex {
		t.Errorf("public key = %s, want %s", got, rfc8032PublicHex)
	}
	if thumbprint != wantThumbprint {
		t.Errorf("thumbprint = %q, want %q", thumbprint, wantThumbprint)
	}

	tests := map[string]string{
		"missing":          `{}`,
		"wrong key type":   `{"kty":"EC","crv":"Ed25519","x":"` + wantPublicX + `"}`,
		"wrong curve":      `{"kty":"OKP","crv":"X25519","x":"` + wantPublicX + `"}`,
		"private material": `{"kty":"OKP","crv":"Ed25519","x":"` + wantPublicX + `","d":"secret"}`,
		"extra metadata":   `{"kty":"OKP","crv":"Ed25519","x":"` + wantPublicX + `","kid":"caller"}`,
		"padded x":         `{"kty":"OKP","crv":"Ed25519","x":"` + wantPublicX + `="}`,
		"short x":          `{"kty":"OKP","crv":"Ed25519","x":"AA"}`,
		"duplicate x":      `{"kty":"OKP","crv":"Ed25519","x":"` + wantPublicX + `","x":"` + wantPublicX + `"}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parsePublicJWK([]byte(raw)); !errors.Is(err, ErrJWK) {
				t.Errorf("parsePublicJWK error = %v, want ErrJWK", err)
			}
		})
	}
}

func TestSignerConstruction(t *testing.T) {
	if _, err := NewSigner(make(ed25519.PrivateKey, ed25519.PrivateKeySize-1), nil); err == nil {
		t.Fatal("NewSigner accepted a short private key")
	}
	if _, err := Thumbprint(make(ed25519.PublicKey, ed25519.PublicKeySize-1)); err == nil {
		t.Fatal("Thumbprint accepted a short public key")
	}
	if _, err := GenerateSigner(strings.NewReader("too short")); err == nil {
		t.Fatal("GenerateSigner accepted exhausted randomness")
	}
	generated, err := GenerateSigner(bytes.NewReader(bytes.Repeat([]byte{0x42}, ed25519.SeedSize+proofIDBytes)))
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	if generated.Thumbprint() == "" {
		t.Error("generated signer has empty thumbprint")
	}
}

func TestSignerSeedIsCopy(t *testing.T) {
	signer, err := NewSigner(rfc8032Private(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	seed := signer.Seed()
	if hex.EncodeToString(seed) != rfc8032SeedHex {
		t.Fatal("seed does not match the original key")
	}
	seed[0] ^= 0xff
	if hex.EncodeToString(signer.Seed()) != rfc8032SeedHex {
		t.Fatal("mutating exported seed changed the signer")
	}
}

func TestStrictJSONDepthBound(t *testing.T) {
	raw := strings.Repeat("[", maxJSONDepth+2) + "0" + strings.Repeat("]", maxJSONDepth+2)
	if err := rejectDuplicateNames([]byte(raw)); err == nil {
		t.Fatal("rejectDuplicateNames accepted excessive nesting")
	}
}
