package proof

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

var goldenTime = time.Unix(1785686460, 0).UTC()

// grpcBinding supplies a v3 request binding for verifier conformance tests.
func grpcBinding() Binding {
	return Binding{
		Version:     Version3,
		Transport:   TransportGRPC,
		Operation:   "/motiveiq.roboship.v1.Roboship/TriggerDeploy",
		Method:      "POST",
		TargetURI:   "https://deploy.platform.motiveiq.net/motiveiq.roboship.v1.Roboship/TriggerDeploy",
		RequestHash: Digest([]byte("deterministic-protobuf-request")),
		BindToken:   true,
		TokenHash:   Digest([]byte("signed-session-token")),
		Nonce:       "server-nonce",
	}
}

func signerWithProofID(t *testing.T, id []byte) *Signer {
	t.Helper()
	signer, err := NewSigner(rfc8032Private(t), bytes.NewReader(id))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return signer
}

func mustSign(t *testing.T, binding Binding, at time.Time) string {
	t.Helper()
	id := make([]byte, proofIDBytes)
	for i := range id {
		id[i] = byte(i)
	}
	compact, err := signerWithProofID(t, id).Sign(binding, at)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return compact
}

func TestSignVerifyRoundTrip(t *testing.T) {
	binding := grpcBinding()
	compact := mustSign(t, binding, goldenTime)
	verification, err := NewVerifier(func() time.Time { return goldenTime.Add(10 * time.Second) }).Verify(compact, binding)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verification.ProofID != "AAECAwQFBgcICQoLDA0ODw" {
		t.Errorf("ProofID = %q", verification.ProofID)
	}
	if !verification.IssuedAt.Equal(goldenTime) || !verification.ExpiresAt.Equal(goldenTime.Add(MaxLifetime)) {
		t.Errorf("validity = %v..%v", verification.IssuedAt, verification.ExpiresAt)
	}
	if verification.KeyThumbprint != wantThumbprint {
		t.Errorf("KeyThumbprint = %q, want %q", verification.KeyThumbprint, wantThumbprint)
	}
	if !reflect.DeepEqual(verification.RequestBinding, binding) {
		t.Errorf("RequestBinding = %+v, want %+v", verification.RequestBinding, binding)
	}
	if verification.ProtocolVersion != Version3 {
		t.Errorf("ProtocolVersion = %d, want %d", verification.ProtocolVersion, Version3)
	}

	parts := strings.Split(compact, ".")
	headerJSON, _ := rawBase64URL.DecodeString(parts[0])
	payloadJSON, _ := rawBase64URL.DecodeString(parts[1])
	var header map[string]any
	var payload map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("decode header: %v", err)
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if header["typ"] != "dpop+jwt" || header["alg"] != "EdDSA" {
		t.Errorf("header = %v", header)
	}
	for _, required := range []string{
		"jti", "iat", "exp", "htm", "htu", "ath", "mqi_v",
		"mqi_transport", "mqi_operation", "mqi_request_hash", "nonce",
	} {
		if _, ok := payload[required]; !ok {
			t.Errorf("payload is missing %q: %v", required, payload)
		}
	}
	if _, ok := payload["mqi_"+"target"]; ok {
		t.Errorf("proof payload contains removed target claim: %v", payload)
	}
}

func TestVerifierRejectsRemovedTargetClaim(t *testing.T) {
	binding := grpcBinding()
	id := make([]byte, proofIDBytes)
	compact, err := signerWithProofID(t, id).Sign(binding, goldenTime)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	verifier := NewVerifier(func() time.Time { return goldenTime.Add(time.Second) })
	verification, err := verifier.Verify(compact, binding)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verification.ProtocolVersion != Version3 {
		t.Errorf("protocol version = %d, want %d", verification.ProtocolVersion, Version3)
	}

	parts := strings.Split(compact, ".")
	payloadJSON, _ := rawBase64URL.DecodeString(parts[1])
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if _, ok := payload["mqi_"+"target"]; ok {
		t.Fatalf("proof unexpectedly contains removed target claim: %v", payload)
	}

	withTarget := resign(t, compact, rfc8032Private(t), func(_ map[string]any, payload map[string]any) {
		payload["mqi_"+"target"] = "roboship"
	})
	if _, err := verifier.Verify(withTarget, binding); !errors.Is(err, ErrClaims) {
		t.Errorf("proof with removed target claim error = %v, want ErrClaims", err)
	}
	legacyVersion := resign(t, compact, rfc8032Private(t), func(_ map[string]any, payload map[string]any) {
		payload["mqi_v"] = float64(1)
	})
	if _, err := verifier.Verify(legacyVersion, binding); !errors.Is(err, ErrClaims) {
		t.Errorf("proof profile 1 error = %v, want ErrClaims", err)
	}
	changed := binding
	changed.TargetURI = "https://other.example" + binding.Operation
	if _, err := verifier.Verify(compact, changed); !errors.Is(err, ErrBinding) {
		t.Errorf("changed target URI error = %v, want ErrBinding", err)
	}
}

func TestSignUntilShortensProofLifetime(t *testing.T) {
	id := make([]byte, proofIDBytes)
	signer := signerWithProofID(t, id)
	expiresAt := goldenTime.Add(7 * time.Second)
	compact, err := signer.SignUntil(grpcBinding(), goldenTime, expiresAt)
	if err != nil {
		t.Fatalf("SignUntil: %v", err)
	}
	verification, err := NewVerifier(func() time.Time { return goldenTime.Add(time.Second) }).Verify(compact, grpcBinding())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !verification.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("proof expiry = %v, want %v", verification.ExpiresAt, expiresAt)
	}
	for name, expiry := range map[string]time.Time{
		"not after issuance": goldenTime,
		"over maximum":       goldenTime.Add(MaxLifetime + time.Second),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := signer.SignUntil(grpcBinding(), goldenTime, expiry); !errors.Is(err, ErrClaims) {
				t.Fatalf("SignUntil error = %v, want ErrClaims", err)
			}
		})
	}
}

func TestRetiredV2GoldenProofRejected(t *testing.T) {
	// This previously accepted v2 vector has a valid Ed25519 signature under
	// the public RFC 8032 test key. It must now fail because its profile is
	// retired, not because the fixture has an invalid signature.
	const want = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVkRFNBIiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMTFxWUFZS3hDcmZWU183VHlXUUhPZzdoY3ZQYXBpTWxyd0lhYVBjSFVSbyJ9fQ.eyJqdGkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R3IiwiaWF0IjoxNzg1Njg2NDYwLCJleHAiOjE3ODU2ODY0OTAsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL2RlcGxveS5wbGF0Zm9ybS5tb3RpdmVpcS5uZXQvbW90aXZlaXEucm9ib3NoaXAudjEuUm9ib3NoaXAvVHJpZ2dlckRlcGxveSIsImF0aCI6Ik45ZUxRR0RsU2hBZG9TX00tWjNuTTRsSmNTdFRNSFpvck4zTDVDS2t6ZTQiLCJtcWlfdiI6MiwibXFpX3RyYW5zcG9ydCI6ImdycGMiLCJtcWlfb3BlcmF0aW9uIjoiL21vdGl2ZWlxLnJvYm9zaGlwLnYxLlJvYm9zaGlwL1RyaWdnZXJEZXBsb3kiLCJtcWlfcmVxdWVzdF9oYXNoIjoiWHRMZnRjVjdTSnlLampUX1VMeEhLSmNLTzZ1NkJFMzRqbWRqeXZKS2luZyIsIm5vbmNlIjoic2VydmVyLW5vbmNlIn0.dF8dnf9woUzfwJdo0w7SPcbsJxHybS0bVh19TRBiVw8nQVJaA3n702yOTmG7TTqZ5vV14a1ZHweTI6beBENZBQ"
	if _, err := NewVerifier(func() time.Time { return goldenTime }).Verify(want, grpcBinding()); !errors.Is(err, ErrClaims) {
		t.Fatalf("retired v2 proof = %v, want ErrClaims", err)
	}
	if _, err := UnverifiedVersion(want); !errors.Is(err, ErrClaims) {
		t.Fatalf("retired v2 dispatch = %v, want ErrClaims", err)
	}
}

func TestBindingMutationsRejected(t *testing.T) {
	binding := grpcBinding()
	compact := mustSign(t, binding, goldenTime)
	verify := NewVerifier(func() time.Time { return goldenTime.Add(time.Second) })
	mutations := map[string]func(*Binding){
		"transport":             func(b *Binding) { b.Transport = TransportHTTP },
		"operation":             func(b *Binding) { b.Operation += "Other" },
		"method":                func(b *Binding) { b.Method = "PUT" },
		"target URI":            func(b *Binding) { b.TargetURI += "?changed=1" },
		"request hash":          func(b *Binding) { b.RequestHash = Digest([]byte("changed request")) },
		"token hash":            func(b *Binding) { b.TokenHash = Digest([]byte("different token")) },
		"token binding removed": func(b *Binding) { b.BindToken = false },
		"nonce":                 func(b *Binding) { b.Nonce = "other-nonce" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			expected := binding
			mutate(&expected)
			if _, err := verify.Verify(compact, expected); !errors.Is(err, ErrBinding) {
				t.Errorf("Verify error = %v, want ErrBinding", err)
			}
		})
	}
}

func TestTokenHashPresenceIsBound(t *testing.T) {
	bound := grpcBinding()
	unbound := bound
	unbound.BindToken = false
	unbound.TokenHash = [32]byte{}
	verify := NewVerifier(func() time.Time { return goldenTime.Add(time.Second) })

	boundProof := mustSign(t, bound, goldenTime)
	if _, err := verify.Verify(boundProof, unbound); !errors.Is(err, ErrBinding) {
		t.Errorf("bound proof as unbound error = %v, want ErrBinding", err)
	}
	unboundProof := mustSign(t, unbound, goldenTime)
	if _, err := verify.Verify(unboundProof, bound); !errors.Is(err, ErrBinding) {
		t.Errorf("unbound proof as bound error = %v, want ErrBinding", err)
	}
}

func TestValidityWindow(t *testing.T) {
	binding := grpcBinding()
	compact := mustSign(t, binding, goldenTime)
	for _, tc := range []struct {
		name string
		now  time.Time
		want error
	}{
		{"at issuance", goldenTime, nil},
		{"one second before expiry", goldenTime.Add(MaxLifetime - time.Second), nil},
		{"at expiry", goldenTime.Add(MaxLifetime), ErrExpired},
		{"future issued-at within skew", goldenTime.Add(-MaxClockSkew), nil},
		{"future issued-at beyond skew", goldenTime.Add(-MaxClockSkew - time.Second), ErrClaims},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewVerifier(func() time.Time { return tc.now }).Verify(compact, binding)
			if tc.want == nil && err != nil {
				t.Errorf("Verify: %v", err)
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Errorf("Verify error = %v, want %v", err, tc.want)
			}
		})
	}

	overlong := resign(t, compact, rfc8032Private(t), func(_ map[string]any, payload map[string]any) {
		payload["exp"] = float64(goldenTime.Add(MaxLifetime + time.Second).Unix())
	})
	if _, err := NewVerifier(func() time.Time { return goldenTime }).Verify(overlong, binding); !errors.Is(err, ErrClaims) {
		t.Errorf("overlong lifetime error = %v, want ErrClaims", err)
	}
	zeroLifetime := resign(t, compact, rfc8032Private(t), func(_ map[string]any, payload map[string]any) {
		payload["exp"] = payload["iat"]
	})
	if _, err := NewVerifier(func() time.Time { return goldenTime }).Verify(zeroLifetime, binding); !errors.Is(err, ErrClaims) {
		t.Errorf("zero lifetime error = %v, want ErrClaims", err)
	}
}

func TestSignedMutationsAndStrictParsing(t *testing.T) {
	binding := grpcBinding()
	compact := mustSign(t, binding, goldenTime)
	verify := NewVerifier(func() time.Time { return goldenTime.Add(time.Second) })

	tamperedParts := strings.Split(compact, ".")
	payload, _ := rawBase64URL.DecodeString(tamperedParts[1])
	payload[len(payload)-2] ^= 1
	tamperedParts[1] = rawBase64URL.EncodeToString(payload)
	if _, err := verify.Verify(strings.Join(tamperedParts, "."), binding); !errors.Is(err, ErrSignature) {
		t.Errorf("tampered payload error = %v, want ErrSignature", err)
	}

	badSignature := strings.Split(compact, ".")
	signature, _ := rawBase64URL.DecodeString(badSignature[2])
	signature[0] ^= 1
	badSignature[2] = rawBase64URL.EncodeToString(signature)
	if _, err := verify.Verify(strings.Join(badSignature, "."), binding); !errors.Is(err, ErrSignature) {
		t.Errorf("bad signature error = %v, want ErrSignature", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(map[string]any, map[string]any)
		want   error
	}{
		{"wrong typ", func(h, _ map[string]any) { h["typ"] = "JWT" }, ErrHeader},
		{"wrong alg", func(h, _ map[string]any) { h["alg"] = "none" }, ErrHeader},
		{"extra header", func(h, _ map[string]any) { h["kid"] = "unexpected" }, ErrHeader},
		{"private JWK", func(h, _ map[string]any) { h["jwk"].(map[string]any)["d"] = "secret" }, ErrJWK},
		{"wrong curve", func(h, _ map[string]any) { h["jwk"].(map[string]any)["crv"] = "X25519" }, ErrJWK},
		{"unknown claim", func(_, p map[string]any) { p["unexpected"] = true }, ErrClaims},
		{"wrong version", func(_, p map[string]any) { p["mqi_v"] = float64(99) }, ErrClaims},
		{"short proof ID", func(_, p map[string]any) { p["jti"] = "AA" }, ErrClaims},
		{"bad request hash", func(_, p map[string]any) { p["mqi_request_hash"] = "AA" }, ErrClaims},
		{"bad token hash", func(_, p map[string]any) { p["ath"] = "AA" }, ErrClaims},
		{"empty token hash", func(_, p map[string]any) { p["ath"] = "" }, ErrClaims},
		{"empty nonce", func(_, p map[string]any) { p["nonce"] = "" }, ErrClaims},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := resign(t, compact, rfc8032Private(t), tc.mutate)
			if _, err := verify.Verify(mutated, binding); !errors.Is(err, tc.want) {
				t.Errorf("Verify error = %v, want %v", err, tc.want)
			}
		})
	}

	duplicateClaim := resignRaw(t, compact, rfc8032Private(t), func(_ string, payload string) (string, string) {
		return "", strings.Replace(payload, `{"jti":`, `{"jti":"duplicate","jti":`, 1)
	})
	if _, err := verify.Verify(duplicateClaim, binding); !errors.Is(err, ErrClaims) {
		t.Errorf("duplicate claim error = %v, want ErrClaims", err)
	}
	duplicateJWK := resignRaw(t, compact, rfc8032Private(t), func(header, _ string) (string, string) {
		return strings.Replace(header, `"kty":"OKP"`, `"kty":"OKP","kty":"OKP"`, 1), ""
	})
	if _, err := verify.Verify(duplicateJWK, binding); !errors.Is(err, ErrHeader) {
		t.Errorf("duplicate JWK member error = %v, want ErrHeader", err)
	}
}

func TestMalformedAndOversizedProofs(t *testing.T) {
	binding := grpcBinding()
	verify := NewVerifier(func() time.Time { return goldenTime })
	for _, raw := range []string{
		"",
		"one.two",
		"one.two.three.four",
		"=.eA.eA",
		strings.Repeat("a", MaxEncodedSize+1),
	} {
		if _, err := verify.Verify(raw, binding); !errors.Is(err, ErrMalformed) {
			t.Errorf("Verify(%q) error = %v, want ErrMalformed", abbreviate(raw), err)
		}
	}
}

func TestBindingValidation(t *testing.T) {
	valid := grpcBinding()
	mutations := map[string]func(*Binding){
		"transport":          func(b *Binding) { b.Transport = "SMTP" },
		"operation":          func(b *Binding) { b.Operation = "" },
		"method":             func(b *Binding) { b.Method = "" },
		"target URI":         func(b *Binding) { b.TargetURI = "" },
		"long nonce":         func(b *Binding) { b.Nonce = strings.Repeat("n", maxNonceLength+1) },
		"unset request hash": func(b *Binding) { b.RequestHash = [32]byte{} },
		"unset token hash":   func(b *Binding) { b.TokenHash = [32]byte{} },
		"unexpected token hash": func(b *Binding) {
			b.BindToken = false
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			binding := valid
			mutate(&binding)
			if _, err := signerWithProofID(t, make([]byte, proofIDBytes)).Sign(binding, goldenTime); !errors.Is(err, ErrBinding) {
				t.Errorf("Sign error = %v, want ErrBinding", err)
			}
		})
	}
	if _, err := signerWithProofID(t, make([]byte, proofIDBytes)).Sign(valid, time.Time{}); !errors.Is(err, ErrClaims) {
		t.Errorf("zero issuedAt error = %v, want ErrClaims", err)
	}
}

func TestVerificationExposesKeyForTokenBinding(t *testing.T) {
	binding := grpcBinding()
	first := mustSign(t, binding, goldenTime)
	firstVerification, err := NewVerifier(func() time.Time { return goldenTime }).Verify(first, binding)
	if err != nil {
		t.Fatalf("verify first key: %v", err)
	}
	otherSeed := bytes.Repeat([]byte{0x5a}, ed25519.SeedSize)
	other, err := NewSigner(ed25519.NewKeyFromSeed(otherSeed), bytes.NewReader(make([]byte, proofIDBytes)))
	if err != nil {
		t.Fatalf("NewSigner(other): %v", err)
	}
	second, err := other.Sign(binding, goldenTime)
	if err != nil {
		t.Fatalf("Sign(other): %v", err)
	}
	secondVerification, err := NewVerifier(func() time.Time { return goldenTime }).Verify(second, binding)
	if err != nil {
		t.Fatalf("verify second key: %v", err)
	}
	if firstVerification.KeyThumbprint == secondVerification.KeyThumbprint {
		t.Fatal("different proof keys produced the same thumbprint")
	}
}

func resign(t *testing.T, compact string, private ed25519.PrivateKey, mutate func(map[string]any, map[string]any)) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	headerJSON, err := rawBase64URL.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	payloadJSON, err := rawBase64URL.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var header, payload map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	mutate(header, payload)
	headerJSON, err = json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadJSON, err = json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return signRaw(t, string(headerJSON), string(payloadJSON), private)
}

// resignRaw lets a test produce deliberately duplicate JSON names. Returning
// an empty replacement preserves that part of the original proof.
func resignRaw(t *testing.T, compact string, private ed25519.PrivateKey, mutate func(string, string) (string, string)) string {
	t.Helper()
	parts := strings.Split(compact, ".")
	headerJSON, _ := rawBase64URL.DecodeString(parts[0])
	payloadJSON, _ := rawBase64URL.DecodeString(parts[1])
	header, payload := mutate(string(headerJSON), string(payloadJSON))
	if header == "" {
		header = string(headerJSON)
	}
	if payload == "" {
		payload = string(payloadJSON)
	}
	return signRaw(t, header, payload, private)
}

func signRaw(t *testing.T, headerJSON, payloadJSON string, private ed25519.PrivateKey) string {
	t.Helper()
	input := rawBase64URL.EncodeToString([]byte(headerJSON)) + "." + rawBase64URL.EncodeToString([]byte(payloadJSON))
	return input + "." + rawBase64URL.EncodeToString(ed25519.Sign(private, []byte(input)))
}

func abbreviate(raw string) string {
	if len(raw) <= 32 {
		return raw
	}
	return fmt.Sprintf("%s...(%d bytes)", raw[:16], len(raw))
}
