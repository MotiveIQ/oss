package proof

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDefaultProfileIsV3(t *testing.T) {
	binding := grpcBinding()
	binding.Version = 0
	binding.Metadata = map[string]string{"x-tenant": "tenant-a"}
	compact := mustSign(t, binding, goldenTime)
	if version, err := UnverifiedVersion(compact); err != nil || version != Version3 {
		t.Fatalf("default profile = %d, %v; want v3", version, err)
	}
	expected := binding
	expected.Version = Version3
	if _, err := NewVerifier(func() time.Time { return goldenTime }).Verify(compact, expected); err != nil {
		t.Fatal(err)
	}
}

func TestV3ProfileIsExplicitAndBound(t *testing.T) {
	verifier := NewVerifier(func() time.Time { return goldenTime })
	v2 := grpcBinding()
	v2.Version = 2
	v3 := grpcBinding()
	v3.Version = Version3
	v3.Metadata = map[string]string{"x-tenant": "tenant-a"}
	compact := mustSign(t, v3, goldenTime)
	if version, err := UnverifiedVersion(compact); err != nil || version != Version3 {
		t.Fatalf("dispatch = %d, %v", version, err)
	}
	if _, err := verifier.Verify(compact, v3); err != nil {
		t.Fatal(err)
	}
	for name, expected := range map[string]Binding{
		"v3 proof as v2":   v2,
		"changed metadata": func() Binding { b := v3; b.Metadata = map[string]string{"x-tenant": "tenant-b"}; return b }(),
		"missing metadata": func() Binding { b := v3; b.Metadata = nil; return b }(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.Verify(compact, expected); !errors.Is(err, ErrBinding) {
				t.Fatalf("Verify = %v, want binding failure", err)
			}
		})
	}
	if _, err := signerWithProofID(t, make([]byte, proofIDBytes)).Sign(v2, goldenTime); !errors.Is(err, ErrBinding) {
		t.Fatalf("v2 signing = %v, want ErrBinding", err)
	}
	// Even a correctly signed envelope must obey its profile's claim schema.
	for _, version := range []int{2, Version3} {
		for _, metadata := range []any{nil, "not-an-object", map[string]any{"x-tenant": nil}} {
			bad := resign(t, compact, rfc8032Private(t), func(_ map[string]any, payload map[string]any) {
				payload["mqi_v"] = version
				payload["mqi_metadata"] = metadata
			})
			expected := v3
			expected.Metadata = nil
			if _, err := verifier.Verify(bad, expected); err == nil {
				t.Fatalf("accepted v%d metadata %#v", version, metadata)
			}
		}
	}
}

func TestV3EmptyMetadataAndRawJWSSerialization(t *testing.T) {
	binding := grpcBinding()
	binding.Version = Version3
	compact := mustSign(t, binding, goldenTime)
	parts := strings.Split(compact, ".")
	data, _ := rawBase64URL.DecodeString(parts[1])
	var claims map[string]json.RawMessage
	if err := json.Unmarshal(data, &claims); err != nil {
		t.Fatal(err)
	}
	if string(claims["mqi_metadata"]) != "{}" {
		t.Fatalf("empty metadata = %s", claims["mqi_metadata"])
	}
	// Reordering object members through a map produces a different signed JSON
	// representation. The receiver verifies that representation, not regenerated JSON.
	reordered := resign(t, compact, rfc8032Private(t), func(_ map[string]any, _ map[string]any) {})
	if _, err := NewVerifier(func() time.Time { return goldenTime }).Verify(reordered, binding); err != nil {
		t.Fatal(err)
	}
	missing := resign(t, compact, rfc8032Private(t), func(_ map[string]any, payload map[string]any) { delete(payload, "mqi_metadata") })
	if _, err := NewVerifier(func() time.Time { return goldenTime }).Verify(missing, binding); err == nil {
		t.Fatal("accepted missing v3 metadata")
	}
}

func TestMetadataProfileBounds(t *testing.T) {
	for _, metadata := range []map[string]string{
		{"authorization": "x"}, {"dpop": "x"},
		{"X-Tenant": "x"}, {":authority": "x"},
		{"x": "bad\nvalue"}, {"x": " padded "}, {"x": strings.Repeat("x", 1025)},
	} {
		if err := ValidateMetadata(metadata); err == nil {
			t.Fatalf("accepted %#v", metadata)
		}
	}
	if err := ValidateMetadata(map[string]string{"x-tenant": "", "x-write-condition": "abc"}); err != nil {
		t.Fatal(err)
	}
}

func TestV3TransportIndependenceAndIsolation(t *testing.T) {
	verifier := NewVerifier(func() time.Time { return goldenTime })
	for _, transport := range []Transport{TransportGRPC, TransportHTTP, "example-rpc.v1"} {
		binding := grpcBinding()
		binding.Version = Version3
		binding.Transport = transport
		if transport == "example-rpc.v1" {
			binding.Method = "CALL"
			binding.TargetURI = "urn:motiveiq:example:rpc"
			binding.Operation = "Echo"
		}
		compact := mustSign(t, binding, goldenTime)
		if _, err := verifier.Verify(compact, binding); err != nil {
			t.Fatal(err)
		}
		for _, other := range []Transport{TransportGRPC, TransportHTTP, "example-rpc.v1"} {
			if other == transport {
				continue
			}
			expected := binding
			expected.Transport = other
			if _, err := verifier.Verify(compact, expected); !errors.Is(err, ErrBinding) {
				t.Fatalf("%s -> %s: %v", transport, other, err)
			}
		}
		aliased := resign(t, compact, rfc8032Private(t), func(_ map[string]any, payload map[string]any) { payload["HTM"] = payload["htm"] })
		if _, err := verifier.Verify(aliased, binding); err == nil {
			t.Fatal("accepted JSON member alias")
		}
	}
}

func TestGoldenV3CompactProof(t *testing.T) {
	// Public RFC 8032 test key, proof ID 000102...0f, never real credentials.
	binding := Binding{
		Version: Version3, Transport: TransportHTTP, Operation: "example.Echo",
		Method: "POST", TargetURI: "https://api.example/rpc?x=1&x=2",
		RequestHash: Digest([]byte(`{"a":1}`)), BindToken: true,
		TokenHash: Digest([]byte("test-session-token")),
		Metadata:  map[string]string{"content-type": "application/json", "x-tenant": "tenant-a"},
	}
	got := mustSign(t, binding, goldenTime)
	const want = "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVkRFNBIiwiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiMTFxWUFZS3hDcmZWU183VHlXUUhPZzdoY3ZQYXBpTWxyd0lhYVBjSFVSbyJ9fQ.eyJqdGkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R3IiwiaWF0IjoxNzg1Njg2NDYwLCJleHAiOjE3ODU2ODY0OTAsImh0bSI6IlBPU1QiLCJodHUiOiJodHRwczovL2FwaS5leGFtcGxlL3JwYz94PTFcdTAwMjZ4PTIiLCJhdGgiOiJlaGIwVG9MNGtzWGJtVV94X2l4R2hsYXRNYTkzNi1CTEhRSy1PX2pVekk0IiwibXFpX3YiOjMsIm1xaV90cmFuc3BvcnQiOiJodHRwIiwibXFpX29wZXJhdGlvbiI6ImV4YW1wbGUuRWNobyIsIm1xaV9yZXF1ZXN0X2hhc2giOiJBVnE5ZjF6RmVpM1pTM1dROEVyWUNFSnprRjdqUHNYT3ZxNWlKMnFYLUdJIiwibXFpX21ldGFkYXRhIjp7ImNvbnRlbnQtdHlwZSI6ImFwcGxpY2F0aW9uL2pzb24iLCJ4LXRlbmFudCI6InRlbmFudC1hIn19.m75iHUZ4Rhy_nGbGOTY8lpmqvA6ScggOxCZYXBzRLWcJNdsw19-grIp-twrZ2_15o58100bd0wuvuJlwP4BmAQ"
	if got != want {
		t.Fatalf("v3 compact vector: %s", got)
	}
	if _, err := NewVerifier(func() time.Time { return goldenTime }).Verify(want, binding); err != nil {
		t.Fatal(err)
	}
}
