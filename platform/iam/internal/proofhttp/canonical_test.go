package proofhttp_test

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"go.motiveiq.dev/platform/iam/internal/proof"
	"go.motiveiq.dev/platform/iam/internal/proofhttp"
)

func TestNormalizeOrigin(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"https://API.Example.COM", "https://api.example.com"},
		{"HTTPS://API.Example.COM/", "https://api.example.com"},
		{"https://api.example.com:443", "https://api.example.com"},
		{"https://api.example.com:8443/", "https://api.example.com:8443"},
		{"https://[2001:0DB8:0:0::1]:443", "https://[2001:db8::1]"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got, err := proofhttp.NormalizeOrigin(tc.input)
			if err != nil {
				t.Fatalf("NormalizeOrigin: %v", err)
			}
			if got != tc.want {
				t.Errorf("NormalizeOrigin(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}

	for _, input := range []string{
		"",
		" https://api.example.com",
		"http://api.example.com",
		"https://",
		"https://user:password@api.example.com",
		"https://api.example.com/v1",
		"https://api.example.com/%2F",
		"https://api.example.com?x=1",
		"https://api.example.com?",
		"https://api.example.com#fragment",
		"https://api.example.com#",
		"https://api.example.com:",
		"https://api.example.com:0",
		"https://api.example.com:65536",
		"https://api.example.com:not-a-port",
		"https://[fe80::1%25en0]",
		"https://café.example",
	} {
		t.Run("reject_"+input, func(t *testing.T) {
			t.Parallel()
			if _, err := proofhttp.NormalizeOrigin(input); !errors.Is(err, proofhttp.ErrInvalidOrigin) {
				t.Errorf("NormalizeOrigin(%q) error = %v, want ErrInvalidOrigin", input, err)
			}
		})
	}
}

func TestCanonicalizeExactHTTPRequest(t *testing.T) {
	t.Parallel()
	canonicalizer, err := proofhttp.New(proofhttp.Config{
		Origin:       "https://API.Example.COM:443/",
		MaxBodyBytes: 1024,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	body := []byte("{ \"sku\" : \"a/b\", \"count\": 2 }\n")
	req, err := http.NewRequest(
		http.MethodPost,
		"https://api.example.com/v1/items/a%2Fb?tag=b&tag=a&slash=%2F",
		strings.NewReader(string(body)),
	)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// These values are controlled by the requester or a proxy. Neither may
	// change the proof target derived from the trusted origin.
	req.Host = "attacker.example"
	req.Header.Set("Forwarded", "host=attacker.example;proto=http")
	req.Header.Set("X-Forwarded-Host", "attacker.example")
	req.Header.Set("X-Forwarded-Proto", "http")

	got, err := canonicalizer.Canonicalize(req, proofhttp.RequestOptions{
		Operation:   "inventory.CreateItem",
		AccessToken: "exact.session.token",
		BindToken:   true,
		Nonce:       "server-nonce",
	})
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	wantBodyDigest := proof.Digest(body)
	wantTokenDigest := proof.Digest([]byte("exact.session.token"))
	wantBinding := proof.Binding{
		Transport:   proof.TransportHTTP,
		Operation:   "inventory.CreateItem",
		Method:      http.MethodPost,
		TargetURI:   "https://api.example.com/v1/items/a%2Fb?tag=b&tag=a&slash=%2F",
		RequestHash: wantBodyDigest,
		BindToken:   true,
		TokenHash:   wantTokenDigest,
		Nonce:       "server-nonce",
	}
	if !reflect.DeepEqual(got.Binding, wantBinding) {
		t.Errorf("binding = %+v, want %+v", got.Binding, wantBinding)
	}
	if got.ContentDigest != proofhttp.FormatContentDigest(wantBodyDigest) {
		t.Errorf("Content-Digest = %q", got.ContentDigest)
	}
	if got.BodySize != int64(len(body)) {
		t.Errorf("BodySize = %d, want %d", got.BodySize, len(body))
	}
	restored, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if string(restored) != string(body) {
		t.Errorf("restored body = %q, want %q", restored, body)
	}
}

func TestCanonicalizePreservesQueryOrderAndJSONWhitespace(t *testing.T) {
	t.Parallel()
	canonicalizer, err := proofhttp.New(proofhttp.Config{
		Origin:       "https://api.example.com",
		MaxBodyBytes: 1024,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	canonicalize := func(rawURL, body string) proofhttp.CanonicalRequest {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, rawURL, strings.NewReader(body))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		got, err := canonicalizer.Canonicalize(req, proofhttp.RequestOptions{Operation: "inventory.Write"})
		if err != nil {
			t.Fatalf("Canonicalize: %v", err)
		}
		return got
	}

	first := canonicalize("https://api.example.com/items?k=2&k=1&z=0", `{"a":1}`)
	second := canonicalize("https://api.example.com/items?k=1&k=2&z=0", "{ \"a\": 1 }\n")
	if first.Binding.TargetURI != "https://api.example.com/items?k=2&k=1&z=0" {
		t.Errorf("first target URI = %q", first.Binding.TargetURI)
	}
	if second.Binding.TargetURI != "https://api.example.com/items?k=1&k=2&z=0" {
		t.Errorf("second target URI = %q", second.Binding.TargetURI)
	}
	if first.Binding.RequestHash == second.Binding.RequestHash {
		t.Error("JSON whitespace was normalized before hashing")
	}
}

func TestCanonicalizeEmptyBodyAndOriginForm(t *testing.T) {
	t.Parallel()
	canonicalizer, err := proofhttp.New(proofhttp.Config{
		Origin:       "https://api.example.com",
		MaxBodyBytes: 0,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	req := &http.Request{
		Method: http.MethodGet,
		URL: &url.URL{
			Path:       "/health",
			ForceQuery: true,
		},
		Host: "spoofed.example",
		Header: http.Header{
			"Forwarded":        {"host=spoofed.example;proto=http"},
			"X-Forwarded-Host": {"spoofed.example"},
		},
	}
	got, err := canonicalizer.Canonicalize(req, proofhttp.RequestOptions{Operation: "health.Read"})
	if err != nil {
		t.Fatalf("Canonicalize: %v", err)
	}
	if got.Binding.TargetURI != "https://api.example.com/health?" {
		t.Errorf("target URI = %q, want trusted origin and empty query marker", got.Binding.TargetURI)
	}
	if got.ContentDigest != "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:" {
		t.Errorf("empty Content-Digest = %q", got.ContentDigest)
	}
	if got.BodySize != 0 || got.Binding.BindToken {
		t.Errorf("empty unbound request = %+v", got)
	}
}

func TestCanonicalizeRejectsCrossOriginClientURL(t *testing.T) {
	t.Parallel()
	canonicalizer, err := proofhttp.New(proofhttp.Config{
		Origin:       "https://api.example.com",
		MaxBodyBytes: 16,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, rawURL := range []string{
		"https://other.example/items",
		"http://api.example.com/items",
		"https://api.example.com:8443/items",
	} {
		t.Run(rawURL, func(t *testing.T) {
			t.Parallel()
			req, err := http.NewRequest(http.MethodGet, rawURL, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			if _, err := canonicalizer.Canonicalize(req, proofhttp.RequestOptions{Operation: "inventory.List"}); !errors.Is(err, proofhttp.ErrCrossOrigin) {
				t.Errorf("Canonicalize error = %v, want ErrCrossOrigin", err)
			}
		})
	}

	// Scheme-relative URLs are not accepted as server origin-form URLs.
	req := &http.Request{Method: http.MethodGet, URL: &url.URL{Host: "other.example", Path: "/items"}}
	if _, err := canonicalizer.Canonicalize(req, proofhttp.RequestOptions{Operation: "inventory.List"}); !errors.Is(err, proofhttp.ErrCrossOrigin) {
		t.Errorf("scheme-relative error = %v, want ErrCrossOrigin", err)
	}

	// Equivalent spelling of the configured origin is accepted.
	equivalent, err := http.NewRequest(http.MethodGet, "HTTPS://API.EXAMPLE.COM:443/items", nil)
	if err != nil {
		t.Fatalf("NewRequest equivalent origin: %v", err)
	}
	if _, err := canonicalizer.Canonicalize(equivalent, proofhttp.RequestOptions{Operation: "inventory.List"}); err != nil {
		t.Errorf("equivalent origin rejected: %v", err)
	}
}

func TestRequestTargetValidatesWithoutReadingBody(t *testing.T) {
	t.Parallel()
	canonicalizer, err := proofhttp.New(proofhttp.Config{
		Origin:       "https://api.example.com",
		MaxBodyBytes: 1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	body := &trackingBody{reader: strings.NewReader("larger than the configured proof body limit")}
	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/items", body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	target, err := canonicalizer.RequestTarget(req)
	if err != nil {
		t.Fatalf("RequestTarget: %v", err)
	}
	if target != "https://api.example.com/items" {
		t.Errorf("target = %q", target)
	}
	if body.reads != 0 || body.closed {
		t.Errorf("RequestTarget touched body: reads=%d closed=%v", body.reads, body.closed)
	}
}

func TestCanonicalizeRequiresUppercaseMethodAndConsistentTokenMode(t *testing.T) {
	t.Parallel()
	canonicalizer, err := proofhttp.New(proofhttp.Config{
		Origin:       "https://api.example.com",
		MaxBodyBytes: 16,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, method := range []string{"", "get", "GeT", "GET SPACE", "GÉT"} {
		req := &http.Request{Method: method, URL: &url.URL{Path: "/items"}}
		if _, err := canonicalizer.Canonicalize(req, proofhttp.RequestOptions{Operation: "inventory.List"}); !errors.Is(err, proofhttp.ErrInvalidMethod) {
			t.Errorf("method %q error = %v, want ErrInvalidMethod", method, err)
		}
	}

	baseRequest := func() *http.Request {
		return &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/items"}}
	}
	if _, err := canonicalizer.Canonicalize(baseRequest(), proofhttp.RequestOptions{
		Operation: "inventory.List", BindToken: true,
	}); !errors.Is(err, proofhttp.ErrInvalidRequest) {
		t.Errorf("empty bound token error = %v, want ErrInvalidRequest", err)
	}
	if _, err := canonicalizer.Canonicalize(baseRequest(), proofhttp.RequestOptions{
		Operation: "inventory.List", AccessToken: "ignored",
	}); !errors.Is(err, proofhttp.ErrInvalidRequest) {
		t.Errorf("token in unbound mode error = %v, want ErrInvalidRequest", err)
	}
	if _, err := canonicalizer.Canonicalize(baseRequest(), proofhttp.RequestOptions{}); !errors.Is(err, proofhttp.ErrInvalidRequest) {
		t.Errorf("empty operation error = %v, want ErrInvalidRequest", err)
	}
}
