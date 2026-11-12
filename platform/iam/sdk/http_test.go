package motiveiq

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	sdktransport "github.com/MotiveIQ/public/platform/iam/sdk/internal/transport"

	"github.com/MotiveIQ/public/platform/iam/internal/proof"
	"github.com/MotiveIQ/public/platform/iam/internal/proofhttp"
)

const httpTestOrigin = "https://api.platform.motiveiq.net"

type capturedHTTPRequest struct {
	method string
	url    string
	header http.Header
	body   string
}

type capturingRoundTripper struct {
	mu       sync.Mutex
	requests []capturedHTTPRequest
}

func (t *capturingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	t.mu.Lock()
	t.requests = append(t.requests, capturedHTTPRequest{
		method: req.Method,
		url:    req.URL.String(),
		header: req.Header.Clone(),
		body:   string(body),
	})
	t.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

func (t *capturingRoundTripper) snapshot() []capturedHTTPRequest {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]capturedHTTPRequest(nil), t.requests...)
}

func staticHTTPTestCredentials(now time.Time, signer *proof.Signer) *SessionCredentials {
	return &SessionCredentials{
		now: func() time.Time { return now },
		generation: &credentialGeneration{
			token:     "session-token",
			signer:    signer,
			expiresAt: now.Add(15 * time.Minute),
			refreshAt: now.Add(10 * time.Minute),
		},
	}
}

func TestAuthenticatedRoundTripperRejectsGenerationWithoutSigner(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	base := new(capturingRoundTripper)
	transport, err := NewAuthenticatedRoundTripper(HTTPClientAuthenticationOptions{
		Base:         base,
		Credentials:  staticHTTPTestCredentials(now, nil),
		Origin:       httpTestOrigin,
		MaxBodyBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewAuthenticatedRoundTripper: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, httpTestOrigin+"/items", strings.NewReader("body"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if _, err := transport.RoundTrip(req); err == nil || !strings.Contains(err.Error(), "not proof-bound") {
		t.Fatalf("RoundTrip error = %v, want proof-bound rejection", err)
	}
	if got := len(base.snapshot()); got != 0 {
		t.Fatalf("base requests = %d, want 0", got)
	}
}

func TestAuthenticatedRoundTripperSignsExactHTTPRequest(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer, err := proof.GenerateSigner(nil)
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	base := new(capturingRoundTripper)
	transport, err := NewAuthenticatedRoundTripper(HTTPClientAuthenticationOptions{
		Base:         base,
		Credentials:  staticHTTPTestCredentials(now, signer),
		Origin:       httpTestOrigin,
		MaxBodyBytes: 1024,
	})
	if err != nil {
		t.Fatalf("NewAuthenticatedRoundTripper: %v", err)
	}
	body := "{ \"item\": \"a/b\", \"count\": 2 }\n"
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPatch,
		httpTestOrigin+"/v1/items/a%2Fb?tag=b&tag=a&slash=%2F",
		strings.NewReader(body),
	)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// A manually constructed request may have a nil Header map. The SDK owns
	// its cloned transport request and must allocate the map before injecting
	// authentication fields.
	req.Header = nil
	if _, err := transport.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	requests := base.snapshot()
	if len(requests) != 1 {
		t.Fatalf("base requests = %d, want 1", len(requests))
	}
	got := requests[0]
	if got.method != http.MethodPatch || got.url != httpTestOrigin+"/v1/items/a%2Fb?tag=b&tag=a&slash=%2F" || got.body != body {
		t.Errorf("transmitted request = method %q url %q body %q", got.method, got.url, got.body)
	}
	if got.header.Get("Authorization") != "DPoP session-token" {
		t.Errorf("Authorization = %q", got.header.Get("Authorization"))
	}
	bodyDigest := proof.Digest([]byte(body))
	if got.header.Get("Content-Digest") != proofhttp.FormatContentDigest(bodyDigest) {
		t.Errorf("Content-Digest = %q", got.header.Get("Content-Digest"))
	}
	compact := got.header.Get("DPoP")
	if compact == "" {
		t.Fatal("DPoP proof is empty")
	}
	verification, err := proof.NewVerifier(func() time.Time { return now }).Verify(compact, proof.Binding{
		Transport:   proof.TransportHTTP,
		Operation:   "/v1/items/a%2Fb",
		Method:      http.MethodPatch,
		TargetURI:   httpTestOrigin + "/v1/items/a%2Fb?tag=b&tag=a&slash=%2F",
		RequestHash: bodyDigest,
		BindToken:   true,
		TokenHash:   proof.Digest([]byte("session-token")),
	})
	if err != nil {
		t.Fatalf("Verify request proof: %v", err)
	}
	if verification.KeyThumbprint != signer.Thumbprint() {
		t.Errorf("proof jkt = %q, want %q", verification.KeyThumbprint, signer.Thumbprint())
	}
	if req.Header.Get("Authorization") != "" || req.Header.Get("DPoP") != "" || req.Header.Get("Content-Digest") != "" {
		t.Error("RoundTripper mutated the caller's request headers")
	}
	originalBody, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read original request body after RoundTrip: %v", err)
	}
	if string(originalBody) != body {
		t.Errorf("original request body after RoundTrip = %q, want %q", originalBody, body)
	}
}

func TestAuthenticatedRoundTripperRejectsConflictsCrossOriginAndLimits(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	signer, err := proof.GenerateSigner(nil)
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	base := new(capturingRoundTripper)
	transport, err := NewAuthenticatedRoundTripper(HTTPClientAuthenticationOptions{
		Base:         base,
		Credentials:  staticHTTPTestCredentials(now, signer),
		Origin:       httpTestOrigin,
		MaxBodyBytes: 4,
	})
	if err != nil {
		t.Fatalf("NewAuthenticatedRoundTripper: %v", err)
	}

	for _, header := range []string{"Authorization", "DPoP", "Content-Digest", proof.DelegationTokenMetadata, proof.DelegationTokenDigestMetadata, sdktransport.DelegationSubjectMetadata} {
		req, _ := http.NewRequest(http.MethodPost, httpTestOrigin+"/items", strings.NewReader("body"))
		req.Header.Set(header, "application-value")
		if _, err := transport.RoundTrip(req); err == nil || !strings.Contains(err.Error(), header) {
			t.Errorf("existing %s error = %v", header, err)
		}
	}
	mixedCase, _ := http.NewRequest(http.MethodPost, httpTestOrigin+"/items", strings.NewReader("body"))
	mixedCase.Header["authorization"] = []string{"Bearer application-token"}
	if _, err := transport.RoundTrip(mixedCase); err == nil || !strings.Contains(err.Error(), "Authorization") {
		t.Errorf("noncanonical Authorization conflict error = %v", err)
	}

	crossOrigin, _ := http.NewRequest(http.MethodGet, "https://attacker.example/items", nil)
	if _, err := transport.RoundTrip(crossOrigin); !errors.Is(err, proofhttp.ErrCrossOrigin) {
		t.Errorf("cross-origin error = %v, want ErrCrossOrigin", err)
	}
	oversize, _ := http.NewRequest(http.MethodPost, httpTestOrigin+"/items", strings.NewReader("12345"))
	if _, err := transport.RoundTrip(oversize); !errors.Is(err, proofhttp.ErrBodyTooLarge) {
		t.Errorf("oversize error = %v, want ErrBodyTooLarge", err)
	}
	if got := len(base.snapshot()); got != 0 {
		t.Errorf("base transport received %d rejected requests", got)
	}

}
