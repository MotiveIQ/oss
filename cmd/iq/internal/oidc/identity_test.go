package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bazelbuild/rules_go/go/runfiles"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/pelletier/go-toml/v2"

	sdkconfig "go.motiveiq.dev/platform/iam/sdk/config"
)

var helperRunfile = flag.String("oidc-helper", "", "OIDC helper executable runfile")

type testIssuer struct {
	server                     *httptest.Server
	signer                     jose.Signer
	jwk                        jose.JSONWebKey
	mu                         sync.Mutex
	nonce, challenge, redirect string
	refreshCount               int
	omitRefresh, omitID        bool
	mutate                     func(map[string]any)
	metadata                   func(map[string]any)
}

func newIssuer(t *testing.T) *testIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	f := &testIssuer{signer: signer, jwk: jose.JSONWebKey{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}
	f.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			metadata := map[string]any{"issuer": f.server.URL + "/", "authorization_endpoint": f.server.URL + "/custom/authorize", "token_endpoint": f.server.URL + "/custom/token", "jwks_uri": f.server.URL + "/custom/keys", "response_types_supported": []string{"code"}, "id_token_signing_alg_values_supported": []string{"RS256"}, "token_endpoint_auth_methods_supported": []string{"none"}, "code_challenge_methods_supported": []string{"S256"}}
			if f.metadata != nil {
				f.metadata(metadata)
			}
			_ = json.NewEncoder(w).Encode(metadata)
		case "/custom/keys":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{f.jwk}})
		case "/custom/authorize":
			q := r.URL.Query()
			if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || q.Get("client_id") != "test-client" || q.Get("nonce") == "" || q.Get("state") == "" {
				t.Error("invalid authorization request")
			}
			if strings.Contains(q.Get("scope"), "offline_access") && q.Get("prompt") != "consent" {
				t.Error("offline request omitted consent")
			}
			f.nonce, f.challenge, f.redirect = q.Get("nonce"), q.Get("code_challenge"), q.Get("redirect_uri")
			// A bad callback must not consume the pending authorization.
			bad, err := http.Get(f.redirect + "?state=wrong&code=attacker")
			if err != nil {
				t.Error(err)
			} else {
				bad.Body.Close()
				if bad.StatusCode != 400 {
					t.Error("bad state accepted")
				}
			}
			http.Redirect(w, r, f.redirect+"?"+url.Values{"state": {q.Get("state")}, "code": {"test-code"}, "iss": {f.server.URL + "/"}}.Encode(), http.StatusFound)
		case "/custom/token":
			_ = r.ParseForm()
			if r.Form.Get("client_id") != "test-client" || r.Form.Get("client_secret") != "" || r.Header.Get("Authorization") != "" {
				t.Error("not a public client exchange")
			}
			if r.Form.Get("grant_type") == "authorization_code" {
				hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				if base64.RawURLEncoding.EncodeToString(hash[:]) != f.challenge || r.Form.Get("redirect_uri") != f.redirect {
					t.Error("PKCE or redirect mismatch")
				}
			} else if r.Form.Get("grant_type") == "refresh_token" {
				if r.Form.Get("refresh_token") != fmt.Sprintf("refresh-%d", f.refreshCount) {
					t.Error("refresh token reused after rotation")
				}
				f.refreshCount++
			} else {
				t.Error("unexpected grant")
			}
			response := map[string]any{"access_token": "opaque-access-token", "token_type": "Bearer", "expires_in": 3600}
			if !f.omitRefresh {
				response["refresh_token"] = fmt.Sprintf("refresh-%d", f.refreshCount)
			}
			if !f.omitID {
				response["id_token"] = f.sign(t, f.claims())
			}
			_ = json.NewEncoder(w).Encode(response)
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *testIssuer) claims() map[string]any {
	claims := map[string]any{"iss": f.server.URL + "/", "sub": "user", "aud": []string{"test-client"}, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(), "nonce": f.nonce, "auth_time": 1}
	if f.mutate != nil {
		f.mutate(claims)
	}
	return claims
}
func (f *testIssuer) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	data, _ := json.Marshal(claims)
	object, err := f.signer.Sign(data)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func (f *testIssuer) source(t *testing.T) *oidcSource {
	t.Helper()
	s, err := newOIDCSource(sdkconfig.SourceConfig{"issuer": f.server.URL + "/", "client_id": "test-client", "scopes": []string{"openid", "offline_access"}, "token_file": filepath.Join(t.TempDir(), "private", "tokens.json")})
	if err != nil {
		t.Fatal(err)
	}
	s.client = f.server.Client()
	s.openURL = func(address string) error {
		response, err := f.server.Client().Get(address)
		if err == nil {
			response.Body.Close()
		}
		return err
	}
	return s
}
func login(t *testing.T, s *oidcSource) {
	t.Helper()
	if err := s.Login(t.Context(), io.Discard); err != nil {
		t.Fatal(err)
	}
}
func expire(t *testing.T, s *oidcSource, f *testIssuer) {
	t.Helper()
	err := s.update(t.Context(), func(c *credentials) (*credentials, error) {
		claims := f.claims()
		claims["exp"] = time.Now().Add(-time.Minute).Unix()
		c.IDToken = f.sign(t, claims)
		c.Token.Expiry = time.Now().Add(-time.Minute)
		return c, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDiscoveryLoginIDTokenAndOptionalRefresh(t *testing.T) {
	f := newIssuer(t)
	f.omitRefresh = true
	s := f.source(t)
	login(t, s)
	id, err := s.token(t.Context(), false)
	if err != nil || id.Token == "opaque-access-token" || id.ExpiresAt == nil {
		t.Fatalf("ID token result: %v", err)
	}
	access, err := s.token(t.Context(), true)
	if err != nil || access.Token != "opaque-access-token" {
		t.Fatalf("access result: %v", err)
	}
	expire(t, s, f)
	if _, err := s.token(t.Context(), false); !errors.Is(err, errLoginRequired) {
		t.Fatalf("expired nonrefreshable login: %v", err)
	}
}

func TestRejectInvalidIdentityAndDiscovery(t *testing.T) {
	mutations := map[string]func(map[string]any){
		"issuer":              func(c map[string]any) { c["iss"] = "https://other.example/" },
		"audience":            func(c map[string]any) { c["aud"] = []string{"another-client"} },
		"additional-audience": func(c map[string]any) { c["aud"] = []string{"test-client", "another-client"} },
		"azp":                 func(c map[string]any) { c["azp"] = "another-client" },
		"nonce":               func(c map[string]any) { c["nonce"] = "wrong" },
		"expired":             func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() },
		"subject":             func(c map[string]any) { delete(c, "sub") },
		"issued-at":           func(c map[string]any) { delete(c, "iat") },
		"authentication-time": func(c map[string]any) { c["auth_time"] = "invalid" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			f := newIssuer(t)
			f.mutate = mutate
			s := f.source(t)
			if err := s.Login(t.Context(), io.Discard); err == nil {
				t.Fatal("invalid identity accepted")
			}
			if _, err := os.Stat(s.path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid login cached")
			}
		})
	}
	for _, kind := range []string{"issuer", "endpoint", "pkce"} {
		t.Run("discovery-"+kind, func(t *testing.T) {
			f := newIssuer(t)
			f.metadata = func(c map[string]any) {
				switch kind {
				case "issuer":
					c["issuer"] = "https://other.example"
				case "endpoint":
					c["token_endpoint"] = "http://example.com/token"
				case "pkce":
					c["code_challenge_methods_supported"] = []string{"plain"}
				}
			}
			s := f.source(t)
			if err := s.Login(t.Context(), io.Discard); err == nil {
				t.Fatal("bad discovery accepted")
			}
		})
	}
}

func TestConcurrentRotationAndRefreshIdentity(t *testing.T) {
	f := newIssuer(t)
	s := f.source(t)
	login(t, s)
	expire(t, s, f)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.token(t.Context(), false); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if f.refreshCount != 1 {
		t.Fatalf("refreshes=%d", f.refreshCount)
	}
	expire(t, s, f)
	f.mutate = func(c map[string]any) { c["sub"] = "different-user" }
	if _, err := s.token(t.Context(), false); err == nil {
		t.Fatal("refresh changed subject")
	}
}

func TestRefreshWithoutIDTokenPreservesRotation(t *testing.T) {
	f := newIssuer(t)
	s := f.source(t)
	login(t, s)
	expire(t, s, f)
	f.omitID = true
	if _, err := s.token(t.Context(), false); !errors.Is(err, errLoginRequired) {
		t.Fatalf("missing ID token: %v", err)
	}
	if _, err := s.token(t.Context(), false); !errors.Is(err, errLoginRequired) {
		t.Fatalf("second request: %v", err)
	}
	if f.refreshCount != 1 {
		t.Fatal("repeated refresh without usable ID token")
	}
	data, _ := os.ReadFile(s.path)
	var record credentials
	_ = json.Unmarshal(data, &record)
	if record.Token.RefreshToken != "refresh-1" {
		t.Fatal("rotation lost")
	}
	if _, err := s.token(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestCacheBindingPermissionsAndCancellation(t *testing.T) {
	f := newIssuer(t)
	s := f.source(t)
	login(t, s)
	other := *s
	other.binding = "another-profile"
	if _, err := other.token(t.Context(), false); !errors.Is(err, errLoginRequired) {
		t.Fatal("source reused another cache")
	}
	if err := os.Chmod(s.path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.token(t.Context(), false); err == nil {
		t.Fatal("public token file accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.token(ctx, false); err == nil {
		t.Fatal("cancelled request succeeded")
	}
}

func TestSDKInvokesOIDCHelperAsExternalTokenProcess(t *testing.T) {
	f := newIssuer(t)
	s := f.source(t)
	login(t, s)
	helper, err := runfiles.Rlocation(*helperRunfile)
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", certPath)
	config := sdkconfig.FileConfig{Profiles: map[string]sdkconfig.Profile{"default": {RoleURN: "urn:motiveiq:iam:role/example", WebIdentitySource: "process"}}, WebIdentitySources: map[string]sdkconfig.Source{
		"process": {Type: "process", Config: sdkconfig.SourceConfig{"command": []string{helper, "token", "test"}}},
		"test":    {Type: "oidc", Config: sdkconfig.SourceConfig{"issuer": s.config.Issuer, "client_id": "test-client", "scopes": s.config.Scopes, "token_file": s.path}},
	}}
	data, _ := toml.Marshal(config)
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(sdkconfig.ConfigFileEnv, path)
	t.Setenv(sdkconfig.ProfileEnv, "default")
	identity, err := (sdkconfig.Resolver{}).Resolve("")
	if err != nil {
		t.Fatal(err)
	}
	token, err := identity.Provider.RetrieveWebIdentityToken(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if token == "opaque-access-token" || len(strings.Split(token, ".")) != 3 {
		t.Fatal("helper did not return ID token")
	}
	if err := os.Remove(s.path); err != nil {
		t.Fatal(err)
	}
	if _, err := identity.Provider.RetrieveWebIdentityToken(t.Context()); err == nil {
		t.Fatal("missing cache did not fail")
	}
}

func TestConfigHasNoProviderDefaults(t *testing.T) {
	for _, settings := range []sdkconfig.SourceConfig{{}, {"issuer": "http://example.com", "client_id": "client"}, {"issuer": "https://example.com", "client_id": "client", "authorization_params": map[string]string{"nonce": "fixed"}}} {
		if _, err := newOIDCSource(settings); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	s, err := newOIDCSource(sdkconfig.SourceConfig{"issuer": "https://example.com/", "client_id": "client"})
	if err != nil {
		t.Fatal(err)
	}
	if s.config.CallbackPort != 0 || len(s.config.Scopes) != 1 || s.config.Scopes[0] != "openid" {
		t.Fatal("unexpected defaults")
	}
}

func TestProcessExportContainsNoCredentialsAndRejectsSymlink(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	command := []string{"/usr/local/bin/iq-oidc", "--config-file", "/custom/config.toml", "access-token", "source"}
	if err := exportProcess("oauth/credentials.json", command); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(base, "oauth/credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if json.Unmarshal(data, &record) != nil || len(record) != 1 || record["credential_process"] == nil {
		t.Fatal("export contains more than a process locator")
	}
	link := filepath.Join(base, "link.json")
	if err := os.Symlink(filepath.Join(base, "oauth/credentials.json"), link); err != nil {
		t.Fatal(err)
	}
	if err := exportProcess(link, command); err == nil {
		t.Fatal("export followed symlink")
	}
	if err := exportProcess("../outside.json", command); err == nil {
		t.Fatal("export escaped config home")
	}
}

func TestInvalidSignatureIsNotRefreshed(t *testing.T) {
	f := newIssuer(t)
	s := f.source(t)
	login(t, s)
	err := s.update(t.Context(), func(c *credentials) (*credentials, error) {
		parts := strings.Split(c.IDToken, ".")
		parts[2] = "invalid-signature"
		c.IDToken = strings.Join(parts, ".")
		return c, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.token(t.Context(), false); err == nil {
		t.Fatal("invalid signature accepted")
	}
	if f.refreshCount != 0 {
		t.Fatal("unverified cache was refreshed")
	}
}
