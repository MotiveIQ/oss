package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthorizationURLIncludesPKCEChallenge(t *testing.T) {
	got := AuthorizationURL(AuthorizationOptions{
		Issuer:       "https://issuer.example/",
		ClientID:     "iq-cli",
		RedirectURI:  "http://127.0.0.1:48195/callback",
		Scopes:       []string{"openid", "offline_access"},
		Audience:     "https://build.example",
		State:        "state",
		Nonce:        "nonce",
		CodeVerifier: "verifier",
	})
	if want := "code_challenge=iMnq5o6zALKXGivsnlom_0F5_WYda32GHkxlV7mq7hQ"; !strings.Contains(got, want) {
		t.Fatalf("authorization URL missing %s: %s", want, got)
	}
	if want := "scope=openid+offline_access"; !strings.Contains(got, want) {
		t.Fatalf("authorization URL missing %s: %s", want, got)
	}
}

func TestCredentialsFromTokenResponseUsesExpiryFields(t *testing.T) {
	now := time.Unix(1000, 0)
	credentials, err := CredentialsFromTokenResponse(map[string]any{
		"access_token":       "access-token",
		"expires_in":         float64(3600),
		"refresh_expires_in": float64(7200),
		"refresh_token":      "refresh-token",
	}, CredentialOptions{
		Issuer:   "https://issuer.example/",
		ClientID: "iq-cli",
		Audience: "https://build.example",
		Scopes:   []string{"openid"},
		Now:      now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if credentials["issuer"] != "https://issuer.example" {
		t.Fatalf("unexpected issuer: %#v", credentials["issuer"])
	}
	if credentials["expires_at"] != int64(4600) {
		t.Fatalf("unexpected expires_at: %#v", credentials["expires_at"])
	}
	if credentials["refresh_expires_at"] != int64(8200) {
		t.Fatalf("unexpected refresh_expires_at: %#v", credentials["refresh_expires_at"])
	}
}

func TestSaveCredentialsWritesPrivateJSON(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "nested", "credentials.json")
	t.Setenv(TokenFileEnv, tokenFile)

	destination, err := SaveCredentials(Credentials{
		"access_token":  "access-token",
		"refresh_token": "refresh-token",
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if destination != tokenFile {
		t.Fatalf("expected %s, got %s", tokenFile, destination)
	}

	payload, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["access_token"] != "access-token" {
		t.Fatalf("unexpected payload: %#v", decoded)
	}
	if mode := fileMode(t, tokenFile); mode != 0o600 {
		t.Fatalf("expected token file mode 0600, got %#o", mode)
	}
	if mode := fileMode(t, filepath.Dir(tokenFile)); mode != 0o700 {
		t.Fatalf("expected token directory mode 0700, got %#o", mode)
	}
}

func TestSaveCredentialsLeavesExistingParentMode(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	before := fileMode(t, parent)

	if _, err := SaveCredentials(Credentials{"access_token": "access-token"}, filepath.Join(parent, "credentials.json")); err != nil {
		t.Fatal(err)
	}
	if after := fileMode(t, parent); after != before {
		t.Fatalf("expected parent mode %#o to be untouched, got %#o", before, after)
	}
}

func TestSaveCredentialsConcurrentWriters(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "nested", "credentials.json")
	const writers = 8
	start := make(chan struct{})
	results := make(chan error, writers)
	for i := range writers {
		go func() {
			<-start
			_, err := SaveCredentials(Credentials{"access_token": fmt.Sprintf("access-token-%d", i)}, tokenFile)
			results <- err
		}()
	}
	close(start)
	for range writers {
		if err := <-results; err != nil {
			t.Fatalf("concurrent SaveCredentials failed: %v", err)
		}
	}

	credentials, _, err := LoadCredentials(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	accessToken, _ := credentials["access_token"].(string)
	if !strings.HasPrefix(accessToken, "access-token-") {
		t.Fatalf("unexpected access_token after concurrent writes: %#v", credentials["access_token"])
	}
	if mode := fileMode(t, tokenFile); mode != 0o600 {
		t.Fatalf("expected token file mode 0600, got %#o", mode)
	}
	entries, err := os.ReadDir(filepath.Dir(tokenFile))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected only the credential file to remain, got %d entries", len(entries))
	}
}

func TestAccessTokenFromStoreRefreshesForDeployAudience(t *testing.T) {
	var formScope string
	var formAudience string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		formScope = r.Form.Get("scope")
		formAudience = r.Form.Get("audience")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"deploy-token","expires_in":3600,"refresh_token":"new-refresh"}`))
	}))
	defer server.Close()

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "credentials.json")
	t.Setenv(TokenFileEnv, tokenFile)
	_, err := SaveCredentials(Credentials{
		"access_token":  "old-token",
		"audience":      BuildAudience,
		"client_id":     DefaultClientID,
		"expires_at":    int64(1000),
		"issuer":        "https://issuer.example",
		"refresh_token": "refresh-token",
		"scope":         "openid build:read build:write",
		"token_url":     server.URL,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	token, err := AccessTokenFromStore(context.Background(), AccessTokenOptions{
		RequiredAudience: DeployAudience,
		RequiredScopes:   []string{"deploy:read", "deploy:write"},
		Now:              func() time.Time { return time.Unix(2000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if token != "deploy-token" {
		t.Fatalf("unexpected token: %q", token)
	}
	if formAudience != DefaultAudience {
		t.Fatalf("unexpected audience: %q", formAudience)
	}
	if formScope != strings.Join(DefaultScopes, " ") {
		t.Fatalf("unexpected scope: %q", formScope)
	}

	credentials, _, err := LoadCredentials("")
	if err != nil {
		t.Fatal(err)
	}
	if credentials["access_token"] != "deploy-token" {
		t.Fatalf("refreshed credentials were not saved: %#v", credentials)
	}
}

func TestDefaultLoginGrantsIncludeBlobData(t *testing.T) {
	if !strings.Contains(DefaultAudience, BlobAudience) {
		t.Fatalf("default audience %q does not include %q", DefaultAudience, BlobAudience)
	}
	scopes := " " + strings.Join(DefaultScopes, " ") + " "
	for _, scope := range []string{"blob:read", "blob:write"} {
		if !strings.Contains(scopes, " "+scope+" ") {
			t.Fatalf("default scopes %#v do not include %q", DefaultScopes, scope)
		}
	}
}

func TestAccessTokenFromStoreRejectsRefreshWithoutDeployGrants(t *testing.T) {
	accessToken := testJWT(t, map[string]any{
		"aud": BuildAudience,
		"exp": float64(5000),
		"scp": []string{"openid", "build:read", "build:write"},
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  accessToken,
			"expires_in":    3600,
			"refresh_token": "new-refresh",
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "credentials.json")
	t.Setenv(TokenFileEnv, tokenFile)
	_, err := SaveCredentials(Credentials{
		"access_token":  "old-token",
		"audience":      BuildAudience,
		"client_id":     DefaultClientID,
		"expires_at":    int64(1000),
		"issuer":        "https://issuer.example",
		"refresh_token": "refresh-token",
		"scope":         "openid build:read build:write",
		"token_url":     server.URL,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = AccessTokenFromStore(context.Background(), AccessTokenOptions{
		RequiredAudience: DeployAudience,
		RequiredScopes:   []string{"deploy:read", "deploy:write"},
		Now:              func() time.Time { return time.Unix(2000, 0) },
	})
	if err == nil || !strings.Contains(err.Error(), "run iq login") {
		t.Fatalf("expected login error, got %v", err)
	}

	credentials, _, err := LoadCredentials("")
	if err != nil {
		t.Fatal(err)
	}
	if credentials["access_token"] != "old-token" {
		t.Fatalf("invalid refresh should not be saved: %#v", credentials)
	}
}

func TestAccessTokenFromStoreRequiresFreshLoginForPlatformAudience(t *testing.T) {
	// Credentials stored before PlatformAudience existed carry only the
	// legacy audiences. Hydra binds the audience at consent, so a refresh
	// cannot mint the platform audience; the flow must land on the standing
	// "run iq login" error instead of returning a stale-audience token.
	accessToken := testJWT(t, map[string]any{
		"aud": []string{BuildAudience, DeployAudience, BlobAudience},
		"exp": float64(5000),
		"scp": DefaultScopes,
	})
	var formAudience string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		formAudience = r.Form.Get("audience")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  accessToken,
			"expires_in":    3600,
			"refresh_token": "new-refresh",
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "credentials.json")
	t.Setenv(TokenFileEnv, tokenFile)
	_, err := SaveCredentials(Credentials{
		"access_token":  "old-token",
		"audience":      BuildAudience + " " + DeployAudience + " " + BlobAudience,
		"client_id":     DefaultClientID,
		"expires_at":    int64(9000),
		"issuer":        "https://issuer.example",
		"refresh_token": "refresh-token",
		"scope":         strings.Join(DefaultScopes, " "),
		"token_url":     server.URL,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = AccessTokenFromStore(context.Background(), AccessTokenOptions{
		RequiredAudience: PlatformAudience,
		Now:              func() time.Time { return time.Unix(2000, 0) },
	})
	if err == nil || !strings.Contains(err.Error(), "run iq login") {
		t.Fatalf("expected login error, got %v", err)
	}
	if !strings.Contains(" "+formAudience+" ", " "+PlatformAudience+" ") {
		t.Fatalf("refresh did not request the platform audience: %q", formAudience)
	}

	credentials, _, err := LoadCredentials("")
	if err != nil {
		t.Fatal(err)
	}
	if credentials["access_token"] != "old-token" {
		t.Fatalf("stale-audience refresh should not be saved: %#v", credentials)
	}
}

// TestAccessTokenFromStoreAnyScopesAcceptsNarrowedConsent pins the
// audience-only requirement. Empty RequiredScopes means "unset" and takes
// the full requested set, so a caller needing an audience alone has to say
// AnyScopes; otherwise a user who consented to a subset is refused a token
// they already hold, and refreshing cannot help — consent, not the refresh,
// fixes the scope set.
func TestAccessTokenFromStoreAnyScopesAcceptsNarrowedConsent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a valid stored token must not be refreshed")
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	dir := t.TempDir()
	t.Setenv(TokenFileEnv, filepath.Join(dir, "credentials.json"))
	_, err := SaveCredentials(Credentials{
		"access_token":  "platform-token",
		"audience":      PlatformAudience,
		"client_id":     DefaultClientID,
		"expires_at":    int64(9000),
		"issuer":        "https://issuer.example",
		"refresh_token": "refresh-token",
		"scope":         "openid profile email offline_access",
		"token_url":     server.URL,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	token, err := AccessTokenFromStore(context.Background(), AccessTokenOptions{
		RequiredAudience: PlatformAudience,
		AnyScopes:        true,
		Now:              func() time.Time { return time.Unix(2000, 0) },
	})
	if err != nil {
		t.Fatalf("narrowed consent should still yield a token: %v", err)
	}
	if token != "platform-token" {
		t.Fatalf("unexpected token: %q", token)
	}
}

// TestAccessTokenFromStoreAnyScopesStillChecksAudience keeps AnyScopes from
// widening into "require nothing": the audience is the one thing the STS
// exchange cannot work without.
func TestAccessTokenFromStoreAnyScopesStillChecksAudience(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": testJWT(t, map[string]any{
				"aud": []string{BuildAudience},
				"exp": float64(9000),
				"scp": DefaultScopes,
			}),
			"expires_in":    3600,
			"refresh_token": "new-refresh",
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	t.Setenv(TokenFileEnv, filepath.Join(dir, "credentials.json"))
	_, err := SaveCredentials(Credentials{
		"access_token":  "build-token",
		"audience":      BuildAudience,
		"client_id":     DefaultClientID,
		"expires_at":    int64(9000),
		"issuer":        "https://issuer.example",
		"refresh_token": "refresh-token",
		"scope":         strings.Join(DefaultScopes, " "),
		"token_url":     server.URL,
	}, "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = AccessTokenFromStore(context.Background(), AccessTokenOptions{
		RequiredAudience: PlatformAudience,
		AnyScopes:        true,
		Now:              func() time.Time { return time.Unix(2000, 0) },
	})
	if err == nil || !strings.Contains(err.Error(), "run iq login") {
		t.Fatalf("expected login error, got %v", err)
	}
}

func TestWaitForCallbackWritesResponseBeforeClosing(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	ready := make(chan struct{})
	result := make(chan callbackResult, 1)
	go func() {
		code, err := waitForCallback(context.Background(), "127.0.0.1", port, "/callback", "state", time.Second, func() {
			close(ready)
		})
		result <- callbackResult{code: code, err: err}
	}()
	<-ready

	staleResponse, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?state=stale&code=stale", port))
	if err != nil {
		t.Fatal(err)
	}
	if staleResponse.StatusCode != http.StatusBadRequest {
		t.Fatalf("unexpected stale callback status: %d", staleResponse.StatusCode)
	}
	if err := staleResponse.Body.Close(); err != nil {
		t.Fatal(err)
	}

	response, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?state=state&code=code", port))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	closeErr := response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "Login complete") {
		t.Fatalf("unexpected callback response: status=%d body=%q", response.StatusCode, body)
	}

	callback := <-result
	if callback.err != nil {
		t.Fatal(callback.err)
	}
	if callback.code != "code" {
		t.Fatalf("unexpected callback code: %q", callback.code)
	}
}

func testJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return "header." + base64.RawURLEncoding.EncodeToString(encoded) + ".signature"
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}
