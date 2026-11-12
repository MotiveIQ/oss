package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultIssuer   = "https://auth.platform.motiveiq.net"
	DefaultClientID = "iq-cli"
	// PlatformAudience is the unified audience going forward
	// (platform/iam/HUMAN-IDENTITY.md); the legacy per-service audiences
	// stay in DefaultAudience until the fleet re-logs in, so one token
	// stays valid everywhere during the transition.
	PlatformAudience           = "https://platform.motiveiq.net"
	BuildAudience              = "https://build.platform.motiveiq.net"
	DeployAudience             = "https://deploy.platform.motiveiq.net"
	BlobAudience               = "https://blob.platform.motiveiq.net"
	DefaultAudience            = PlatformAudience + " " + BuildAudience + " " + DeployAudience + " " + BlobAudience
	DefaultCallbackHost        = "127.0.0.1"
	DefaultCallbackPort        = 48195
	DefaultCallbackPath        = "/callback"
	DefaultLoginTimeout        = 300 * time.Second
	DefaultRefreshTokenSeconds = 30 * 24 * 60 * 60
	RefreshSkew                = 5 * time.Minute
	TokenFileEnv               = "MOTIVEIQ_IQ_TOKEN_FILE"
	BazelTokenFileEnv          = "MOTIVEIQ_BAZEL_RBE_TOKEN_FILE"
)

var DefaultScopes = []string{
	"openid",
	"profile",
	"email",
	"offline_access",
	"build:read",
	"build:write",
	"deploy:read",
	"deploy:write",
	"blob:read",
	"blob:write",
}

type Credentials map[string]any

type AccessTokenOptions struct {
	Path             string
	Audience         string
	Scopes           []string
	RequiredAudience string
	RequiredScopes   []string
	// AnyScopes accepts whatever scope set the stored credentials carry,
	// checking the audience alone. An empty RequiredScopes reads as "unset"
	// and takes the whole requested set, so without this flag a caller that
	// needs only an audience demands every scope in Scopes — an ask no
	// consent-narrowed login satisfies and no refresh can repair, since a
	// refresh never adds a scope consent withheld.
	AnyScopes  bool
	HTTPClient *http.Client
	Now        func() time.Time
}

type LoginOptions struct {
	Issuer         string
	ClientID       string
	Audience       string
	Scopes         []string
	CallbackHost   string
	CallbackPort   int
	CallbackPath   string
	OpenBrowser    bool
	Timeout        time.Duration
	Output         io.Writer
	HTTPClient     *http.Client
	OpenURL        func(string) error
	TokenGenerator func(int) (string, error)
	Now            func() time.Time
}

func LoginWithBrowser(ctx context.Context, options LoginOptions) (Credentials, error) {
	options = options.withDefaults()

	issuer, err := NormalizeIssuer(options.Issuer)
	if err != nil {
		return nil, err
	}
	verifier, err := options.TokenGenerator(64)
	if err != nil {
		return nil, err
	}
	state, err := options.TokenGenerator(32)
	if err != nil {
		return nil, err
	}
	nonce, err := options.TokenGenerator(32)
	if err != nil {
		return nil, err
	}

	redirectURI := fmt.Sprintf("http://%s:%d%s", options.CallbackHost, options.CallbackPort, options.CallbackPath)
	authURL := AuthorizationURL(AuthorizationOptions{
		Issuer:       issuer,
		ClientID:     options.ClientID,
		RedirectURI:  redirectURI,
		Scopes:       options.Scopes,
		Audience:     options.Audience,
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
	})

	code, err := waitForCallback(ctx, options.CallbackHost, options.CallbackPort, options.CallbackPath, state, options.Timeout, func() {
		fmt.Fprintln(options.Output, "Open this URL to log in:")
		fmt.Fprintln(options.Output, authURL)
		if options.OpenBrowser {
			_ = options.OpenURL(authURL)
		}
	})
	if err != nil {
		return nil, err
	}

	tokenResponse, err := RequestToken(ctx, TokenEndpoint(issuer), url.Values{
		"client_id":     {options.ClientID},
		"code":          {code},
		"code_verifier": {verifier},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {redirectURI},
	}, options.HTTPClient)
	if err != nil {
		return nil, err
	}

	return CredentialsFromTokenResponse(tokenResponse, CredentialOptions{
		Issuer:   issuer,
		ClientID: options.ClientID,
		Audience: options.Audience,
		Scopes:   options.Scopes,
		Now:      options.Now(),
	})
}

func (o LoginOptions) withDefaults() LoginOptions {
	if o.Issuer == "" {
		o.Issuer = DefaultIssuer
	}
	if o.ClientID == "" {
		o.ClientID = DefaultClientID
	}
	if o.Audience == "" {
		o.Audience = DefaultAudience
	}
	if len(o.Scopes) == 0 {
		o.Scopes = append([]string(nil), DefaultScopes...)
	}
	if o.CallbackHost == "" {
		o.CallbackHost = DefaultCallbackHost
	}
	if o.CallbackPort == 0 {
		o.CallbackPort = DefaultCallbackPort
	}
	if o.CallbackPath == "" {
		o.CallbackPath = DefaultCallbackPath
	}
	if o.Timeout == 0 {
		o.Timeout = DefaultLoginTimeout
	}
	if o.Output == nil {
		o.Output = io.Discard
	}
	if o.HTTPClient == nil {
		o.HTTPClient = http.DefaultClient
	}
	if o.OpenURL == nil {
		o.OpenURL = openBrowser
	}
	if o.TokenGenerator == nil {
		o.TokenGenerator = TokenURLSafe
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

type AuthorizationOptions struct {
	Issuer       string
	ClientID     string
	RedirectURI  string
	Scopes       []string
	Audience     string
	State        string
	Nonce        string
	CodeVerifier string
}

func AuthorizationURL(options AuthorizationOptions) string {
	values := url.Values{
		"audience":              {options.Audience},
		"client_id":             {options.ClientID},
		"code_challenge":        {PKCEChallenge(options.CodeVerifier)},
		"code_challenge_method": {"S256"},
		"nonce":                 {options.Nonce},
		"redirect_uri":          {options.RedirectURI},
		"response_type":         {"code"},
		"scope":                 {strings.Join(options.Scopes, " ")},
		"state":                 {options.State},
	}
	return AuthorizationEndpoint(options.Issuer) + "?" + values.Encode()
}

func NormalizeIssuer(issuer string) (string, error) {
	normalized := strings.TrimRight(strings.TrimSpace(issuer), "/")
	if normalized == "" {
		return "", errors.New("OAuth issuer is required")
	}
	return normalized, nil
}

func AuthorizationEndpoint(issuer string) string {
	normalized, _ := NormalizeIssuer(issuer)
	return normalized + "/oauth2/auth"
}

func TokenEndpoint(issuer string) string {
	normalized, _ := NormalizeIssuer(issuer)
	return normalized + "/oauth2/token"
}

func RequestToken(ctx context.Context, tokenURL string, form url.Values, httpClient *http.Client) (map[string]any, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer response.Body.Close()

	payload, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		detail := strings.TrimSpace(string(payload))
		if detail != "" {
			return nil, fmt.Errorf("token request failed with HTTP %d: %s", response.StatusCode, detail)
		}
		return nil, fmt.Errorf("token request failed with HTTP %d", response.StatusCode)
	}

	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	return decoded, nil
}

type CredentialOptions struct {
	Issuer   string
	ClientID string
	Audience string
	Scopes   []string
	Previous Credentials
	Now      time.Time
}

func CredentialsFromTokenResponse(response map[string]any, options CredentialOptions) (Credentials, error) {
	accessToken, _ := response["access_token"].(string)
	if accessToken == "" {
		return nil, errors.New("token response did not include access_token")
	}

	refreshToken, _ := response["refresh_token"].(string)
	if refreshToken == "" && options.Previous != nil {
		refreshToken, _ = options.Previous["refresh_token"].(string)
	}
	if options.Now.IsZero() {
		options.Now = time.Now()
	}
	issuer, err := NormalizeIssuer(defaultString(options.Issuer, DefaultIssuer))
	if err != nil {
		return nil, err
	}
	clientID := defaultString(options.ClientID, DefaultClientID)
	audience := defaultString(options.Audience, DefaultAudience)
	scopes := options.Scopes
	if len(scopes) == 0 {
		scopes = DefaultScopes
	}
	if tokenAudiences, tokenScopes, ok := jwtGrants(accessToken); ok {
		audience = strings.Join(tokenAudiences, " ")
		scopes = tokenScopes
	} else if responseScope := stringField(response, "scope"); responseScope != "" {
		scopes = strings.Fields(responseScope)
	}
	tokenType := defaultString(stringField(response, "token_type"), "Bearer")

	return Credentials{
		"access_token":       accessToken,
		"audience":           audience,
		"client_id":          clientID,
		"expires_at":         expiresAt(response, accessToken, options.Now),
		"issuer":             issuer,
		"obtained_at":        options.Now.Unix(),
		"refresh_expires_at": refreshExpiresAt(response, options.Previous, options.Now),
		"refresh_token":      refreshToken,
		"scope":              strings.Join(scopes, " "),
		"token_type":         tokenType,
		"token_url":          TokenEndpoint(issuer),
	}, nil
}

func SaveCredentials(credentials Credentials, path string) (string, error) {
	destination, err := TokenFilePath(path)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", err
	}
	// Only a directory MkdirAll just created is ours to lock down. A
	// caller-chosen credential location (TokenFileEnv, BazelTokenFileEnv) may
	// live in a shared or unowned directory, where chmod would either strip
	// collaborators' access or fail outright and take every iq command with
	// it. The file's own 0600 is what actually protects the token.

	// Concurrent iq processes each write their own temp file: a shared fixed
	// name lets two writers interleave into one inode, and LoadCredentials
	// rejects the resulting malformed JSON until the user deletes the file.
	file, err := os.CreateTemp(parent, filepath.Base(destination)+".*.tmp")
	if err != nil {
		return "", err
	}
	tmp := file.Name()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return "", err
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	writeErr := encoder.Encode(credentials)
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(tmp)
		return "", writeErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return "", closeErr
	}
	if err := os.Rename(tmp, destination); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return destination, nil
}

func LoadCredentials(path string) (Credentials, string, error) {
	source, err := TokenFilePath(path)
	if err != nil {
		return nil, "", err
	}
	payload, err := os.ReadFile(source)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, source, nil
		}
		return nil, source, err
	}
	var credentials Credentials
	if err := json.Unmarshal(payload, &credentials); err != nil {
		return nil, source, fmt.Errorf("credential file %s is not valid JSON: %w", source, err)
	}
	return credentials, source, nil
}

func AccessTokenFromStore(ctx context.Context, options AccessTokenOptions) (string, error) {
	options = options.withDefaults()
	credentials, source, err := LoadCredentials(options.Path)
	if err != nil {
		return "", err
	}
	if credentials == nil {
		return "", fmt.Errorf("not logged in; run iq login")
	}
	accessToken, _ := credentials["access_token"].(string)
	if accessToken != "" && tokenIsFresh(credentials, options.Now()) && credentialsAllow(credentials, options.RequiredAudience, options.RequiredScopes) {
		return accessToken, nil
	}

	refreshed, err := RefreshCredentials(ctx, credentials, options)
	if err != nil {
		return "", err
	}
	if !credentialsAllow(refreshed, options.RequiredAudience, options.RequiredScopes) {
		return "", errors.New("refreshed credentials do not include the required audience and scopes; run iq login")
	}
	if _, err := SaveCredentials(refreshed, source); err != nil {
		return "", err
	}
	refreshedAccessToken, _ := refreshed["access_token"].(string)
	if refreshedAccessToken == "" {
		return "", errors.New("token refresh did not return an access token")
	}
	return refreshedAccessToken, nil
}

func RefreshCredentials(ctx context.Context, credentials Credentials, options AccessTokenOptions) (Credentials, error) {
	options = options.withDefaults()
	refreshToken, _ := credentials["refresh_token"].(string)
	if refreshToken == "" {
		return nil, errors.New("credential file does not include refresh_token; run iq login")
	}

	issuer, err := NormalizeIssuer(defaultString(stringField(credentials, "issuer"), DefaultIssuer))
	if err != nil {
		return nil, err
	}
	clientID := defaultString(stringField(credentials, "client_id"), DefaultClientID)
	form := url.Values{
		"client_id":     {clientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	if options.Audience != "" {
		form.Set("audience", options.Audience)
	}
	if len(options.Scopes) > 0 {
		form.Set("scope", strings.Join(options.Scopes, " "))
	}

	response, err := RequestToken(ctx, defaultString(stringField(credentials, "token_url"), TokenEndpoint(issuer)), form, options.HTTPClient)
	if err != nil {
		return nil, err
	}
	return CredentialsFromTokenResponse(response, CredentialOptions{
		Issuer:   issuer,
		ClientID: clientID,
		Audience: options.Audience,
		Scopes:   options.Scopes,
		Previous: credentials,
		Now:      options.Now(),
	})
}

func TokenFilePath(path string) (string, error) {
	if path != "" {
		return expandUser(path)
	}
	if envPath := os.Getenv(TokenFileEnv); envPath != "" {
		return expandUser(envPath)
	}
	if envPath := os.Getenv(BazelTokenFileEnv); envPath != "" {
		return expandUser(envPath)
	}

	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		configHome = filepath.Join(home, ".config")
	}
	return filepath.Join(configHome, "motiveiq", "iq", "credentials.json"), nil
}

func (o AccessTokenOptions) withDefaults() AccessTokenOptions {
	if o.Audience == "" {
		o.Audience = DefaultAudience
	}
	if len(o.Scopes) == 0 {
		o.Scopes = append([]string(nil), DefaultScopes...)
	}
	if o.RequiredAudience == "" {
		o.RequiredAudience = o.Audience
	}
	// AnyScopes wins over RequiredScopes, so setting both is a stated
	// requirement of "none" rather than a silent contradiction.
	if o.AnyScopes {
		o.RequiredScopes = nil
	} else if len(o.RequiredScopes) == 0 {
		o.RequiredScopes = append([]string(nil), o.Scopes...)
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.HTTPClient == nil {
		o.HTTPClient = http.DefaultClient
	}
	return o
}

func tokenIsFresh(credentials Credentials, now time.Time) bool {
	expiresAt, ok := number(credentials["expires_at"])
	if !ok {
		exp, ok := jwtExp(stringField(credentials, "access_token"))
		if !ok {
			return true
		}
		expiresAt = exp
	}
	return time.Unix(expiresAt, 0).After(now.Add(RefreshSkew))
}

func credentialsAllow(credentials Credentials, audience string, scopes []string) bool {
	if audience != "" && !containsWord(stringField(credentials, "audience"), audience) {
		return false
	}
	for _, scope := range scopes {
		if !containsWord(stringField(credentials, "scope"), scope) {
			return false
		}
	}
	return true
}

func containsWord(value, target string) bool {
	for _, field := range strings.Fields(value) {
		if field == target {
			return true
		}
	}
	return false
}

func FormatTimestamp(value any) string {
	seconds, ok := number(value)
	if !ok {
		return "unknown"
	}
	return time.Unix(int64(seconds), 0).UTC().Format("2006-01-02T15:04:05+00:00")
}

func TokenURLSafe(bytesCount int) (string, error) {
	payload := make([]byte, bytesCount)
	if _, err := rand.Read(payload); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func PKCEChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func jwtExp(token string) (int64, bool) {
	payload, ok := jwtPayload(token)
	if !ok {
		return 0, false
	}
	return number(payload["exp"])
}

func jwtGrants(token string) ([]string, []string, bool) {
	payload, ok := jwtPayload(token)
	if !ok {
		return nil, nil, false
	}
	audiences := stringList(payload["aud"])
	scopes := stringList(payload["scp"])
	if len(scopes) == 0 {
		scopes = strings.Fields(stringField(payload, "scope"))
	}
	return audiences, scopes, true
}

// TokenInfo is the locally decodable identity carried by an access token.
type TokenInfo struct {
	Subject   string
	Issuer    string
	Audiences []string
	Scopes    []string
	ExpiresAt int64
}

// DecodeTokenInfo decodes a JWT's payload without verifying its signature;
// it is for local display only, never for trust decisions.
func DecodeTokenInfo(token string) (TokenInfo, bool) {
	payload, ok := jwtPayload(token)
	if !ok {
		return TokenInfo{}, false
	}
	expiresAt, _ := number(payload["exp"])
	scopes := stringList(payload["scp"])
	if len(scopes) == 0 {
		scopes = strings.Fields(stringField(payload, "scope"))
	}
	return TokenInfo{
		Subject:   stringField(payload, "sub"),
		Issuer:    stringField(payload, "iss"),
		Audiences: stringList(payload["aud"]),
		Scopes:    scopes,
		ExpiresAt: expiresAt,
	}, true
}

func jwtPayload(token string) (map[string]any, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var payload map[string]any
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, false
	}
	return payload, true
}

func stringList(value any) []string {
	switch typed := value.(type) {
	case string:
		if typed == "" {
			return nil
		}
		return []string{typed}
	case []any:
		values := make([]string, 0, len(typed))
		for _, item := range typed {
			if value, ok := item.(string); ok && value != "" {
				values = append(values, value)
			}
		}
		return values
	default:
		return nil
	}
}

func waitForCallback(ctx context.Context, host string, port int, path string, expectedState string, timeout time.Duration, ready func()) (string, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", err
	}

	result := make(chan callbackResult, 1)
	serveErr := make(chan error, 1)
	var once sync.Once
	complete := func(value callbackResult) {
		once.Do(func() {
			result <- value
		})
	}

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parsed := r.URL
		if parsed.Path != path {
			http.NotFound(w, r)
			return
		}
		state := parsed.Query().Get("state")
		if state != expectedState {
			writeHTML(w, http.StatusBadRequest, "Login failed. You can close this tab.")
			return
		}
		if oauthError := parsed.Query().Get("error"); oauthError != "" {
			description := parsed.Query().Get("error_description")
			if description == "" {
				description = oauthError
			}
			complete(callbackResult{err: errors.New(description)})
			writeHTML(w, http.StatusBadRequest, "Login failed. You can close this tab.")
			return
		}
		code := parsed.Query().Get("code")
		complete(callbackResult{code: code})
		writeHTML(w, http.StatusOK, "Login complete. You can close this tab.")
	})}

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()
	defer server.Close()

	if ready != nil {
		ready()
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case value := <-result:
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		if value.err != nil {
			return "", value.err
		}
		if value.code == "" {
			return "", errors.New("OAuth callback did not include an authorization code")
		}
		return value.code, nil
	case err := <-serveErr:
		return "", err
	case <-ctx.Done():
		return "", ctx.Err()
	case <-timer.C:
		return "", errors.New("timed out waiting for OAuth callback")
	}
}

type callbackResult struct {
	code string
	err  error
}

func writeHTML(w http.ResponseWriter, status int, message string) {
	payload := []byte("<!doctype html><html><head><title>MotiveIQ Login</title></head><body><p>" + html.EscapeString(message) + "</p></body></html>")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
	w.WriteHeader(status)
	_, _ = w.Write(payload)
}

func openBrowser(rawURL string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", rawURL).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL).Start()
	default:
		return exec.Command("xdg-open", rawURL).Start()
	}
}

func expandUser(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}
	return path, nil
}

func expiresAt(response map[string]any, accessToken string, now time.Time) int64 {
	if expiresIn, ok := number(response["expires_in"]); ok {
		return now.Unix() + expiresIn
	}
	if exp, ok := jwtExp(accessToken); ok {
		return exp
	}
	return now.Unix() + 3600
}

func refreshExpiresAt(response map[string]any, previous Credentials, now time.Time) int64 {
	if refreshExpiresIn, ok := number(response["refresh_expires_in"]); ok {
		return now.Unix() + refreshExpiresIn
	}
	if previous != nil {
		if previousValue, ok := number(previous["refresh_expires_at"]); ok {
			return previousValue
		}
	}
	return now.Unix() + DefaultRefreshTokenSeconds
}

func number(value any) (int64, bool) {
	switch typed := value.(type) {
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case float64:
		return int64(typed), true
	case json.Number:
		parsed, err := typed.Int64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func stringField(values map[string]any, name string) string {
	value, _ := values[name].(string)
	return value
}

func defaultString(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
