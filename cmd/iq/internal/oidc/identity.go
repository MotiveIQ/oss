// Package oidc implements a native OIDC client and external-token helper.
package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	sdkconfig "go.motiveiq.dev/platform/iam/sdk/config"
)

var errLoginRequired = errors.New("OIDC login required; run iq-oidc login with this source")

type oidcConfig struct {
	Issuer       string   `toml:"issuer"`
	ClientID     string   `toml:"client_id"`
	Scopes       []string `toml:"scopes"`
	CallbackPort int      `toml:"callback_port,omitempty"`
	TokenFile    string   `toml:"token_file,omitempty"`
	// Provider extensions are explicit data, never compiled-in defaults.
	AuthorizationParams map[string]string `toml:"authorization_params,omitempty"`
	// Optional credential-process bridge for OAuth consumers. No refresh token
	// is exported: every consumer goes through the same locked cache.
	AccessTokenExportFile string `toml:"access_token_export_file,omitempty"`
}

type oidcSource struct {
	config  oidcConfig
	path    string
	binding string
	client  *http.Client
	openURL func(string) error
}

func newOIDCSource(settings sdkconfig.SourceConfig) (*oidcSource, error) {
	var config oidcConfig
	if err := settings.Decode(&config); err != nil {
		return nil, err
	}
	if !httpsURL(config.Issuer) || config.ClientID == "" || strings.TrimSpace(config.ClientID) != config.ClientID || config.CallbackPort < 0 || config.CallbackPort > 65535 {
		return nil, errors.New("OIDC source requires an HTTPS issuer, client_id, and a callback_port between 0 and 65535")
	}
	u, _ := url.Parse(config.Issuer)
	if u.RawQuery != "" {
		return nil, errors.New("OIDC issuer must not contain a query")
	}
	if len(config.Scopes) == 0 {
		config.Scopes = []string{"openid"}
	}
	if !slices.Contains(config.Scopes, "openid") {
		return nil, errors.New("OIDC scopes must include openid")
	}
	for _, scope := range config.Scopes {
		if scope == "" || strings.ContainsAny(scope, " \t\r\n") {
			return nil, errors.New("invalid OIDC scope")
		}
	}
	for key := range config.AuthorizationParams {
		switch key {
		case "client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "request", "request_uri", "client_secret", "max_age", "claims", "acr_values":
			return nil, fmt.Errorf("authorization_params cannot override %s", key)
		}
	}
	scopes := slices.Clone(config.Scopes)
	slices.Sort(scopes)
	data, _ := json.Marshal(struct {
		Issuer, ClientID string
		Scopes           []string
		Params           map[string]string
	}{config.Issuer, config.ClientID, scopes, config.AuthorizationParams})
	binding := fmt.Sprintf("%x", sha256.Sum256(data))
	path := config.TokenFile
	if path == "" {
		base := os.Getenv("XDG_CACHE_HOME")
		if base == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return nil, err
			}
			base = filepath.Join(home, ".cache")
		}
		path = filepath.Join(base, "iq", "oidc", binding+".json")
	}
	if !filepath.IsAbs(path) {
		return nil, errors.New("OIDC cache path must be absolute")
	}
	client := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("OIDC endpoint redirects are not accepted")
	}}
	return &oidcSource{config: config, path: path, binding: binding, client: client, openURL: openBrowser}, nil
}

func httpsURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}

func (s *oidcSource) discover(ctx context.Context) (*gooidc.Provider, *oauth2.Config, error) {
	provider, err := gooidc.NewProvider(ctx, s.config.Issuer)
	if err != nil {
		return nil, nil, errors.New("OIDC discovery failed")
	}
	var metadata struct {
		JWKS          string   `json:"jwks_uri"`
		ResponseTypes []string `json:"response_types_supported"`
		AuthMethods   []string `json:"token_endpoint_auth_methods_supported"`
		PKCE          []string `json:"code_challenge_methods_supported"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, nil, errors.New("invalid OIDC metadata")
	}
	endpoint := provider.Endpoint()
	if !httpsURL(endpoint.AuthURL) || !httpsURL(endpoint.TokenURL) || !httpsURL(metadata.JWKS) || !slices.Contains(metadata.ResponseTypes, "code") {
		return nil, nil, errors.New("OIDC provider must advertise HTTPS authorization, token and JWKS endpoints and the code flow")
	}
	if len(metadata.AuthMethods) > 0 && !slices.Contains(metadata.AuthMethods, "none") {
		return nil, nil, errors.New("OIDC provider does not support public clients")
	}
	if len(metadata.PKCE) > 0 && !slices.Contains(metadata.PKCE, "S256") {
		return nil, nil, errors.New("OIDC provider does not support PKCE S256")
	}
	endpoint.AuthStyle = oauth2.AuthStyleInParams
	return provider, &oauth2.Config{ClientID: s.config.ClientID, Endpoint: endpoint, Scopes: s.config.Scopes}, nil
}

func (s *oidcSource) verify(ctx context.Context, provider *gooidc.Provider, raw string, allowExpired bool) (*gooidc.IDToken, error) {
	id, err := provider.VerifierContext(ctx, &gooidc.Config{ClientID: s.config.ClientID, SkipExpiryCheck: allowExpired}).Verify(ctx, raw)
	if err != nil {
		return nil, errors.New("OIDC ID token verification failed")
	}
	var claims struct {
		AuthorizedParty string `json:"azp"`
		NotBefore       int64  `json:"nbf"`
		AuthTime        *int64 `json:"auth_time"`
	}
	if err := id.Claims(&claims); err != nil {
		return nil, errors.New("invalid OIDC ID token claims")
	}
	if claims.AuthTime != nil && (*claims.AuthTime < 0 || *claims.AuthTime > id.IssuedAt.Add(time.Minute).Unix()) {
		return nil, errors.New("invalid OIDC authentication time")
	}
	// Trust only the configured client audience, with no provider issuer aliases.
	if id.Issuer != s.config.Issuer || id.Subject == "" || id.IssuedAt.IsZero() || id.IssuedAt.After(time.Now().Add(time.Minute)) || id.Expiry.IsZero() || (!allowExpired && !id.Expiry.After(time.Now())) || claims.NotBefore > time.Now().Add(time.Minute).Unix() || len(id.Audience) != 1 || id.Audience[0] != s.config.ClientID || (claims.AuthorizedParty != "" && claims.AuthorizedParty != s.config.ClientID) {
		return nil, errors.New("OIDC ID token claims do not match this source")
	}
	return id, nil
}

func (s *oidcSource) token(ctx context.Context, access bool) (sdkconfig.ProcessToken, error) {
	ctx = gooidc.ClientContext(ctx, s.client)
	var result sdkconfig.ProcessToken
	err := s.update(ctx, func(record *credentials) (*credentials, error) {
		if record == nil || record.Binding != s.binding {
			return nil, errLoginRequired
		}
		provider, config, err := s.discover(ctx)
		if err != nil {
			return nil, err
		}
		previous, err := s.verify(ctx, provider, record.IDToken, true)
		if err != nil {
			return nil, err
		}
		if record.Nonce == "" || (previous.Nonce != "" && previous.Nonce != record.Nonce) {
			return nil, errors.New("cached OIDC nonce mismatch")
		}
		fresh := previous.Expiry.After(time.Now().Add(30 * time.Second))
		if access {
			fresh = record.Token.AccessToken != "" && record.Token.Expiry.After(time.Now().Add(30*time.Second))
		}
		if !fresh {
			if record.Token.RefreshToken == "" || (!access && record.NoIDToken) {
				return nil, errLoginRequired
			}
			// Select refresh using the requested token's expiry, not the access token's.
			old := record.Token
			old.Expiry = time.Now().Add(-time.Hour)
			token, err := config.TokenSource(ctx, &old).Token()
			if err != nil {
				return nil, errors.New("OIDC refresh failed; run iq-oidc login with this source")
			}
			raw, _ := token.Extra("id_token").(string)
			if raw != "" {
				id, err := s.verify(ctx, provider, raw, false)
				if err != nil {
					return nil, err
				}
				var before, after struct {
					AuthTime int64 `json:"auth_time"`
				}
				if previous.Claims(&before) != nil || id.Claims(&after) != nil {
					return nil, errors.New("invalid refreshed OIDC authentication time")
				}
				if id.Subject != previous.Subject || !slices.Equal(id.Audience, previous.Audience) || (id.Nonce != "" && id.Nonce != record.Nonce) || before.AuthTime != after.AuthTime {
					return nil, errors.New("OIDC refresh changed the authenticated identity")
				}
				if id.AccessTokenHash != "" && id.VerifyAccessToken(token.AccessToken) != nil {
					return nil, errors.New("OIDC refreshed access token hash mismatch")
				}
				record.IDToken, record.NoIDToken = raw, false
				previous = id
			} else {
				record.NoIDToken = true
			}
			record.Token = *token
			// Save rotated credentials even when no ID token is returned. A missing
			// usable token is reported after committing this transaction.
		}
		if access {
			if record.Token.AccessToken != "" && record.Token.Expiry.After(time.Now()) {
				result = sdkconfig.ProcessToken{Version: 1, Token: record.Token.AccessToken, ExpiresAt: &record.Token.Expiry}
			}
		} else if previous.Expiry.After(time.Now()) {
			result = sdkconfig.ProcessToken{Version: 1, Token: record.IDToken, ExpiresAt: &previous.Expiry}
		}
		return record, nil
	})
	if err != nil {
		return result, err
	}
	if result.Token == "" {
		return result, errLoginRequired
	}
	return result, nil
}
