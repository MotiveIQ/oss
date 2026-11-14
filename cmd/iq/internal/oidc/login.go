package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func (s *oidcSource) Login(ctx context.Context, output io.Writer) error {
	ctx, cancel := context.WithTimeout(gooidc.ClientContext(ctx, s.client), 5*time.Minute)
	defer cancel()
	provider, config, err := s.discover(ctx)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(s.config.CallbackPort))
	if err != nil {
		return errors.New("cannot listen on OIDC loopback callback")
	}
	defer listener.Close()
	config.RedirectURL = "http://" + listener.Addr().String() + "/callback"
	state, nonce, verifier := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	options := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), gooidc.Nonce(nonce)}
	for key, value := range s.config.AuthorizationParams {
		options = append(options, oauth2.SetAuthURLParam(key, value))
	}
	if slices.Contains(s.config.Scopes, "offline_access") {
		prompt := s.config.AuthorizationParams["prompt"]
		if prompt != "" && prompt != "consent" {
			return errors.New("offline_access requires prompt=consent")
		}
		options = append(options, oauth2.SetAuthURLParam("prompt", "consent"))
	}
	code, err := callback(ctx, listener, state, s.config.Issuer, func() {
		authURL := config.AuthCodeURL(state, options...)
		fmt.Fprintln(output, "Open this URL to log in:")
		fmt.Fprintln(output, authURL)
		_ = s.openURL(authURL)
	})
	if err != nil {
		return err
	}
	token, err := config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return errors.New("OIDC authorization code exchange failed")
	}
	raw, _ := token.Extra("id_token").(string)
	id, err := s.verify(ctx, provider, raw, false)
	if err != nil {
		return err
	}
	if id.Nonce != nonce {
		return errors.New("OIDC ID token nonce mismatch")
	}
	if id.AccessTokenHash != "" && id.VerifyAccessToken(token.AccessToken) != nil {
		return errors.New("OIDC access token hash mismatch")
	}
	err = s.update(ctx, func(*credentials) (*credentials, error) {
		return &credentials{Binding: s.binding, IDToken: raw, Nonce: nonce, Token: *token}, nil
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "Login complete.")
	return nil
}

func callback(ctx context.Context, listener net.Listener, state, issuer string, ready func()) (string, error) {
	type response struct {
		code string
		err  error
	}
	result := make(chan response, 1)
	var once sync.Once
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		q, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || r.Method != http.MethodGet || r.URL.Path != "/callback" || r.Host != listener.Addr().String() || len(q["state"]) != 1 || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(state)) != 1 {
			http.Error(w, "Invalid callback", http.StatusBadRequest)
			return
		}
		if len(q["iss"]) > 1 || (q.Has("iss") && q.Get("iss") != issuer) {
			http.Error(w, "Invalid issuer", http.StatusBadRequest)
			return
		}
		answer := response{code: q.Get("code")}
		if q.Has("error") || len(q["code"]) != 1 || answer.code == "" {
			answer = response{err: errors.New("OIDC authorization was not completed")}
		}
		once.Do(func() { result <- answer })
		fmt.Fprintln(w, "Return to your terminal to finish signing in.")
	})}
	defer server.Close()
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			once.Do(func() { result <- response{err: errors.New("OIDC callback server failed")} })
		}
	}()
	ready()
	select {
	case answer := <-result:
		return answer.code, answer.err
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func openBrowser(address string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", address).Run()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", address).Run()
	default:
		return exec.Command("xdg-open", address).Run()
	}
}
