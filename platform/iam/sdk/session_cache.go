package motiveiq

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/MotiveIQ/public/platform/iam/internal/proof"
)

// SessionCache optionally shares session credentials beyond one Config's
// in-memory cache. The SDK owns cache keys, record encoding, validation, and
// refresh policy; implementations only store opaque, secret-bearing bytes.
// Cache keys are SHA-256 hex strings. Records contain both a session token
// and its private proof key, so persistent implementations must protect them.
type SessionCache interface {
	// Update exclusively locks key, reads its current record, invokes update
	// exactly once, and atomically stores the returned record before unlocking.
	// The lock must cover the callback, including any STS exchange it performs,
	// across all users of the backing store (processes for a shared disk cache).
	// A missing record is nil. A nil result leaves storage unchanged. Callback
	// errors must leave the previous record intact and be returned to the caller;
	// storage errors must also be returned, never treated as successful writes.
	// Implementations must support concurrent use and respect ctx while waiting
	// for the lock. The callback's bytes must not alias another operation's data.
	Update(ctx context.Context, key string, update func(current []byte) ([]byte, error)) error
}

const (
	sessionCacheVersion = 1
	sessionCacheMaxSize = 64 * 1024
	sessionCacheRetry   = 30 * time.Second
)

type sessionCache struct {
	backend SessionCache
	// These settings affect the identity or authority of an issued session.
	// Service-specific endpoints are intentionally absent: one STS session
	// can authenticate IAM, S3 and other services sharing this configuration.
	scope []string
}

func newSessionCache(cfg *Config) *sessionCache {
	if cfg.sessionCache == nil {
		return nil
	}
	return &sessionCache{
		backend: cfg.sessionCache,
		scope: []string{
			strconv.Itoa(sessionCacheVersion), cfg.RoleURN, cfg.STSEndpoint,
			cfg.STSProofOrigin, cfg.sessionName,
			strconv.FormatInt(int64(cfg.sessionDuration), 10),
		},
	}
}

func (c *sessionCache) key(webIdentity string) string {
	// Hash the exact web credential, rather than trusting unverified JWT
	// claims for account/scope isolation. OAuth token rotation intentionally
	// starts a new session. No web credential is written to the cache.
	values := append(append([]string(nil), c.scope...), webIdentity)
	payload, _ := json.Marshal(values)
	return fmt.Sprintf("%x", sha256.Sum256(payload))
}

type sessionCacheRecord struct {
	Version    int       `json:"version"`
	Key        string    `json:"key"`
	Token      string    `json:"token"`
	ProofSeed  []byte    `json:"proof_seed"`
	Thumbprint string    `json:"proof_key_thumbprint"`
	ExpiresAt  time.Time `json:"expires_at"`
	RefreshAt  time.Time `json:"refresh_at"`
}

// retrieve runs credential policy within the backend's exclusive transaction.
// The backend knows nothing about STS, expiration, or proof-key serialization.
func (c *sessionCache) retrieve(ctx context.Context, provider *SessionCredentials, web string) (*credentialGeneration, error) {
	key := c.key(web)
	var generation *credentialGeneration
	err := c.backend.Update(ctx, key, func(payload []byte) ([]byte, error) {
		previous := decodeSessionCache(payload, key)
		now := provider.now()
		if previous != nil && now.Before(previous.expiresAt) && now.Before(previous.refreshAt) {
			generation = previous
			return nil, nil
		}

		// Finish a due refresh before returning from a fresh Config, so a
		// short-lived CLI cannot exit before its backend stores the result.
		var err error
		generation, err = provider.exchangeWebIdentity(ctx, web)
		now = provider.now()
		if err != nil {
			if previous == nil || !now.Before(previous.expiresAt) {
				return nil, err
			}
			provider.logger.Warn("motiveiq: session refresh failed; using unexpired cached session", "error", err)
			// Share the retry delay without extending the session's expiry.
			generation = previous
			generation.refreshAt = now.Add(sessionCacheRetry)
			if generation.refreshAt.After(generation.expiresAt) {
				generation.refreshAt = generation.expiresAt
			}
		} else {
			generation.refreshAt = sessionRefreshTime(now, generation.expiresAt)
		}
		return encodeSessionCache(key, generation)
	})
	if err != nil {
		return nil, err
	}
	if generation == nil {
		return nil, fmt.Errorf("session cache did not execute its update callback")
	}
	return generation, nil
}

// A malformed or incomplete record is a cache miss. Never publish a token
// without restoring and checking its matching proof key. Parsing errors are
// not returned because they can contain fragments of secret cache contents.
func decodeSessionCache(payload []byte, key string) *credentialGeneration {
	if len(payload) > sessionCacheMaxSize {
		return nil
	}
	var record sessionCacheRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		return nil
	}
	if record.Version != sessionCacheVersion || record.Key != key || record.Token == "" ||
		len(record.ProofSeed) != ed25519.SeedSize || record.RefreshAt.IsZero() ||
		record.ExpiresAt.IsZero() || record.RefreshAt.After(record.ExpiresAt) {
		return nil
	}
	signer, err := proof.NewSigner(ed25519.NewKeyFromSeed(record.ProofSeed), nil)
	if err != nil || signer.Thumbprint() != record.Thumbprint {
		return nil
	}
	return &credentialGeneration{
		token: record.Token, signer: signer,
		expiresAt: record.ExpiresAt, refreshAt: record.RefreshAt,
	}
}

func encodeSessionCache(key string, generation *credentialGeneration) ([]byte, error) {
	record := sessionCacheRecord{
		Version: sessionCacheVersion, Key: key, Token: generation.token,
		ProofSeed: generation.signer.Seed(), Thumbprint: generation.signer.Thumbprint(),
		ExpiresAt: generation.expiresAt, RefreshAt: generation.refreshAt,
	}
	return json.Marshal(record)
}
