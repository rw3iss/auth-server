package cache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const keyPrefix = "auth:"

// CachedClaims represents cached token claims
type CachedClaims struct {
	UserID           string   `json:"uid"`
	Email            string   `json:"email"`
	FirstName        string   `json:"first_name,omitempty"`
	LastName         string   `json:"last_name,omitempty"`
	OrganizationID   string   `json:"org_id,omitempty"`
	OrganizationSlug string   `json:"org_slug,omitempty"`
	Roles            []string `json:"roles"`
	Permissions      []string `json:"permissions"`
	TokenType        string   `json:"token_type"`
	SessionID        string   `json:"session_id,omitempty"`
	ExpiresAt        int64    `json:"exp"`
	// TokenVersion is the per-user token-version counter captured at
	// issue time. Validators reject tokens whose stored version is below
	// the current per-user version, giving "logout-everywhere" immediate
	// effect on access tokens (AUDIT 1.10).
	TokenVersion int64 `json:"tv,omitempty"`
}

// TokenCache defines the interface for token caching operations
type TokenCache interface {
	// CacheValidatedToken caches parsed JWT claims by token hash
	CacheValidatedToken(ctx context.Context, tokenHash string, claims *CachedClaims, ttl time.Duration) error
	// GetCachedToken retrieves cached claims by token hash
	GetCachedToken(ctx context.Context, tokenHash string) (*CachedClaims, error)
	// InvalidateCachedToken explicitly evicts a cached entry — used when
	// a stale-version cache hit is detected mid-validate.
	InvalidateCachedToken(ctx context.Context, tokenHash string) error
	// BlacklistToken adds a token JTI to the revocation blacklist
	BlacklistToken(ctx context.Context, jti string, ttl time.Duration) error
	// IsBlacklisted checks if a token JTI is blacklisted
	IsBlacklisted(ctx context.Context, jti string) (bool, error)
	// IncrementRateLimit increments a rate limit counter and returns the current count
	IncrementRateLimit(ctx context.Context, key string, window time.Duration) (int64, error)
	// IncrementAccountAttempts increments a per-account counter (typically
	// keyed on sha256(email)) for AUDIT 1.17 — per-account login limit
	// separate from per-IP. Same primitive as IncrementRateLimit but a
	// distinct key prefix so the two windows don't collide.
	IncrementAccountAttempts(ctx context.Context, key string, window time.Duration) (int64, error)
	// ResetAccountAttempts clears the per-account counter (called on
	// successful login so a user who finally remembers their password
	// isn't locked out by the trailing window).
	ResetAccountAttempts(ctx context.Context, key string) error
	// GetUserTokenVersion reads the per-user token-version counter. A
	// fresh user (no prior bump) returns 0 — and tokens are issued with
	// tv=0 in that case, so the equality check passes.
	GetUserTokenVersion(ctx context.Context, userID string) (int64, error)
	// BumpUserTokenVersion atomically increments the per-user counter
	// and returns the new value. Called on logout-all, role change, and
	// any other event that should immediately invalidate every
	// outstanding access token for the user.
	BumpUserTokenVersion(ctx context.Context, userID string) (int64, error)
}

// RedisTokenCache implements TokenCache using Redis
type RedisTokenCache struct {
	client *redis.Client
}

// NewRedisTokenCache creates a new Redis-backed token cache
func NewRedisTokenCache(rc *RedisClient) TokenCache {
	if !rc.IsConnected() {
		return NewNoOpTokenCache()
	}
	return &RedisTokenCache{client: rc.Client()}
}

func (c *RedisTokenCache) CacheValidatedToken(ctx context.Context, tokenHash string, claims *CachedClaims, ttl time.Duration) error {
	data, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("failed to marshal claims: %w", err)
	}
	key := keyPrefix + "token:" + tokenHash
	return c.client.Set(ctx, key, data, ttl).Err()
}

func (c *RedisTokenCache) GetCachedToken(ctx context.Context, tokenHash string) (*CachedClaims, error) {
	key := keyPrefix + "token:" + tokenHash
	data, err := c.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	var claims CachedClaims
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims: %w", err)
	}
	return &claims, nil
}

func (c *RedisTokenCache) BlacklistToken(ctx context.Context, jti string, ttl time.Duration) error {
	key := keyPrefix + "blacklist:" + jti
	return c.client.Set(ctx, key, "1", ttl).Err()
}

func (c *RedisTokenCache) IsBlacklisted(ctx context.Context, jti string) (bool, error) {
	key := keyPrefix + "blacklist:" + jti
	exists, err := c.client.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

func (c *RedisTokenCache) InvalidateCachedToken(ctx context.Context, tokenHash string) error {
	key := keyPrefix + "token:" + tokenHash
	return c.client.Del(ctx, key).Err()
}

func (c *RedisTokenCache) GetUserTokenVersion(ctx context.Context, userID string) (int64, error) {
	key := keyPrefix + "user_tv:" + userID
	v, err := c.client.Get(ctx, key).Int64()
	if err != nil {
		if err == redis.Nil {
			return 0, nil
		}
		return 0, err
	}
	return v, nil
}

func (c *RedisTokenCache) BumpUserTokenVersion(ctx context.Context, userID string) (int64, error) {
	// INCR is atomic — concurrent bumps simply increment further, which is
	// the desired behavior (each one invalidates more outstanding tokens).
	// We never set a TTL: the counter must persist as long as the user
	// exists, otherwise an expired key would reset to 0 and let stale
	// access tokens through.
	key := keyPrefix + "user_tv:" + userID
	return c.client.Incr(ctx, key).Result()
}

func (c *RedisTokenCache) IncrementAccountAttempts(ctx context.Context, key string, window time.Duration) (int64, error) {
	rKey := keyPrefix + "account_attempts:" + key
	pipe := c.client.Pipeline()
	incr := pipe.Incr(ctx, rKey)
	pipe.Expire(ctx, rKey, window)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

func (c *RedisTokenCache) ResetAccountAttempts(ctx context.Context, key string) error {
	return c.client.Del(ctx, keyPrefix+"account_attempts:"+key).Err()
}

func (c *RedisTokenCache) IncrementRateLimit(ctx context.Context, key string, window time.Duration) (int64, error) {
	rKey := keyPrefix + "ratelimit:" + key
	pipe := c.client.Pipeline()
	incr := pipe.Incr(ctx, rKey)
	pipe.Expire(ctx, rKey, window)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incr.Val(), nil
}

// NoOpTokenCache is a no-op implementation that always returns cache misses
type NoOpTokenCache struct{}

// NewNoOpTokenCache creates a new no-op token cache
func NewNoOpTokenCache() TokenCache {
	return &NoOpTokenCache{}
}

func (c *NoOpTokenCache) CacheValidatedToken(_ context.Context, _ string, _ *CachedClaims, _ time.Duration) error {
	return nil
}

func (c *NoOpTokenCache) GetCachedToken(_ context.Context, _ string) (*CachedClaims, error) {
	return nil, nil
}

func (c *NoOpTokenCache) BlacklistToken(_ context.Context, _ string, _ time.Duration) error {
	return nil
}

func (c *NoOpTokenCache) IsBlacklisted(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (c *NoOpTokenCache) IncrementRateLimit(_ context.Context, _ string, _ time.Duration) (int64, error) {
	return 0, nil
}

func (c *NoOpTokenCache) IncrementAccountAttempts(_ context.Context, _ string, _ time.Duration) (int64, error) {
	return 0, nil
}

func (c *NoOpTokenCache) ResetAccountAttempts(_ context.Context, _ string) error { return nil }

// InvalidateCachedToken: nothing to invalidate without Redis.
func (c *NoOpTokenCache) InvalidateCachedToken(_ context.Context, _ string) error { return nil }

// GetUserTokenVersion: without Redis, every user is at version 0 forever.
// Combined with tokens being issued at tv=0, the version gate is a no-op —
// graceful degradation to "no logout-everywhere enforcement on access
// tokens, but everything else still works."
func (c *NoOpTokenCache) GetUserTokenVersion(_ context.Context, _ string) (int64, error) {
	return 0, nil
}

// BumpUserTokenVersion: same — without Redis we can't increment, but
// returning 0 keeps the logout-all path running through successfully
// (refresh tokens are still revoked via the DB path).
func (c *NoOpTokenCache) BumpUserTokenVersion(_ context.Context, _ string) (int64, error) {
	return 0, nil
}
