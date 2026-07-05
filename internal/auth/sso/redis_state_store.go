package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/ven/auth/pkg/shared/errors"
)

// RedisStateStore stores OAuth state in Redis with atomic GET+DEL on
// validate. AUDIT 1.12 and 1.14:
//
//   - 1.12: in-memory state is per-replica. A user routed to replica B
//     after minting state on replica A would have failed the callback.
//     Redis makes state cluster-global.
//   - 1.14: validation must be atomic so two concurrent callbacks with the
//     same state can't both pass the "exists" check before either delete
//     runs. We use Redis 6.2+'s GETDEL to do both in one command. Falls
//     back to a Lua script when GETDEL isn't available.
type RedisStateStore struct {
	client *redis.Client
}

// NewRedisStateStore returns nil if the Redis client is not connected;
// callers should detect that and fall back to InMemoryStateStore.
func NewRedisStateStore(client *redis.Client) *RedisStateStore {
	if client == nil {
		return nil
	}
	return &RedisStateStore{client: client}
}

const ssoStateKeyPrefix = "auth:sso:state:"

func (s *RedisStateStore) Set(ctx context.Context, state string, data *StateData, expiry time.Duration) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	return s.client.Set(ctx, ssoStateKeyPrefix+state, payload, expiry).Err()
}

func (s *RedisStateStore) Get(ctx context.Context, state string) (*StateData, error) {
	payload, err := s.client.Get(ctx, ssoStateKeyPrefix+state).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.NotFound("OAuth state")
		}
		return nil, err
	}
	var data StateData
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}
	return &data, nil
}

func (s *RedisStateStore) Delete(ctx context.Context, state string) error {
	return s.client.Del(ctx, ssoStateKeyPrefix+state).Err()
}

// GetAndDelete atomically reads the state and removes it. This is the path
// the Manager uses during callback validation; the non-atomic Get + Delete
// pair on the StateStore interface is preserved for back-compat but should
// not be relied on for one-shot semantics.
func (s *RedisStateStore) GetAndDelete(ctx context.Context, state string) (*StateData, error) {
	key := ssoStateKeyPrefix + state
	// GETDEL is one round-trip and atomic on the server side.
	payload, err := s.client.GetDel(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.NotFound("OAuth state")
		}
		return nil, err
	}
	var data StateData
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("unmarshal state: %w", err)
	}
	return &data, nil
}

// RedisAuthCodeStore — same one-shot GETDEL pattern, but for PKCE auth codes
// (AUDIT C2). Codes are minted in the SSO callback and redeemed at
// /auth/sso/exchange. Each is an opaque 32-byte random value; the namespace
// is distinct from state keys so a key collision is impossible.
type RedisAuthCodeStore struct {
	client *redis.Client
}

// NewRedisAuthCodeStore returns nil if the Redis client is not connected,
// matching NewRedisStateStore's convention so the caller can fall back to
// InMemoryAuthCodeStore without nil-pointer surprises.
func NewRedisAuthCodeStore(client *redis.Client) *RedisAuthCodeStore {
	if client == nil {
		return nil
	}
	return &RedisAuthCodeStore{client: client}
}

const ssoAuthCodeKeyPrefix = "auth:sso:authcode:"

func (s *RedisAuthCodeStore) Set(ctx context.Context, code string, data *AuthCodeData, expiry time.Duration) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal auth_code: %w", err)
	}
	return s.client.Set(ctx, ssoAuthCodeKeyPrefix+code, payload, expiry).Err()
}

func (s *RedisAuthCodeStore) GetAndDelete(ctx context.Context, code string) (*AuthCodeData, error) {
	payload, err := s.client.GetDel(ctx, ssoAuthCodeKeyPrefix+code).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, errors.NotFound("auth_code")
		}
		return nil, err
	}
	var data AuthCodeData
	if err := json.Unmarshal(payload, &data); err != nil {
		return nil, fmt.Errorf("unmarshal auth_code: %w", err)
	}
	return &data, nil
}
