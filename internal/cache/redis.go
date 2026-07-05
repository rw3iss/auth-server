// Package cache provides Redis-based caching for the auth service
package cache

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rw3iss/auth/internal/config"
)

// RedisClient wraps a Redis client with graceful fallback
type RedisClient struct {
	client    *redis.Client
	connected bool
}

// NewRedisClient creates a new Redis client with graceful fallback
func NewRedisClient(cfg config.RedisConfig) *RedisClient {
	client := redis.NewClient(&redis.Options{
		Addr:         cfg.Address(),
		Password:     cfg.Password,
		DB:           cfg.DB,
		PoolSize:     cfg.PoolSize,
		MinIdleConns: cfg.MinIdleConns,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	rc := &RedisClient{
		client:    client,
		connected: false,
	}

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		slog.Warn("redis connect failed; falling back to no-op cache", "err", err)
		return rc
	}

	rc.connected = true
	slog.Info("redis connected", "addr", cfg.Address())
	return rc
}

// Ping checks the Redis connection
func (r *RedisClient) Ping(ctx context.Context) error {
	if !r.connected {
		return fmt.Errorf("redis not connected")
	}
	return r.client.Ping(ctx).Err()
}

// Close closes the Redis connection
func (r *RedisClient) Close() error {
	if r.client != nil {
		return r.client.Close()
	}
	return nil
}

// IsConnected returns whether Redis is connected
func (r *RedisClient) IsConnected() bool {
	return r.connected
}

// Client returns the underlying Redis client
func (r *RedisClient) Client() *redis.Client {
	return r.client
}
