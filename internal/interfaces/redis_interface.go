package interfaces

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisClient interface wraps the essential Redis operations needed by the auth service
type RedisClient interface {
	SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd
	Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
	Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	Exists(ctx context.Context, keys ...string) *redis.IntCmd
}

// RedisClientWrapper wraps a *redis.Client to implement the RedisClient interface
type RedisClientWrapper struct {
	client *redis.Client
}

// NewRedisClientWrapper creates a new wrapper around a redis.Client
func NewRedisClientWrapper(client *redis.Client) *RedisClientWrapper {
	return &RedisClientWrapper{client: client}
}

// SetNX wraps the redis SetNX operation
func (w *RedisClientWrapper) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd {
	return w.client.SetNX(ctx, key, value, expiration)
}

// Eval wraps the redis Eval operation
func (w *RedisClientWrapper) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd {
	return w.client.Eval(ctx, script, keys, args...)
}

// Set wraps the redis Set operation
func (w *RedisClientWrapper) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	return w.client.Set(ctx, key, value, expiration)
}

// Exists wraps the redis Exists operation
func (w *RedisClientWrapper) Exists(ctx context.Context, keys ...string) *redis.IntCmd {
	return w.client.Exists(ctx, keys...)
}