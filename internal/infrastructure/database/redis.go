package database

import (
	"context"
	"time"
	"github.com/redis/go-redis/v9"
)

type RedisClient struct{ *redis.Client }

func NewRedis(addr, pass string, db int) *RedisClient {
	return &RedisClient{redis.NewClient(&redis.Options{Addr: addr, Password: pass, DB: db})}
}

func (c *RedisClient) Ping(ctx context.Context) error { return c.Client.Ping(ctx).Err() }

// Helpers
func SetNX(ctx context.Context, r *RedisClient, key string, val any, ttl time.Duration) (bool, error) {
	return r.SetNX(ctx, key, val, ttl).Result()
}