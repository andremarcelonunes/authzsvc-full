package mocks

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// MockRedisClient implements a simple mock for Redis operations needed for testing
type MockRedisClient struct {
	SetNXFunc func(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd
	EvalFunc  func(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
}

// NewMockRedisClient creates a new mock Redis client
func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		SetNXFunc: func(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd {
			// Default: lock acquired successfully
			cmd := redis.NewBoolCmd(ctx, "setnx", key, value)
			cmd.SetVal(true)
			return cmd
		},
		EvalFunc: func(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd {
			// Default: lock released successfully
			cmd := redis.NewCmd(ctx, "eval", script)
			cmd.SetVal(int64(1))
			return cmd
		},
	}
}

// SetNX mocks Redis SETNX operation
func (m *MockRedisClient) SetNX(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd {
	if m.SetNXFunc != nil {
		return m.SetNXFunc(ctx, key, value, expiration)
	}
	cmd := redis.NewBoolCmd(ctx, "setnx", key, value)
	cmd.SetVal(true)
	return cmd
}

// Eval mocks Redis EVAL operation for Lua scripts
func (m *MockRedisClient) Eval(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd {
	if m.EvalFunc != nil {
		return m.EvalFunc(ctx, script, keys, args...)
	}
	cmd := redis.NewCmd(ctx, "eval", script)
	cmd.SetVal(int64(1))
	return cmd
}