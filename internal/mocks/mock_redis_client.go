package mocks

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/internal/interfaces"
)

// MockRedisClient implements interfaces.RedisClient for testing
type MockRedisClient struct {
	SetNXFunc func(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd
	EvalFunc  func(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd
	ExistsFunc func(ctx context.Context, keys ...string) *redis.IntCmd
	SetFunc   func(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd
	GetFunc   func(ctx context.Context, key string) *redis.StringCmd
	IncrFunc  func(ctx context.Context, key string) *redis.IntCmd
	ExpireFunc func(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd
	
	// Internal storage for mocking
	storage map[string]interface{}
}

// Ensure MockRedisClient implements interfaces.RedisClient
var _ interfaces.RedisClient = (*MockRedisClient)(nil)

// NewMockRedisClient creates a new mock Redis client
func NewMockRedisClient() *MockRedisClient {
	return &MockRedisClient{
		storage: make(map[string]interface{}),
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

// Exists mocks Redis EXISTS operation
func (m *MockRedisClient) Exists(ctx context.Context, keys ...string) *redis.IntCmd {
	if m.ExistsFunc != nil {
		return m.ExistsFunc(ctx, keys...)
	}
	
	// Default implementation: check if key exists in storage
	cmd := redis.NewIntCmd(ctx, "exists")
	if len(keys) > 0 {
		if _, exists := m.storage[keys[0]]; exists {
			cmd.SetVal(1)
		} else {
			cmd.SetVal(0)
		}
	} else {
		cmd.SetVal(0)
	}
	return cmd
}

// Set mocks Redis SET operation
func (m *MockRedisClient) Set(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.StatusCmd {
	if m.SetFunc != nil {
		return m.SetFunc(ctx, key, value, expiration)
	}
	
	// Default implementation: store in internal storage
	m.storage[key] = value
	cmd := redis.NewStatusCmd(ctx, "set", key, value)
	cmd.SetVal("OK")
	return cmd
}

// Get mocks Redis GET operation
func (m *MockRedisClient) Get(ctx context.Context, key string) *redis.StringCmd {
	if m.GetFunc != nil {
		return m.GetFunc(ctx, key)
	}
	
	// Default implementation: return from storage or empty
	cmd := redis.NewStringCmd(ctx, "get", key)
	if value, exists := m.storage[key]; exists {
		if strVal, ok := value.(string); ok {
			cmd.SetVal(strVal)
		} else if intVal, ok := value.(int); ok {
			cmd.SetVal(fmt.Sprintf("%d", intVal))
		} else {
			cmd.SetVal("0")
		}
	} else {
		cmd.SetVal("0")
	}
	return cmd
}

// Incr mocks Redis INCR operation
func (m *MockRedisClient) Incr(ctx context.Context, key string) *redis.IntCmd {
	if m.IncrFunc != nil {
		return m.IncrFunc(ctx, key)
	}
	
	// Default implementation: increment value in storage
	cmd := redis.NewIntCmd(ctx, "incr", key)
	if value, exists := m.storage[key]; exists {
		if intVal, ok := value.(int); ok {
			m.storage[key] = intVal + 1
			cmd.SetVal(int64(intVal + 1))
		} else {
			m.storage[key] = 1
			cmd.SetVal(1)
		}
	} else {
		m.storage[key] = 1
		cmd.SetVal(1)
	}
	return cmd
}

// Expire mocks Redis EXPIRE operation
func (m *MockRedisClient) Expire(ctx context.Context, key string, expiration time.Duration) *redis.BoolCmd {
	if m.ExpireFunc != nil {
		return m.ExpireFunc(ctx, key, expiration)
	}
	
	// Default implementation: always succeed
	cmd := redis.NewBoolCmd(ctx, "expire", key, expiration)
	cmd.SetVal(true)
	return cmd
}