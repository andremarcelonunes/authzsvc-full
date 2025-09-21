package mocks

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
)

// MockRateLimitValidationService implements domain.RateLimitValidationService interface for testing
type MockRateLimitValidationService struct {
	CheckRateLimitFunc              func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error)
	IncrementCounterFunc            func(ctx context.Context, key string, window time.Duration) error
	GetRateLimitStatusFunc          func(ctx context.Context, key string) (*domain.RateLimitStatus, error)
	CheckSlidingWindowLimitFunc     func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error)
	CheckTokenBucketLimitFunc       func(ctx context.Context, key string, capacity int, refillRate float64) (*domain.RateLimitResult, error)
	RecordFailedAttemptFunc         func(ctx context.Context, identifier string, attemptType string) error
	IsBlockedFunc                   func(ctx context.Context, identifier string, attemptType string) (bool, time.Duration, error)
	ResetFailedAttemptsFunc         func(ctx context.Context, identifier string, attemptType string) error
	BlockUserFunc                   func(ctx context.Context, userID uint, duration time.Duration, reason string) error
	UnblockUserFunc                 func(ctx context.Context, userID uint) error
	BlockIPFunc                     func(ctx context.Context, ipAddress string, duration time.Duration, reason string) error
	UnblockIPFunc                   func(ctx context.Context, ipAddress string) error
}

// NewMockRateLimitValidationService creates a new MockRateLimitValidationService with default behaviors
func NewMockRateLimitValidationService() *MockRateLimitValidationService {
	return &MockRateLimitValidationService{}
}

// CheckRateLimit checks if a request is within rate limits
func (m *MockRateLimitValidationService) CheckRateLimit(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
	if m.CheckRateLimitFunc != nil {
		return m.CheckRateLimitFunc(ctx, key, limit, window)
	}
	// Default behavior: allowed
	return &domain.RateLimitResult{
		Allowed:      true,
		Key:          key,
		CurrentCount: 0,
		Limit:        limit,
		Window:       window,
		ResetTime:    time.Now().Add(window),
		Remaining:    limit,
	}, nil
}

// IncrementCounter increments the request counter for rate limiting
func (m *MockRateLimitValidationService) IncrementCounter(ctx context.Context, key string, window time.Duration) error {
	if m.IncrementCounterFunc != nil {
		return m.IncrementCounterFunc(ctx, key, window)
	}
	// Default behavior: success
	return nil
}

// GetRateLimitStatus gets the current rate limit status for a key
func (m *MockRateLimitValidationService) GetRateLimitStatus(ctx context.Context, key string) (*domain.RateLimitStatus, error) {
	if m.GetRateLimitStatusFunc != nil {
		return m.GetRateLimitStatusFunc(ctx, key)
	}
	// Default behavior: not blocked
	return &domain.RateLimitStatus{
		Key:          key,
		CurrentCount: 0,
		Limit:        100,
		Window:       time.Hour,
		ResetTime:    time.Now().Add(time.Hour),
		IsBlocked:    false,
	}, nil
}

// CheckSlidingWindowLimit checks rate limits using sliding window algorithm
func (m *MockRateLimitValidationService) CheckSlidingWindowLimit(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
	if m.CheckSlidingWindowLimitFunc != nil {
		return m.CheckSlidingWindowLimitFunc(ctx, key, limit, window)
	}
	// Default behavior: allowed
	return &domain.RateLimitResult{
		Allowed:      true,
		Key:          key,
		CurrentCount: 0,
		Limit:        limit,
		Window:       window,
		ResetTime:    time.Now().Add(window),
		Remaining:    limit,
	}, nil
}

// CheckTokenBucketLimit checks rate limits using token bucket algorithm
func (m *MockRateLimitValidationService) CheckTokenBucketLimit(ctx context.Context, key string, capacity int, refillRate float64) (*domain.RateLimitResult, error) {
	if m.CheckTokenBucketLimitFunc != nil {
		return m.CheckTokenBucketLimitFunc(ctx, key, capacity, refillRate)
	}
	// Default behavior: allowed
	return &domain.RateLimitResult{
		Allowed:      true,
		Key:          key,
		CurrentCount: 0,
		Limit:        capacity,
		Remaining:    capacity,
	}, nil
}

// RecordFailedAttempt records a failed attempt for brute force detection
func (m *MockRateLimitValidationService) RecordFailedAttempt(ctx context.Context, identifier string, attemptType string) error {
	if m.RecordFailedAttemptFunc != nil {
		return m.RecordFailedAttemptFunc(ctx, identifier, attemptType)
	}
	// Default behavior: success
	return nil
}

// IsBlocked checks if an identifier is currently blocked
func (m *MockRateLimitValidationService) IsBlocked(ctx context.Context, identifier string, attemptType string) (bool, time.Duration, error) {
	if m.IsBlockedFunc != nil {
		return m.IsBlockedFunc(ctx, identifier, attemptType)
	}
	// Default behavior: not blocked
	return false, 0, nil
}

// ResetFailedAttempts resets the failed attempts counter for an identifier
func (m *MockRateLimitValidationService) ResetFailedAttempts(ctx context.Context, identifier string, attemptType string) error {
	if m.ResetFailedAttemptsFunc != nil {
		return m.ResetFailedAttemptsFunc(ctx, identifier, attemptType)
	}
	// Default behavior: success
	return nil
}

// BlockUser blocks a user for a specific duration
func (m *MockRateLimitValidationService) BlockUser(ctx context.Context, userID uint, duration time.Duration, reason string) error {
	if m.BlockUserFunc != nil {
		return m.BlockUserFunc(ctx, userID, duration, reason)
	}
	// Default behavior: success
	return nil
}

// UnblockUser removes a user block
func (m *MockRateLimitValidationService) UnblockUser(ctx context.Context, userID uint) error {
	if m.UnblockUserFunc != nil {
		return m.UnblockUserFunc(ctx, userID)
	}
	// Default behavior: success
	return nil
}

// BlockIP blocks an IP address for a specific duration
func (m *MockRateLimitValidationService) BlockIP(ctx context.Context, ipAddress string, duration time.Duration, reason string) error {
	if m.BlockIPFunc != nil {
		return m.BlockIPFunc(ctx, ipAddress, duration, reason)
	}
	// Default behavior: success
	return nil
}

// UnblockIP removes an IP address block
func (m *MockRateLimitValidationService) UnblockIP(ctx context.Context, ipAddress string) error {
	if m.UnblockIPFunc != nil {
		return m.UnblockIPFunc(ctx, ipAddress)
	}
	// Default behavior: success
	return nil
}

// Compile-time interface compliance verification
var _ domain.RateLimitValidationService = (*MockRateLimitValidationService)(nil)