package services

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
)

// RateLimitValidationServiceImpl implements domain.RateLimitValidationService
type RateLimitValidationServiceImpl struct {
	redisClient *redis.Client
	logger      *slog.Logger
	
	// Configuration
	defaultWindowSize    time.Duration
	defaultLimit         int
	bruteForceThreshold  int
	bruteForceWindow     time.Duration
	blockDuration        time.Duration
	enableGracefulMode   bool
}

// RateLimitConfig holds configuration for rate limiting
type RateLimitConfig struct {
	DefaultWindowSize    time.Duration
	DefaultLimit         int
	BruteForceThreshold  int
	BruteForceWindow     time.Duration
	BlockDuration        time.Duration
	EnableGracefulMode   bool // Continue without rate limiting if Redis fails
}

// NewRateLimitValidationService creates a new rate limit validation service
func NewRateLimitValidationService(
	redisClient *redis.Client,
	config RateLimitConfig,
) domain.RateLimitValidationService {
	// Set defaults
	if config.DefaultWindowSize == 0 {
		config.DefaultWindowSize = 1 * time.Hour
	}
	if config.DefaultLimit == 0 {
		config.DefaultLimit = 100
	}
	if config.BruteForceThreshold == 0 {
		config.BruteForceThreshold = 5
	}
	if config.BruteForceWindow == 0 {
		config.BruteForceWindow = 15 * time.Minute
	}
	if config.BlockDuration == 0 {
		config.BlockDuration = 1 * time.Hour
	}

	return &RateLimitValidationServiceImpl{
		redisClient:         redisClient,
		logger:             slog.Default(),
		defaultWindowSize:   config.DefaultWindowSize,
		defaultLimit:        config.DefaultLimit,
		bruteForceThreshold: config.BruteForceThreshold,
		bruteForceWindow:    config.BruteForceWindow,
		blockDuration:       config.BlockDuration,
		enableGracefulMode:  config.EnableGracefulMode,
	}
}

// CheckRateLimit checks if a request is within rate limits using fixed window algorithm
func (s *RateLimitValidationServiceImpl) CheckRateLimit(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
	if s.redisClient == nil {
		if s.enableGracefulMode {
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
		return nil, fmt.Errorf("redis client not available for rate limiting")
	}

	// Use fixed window rate limiting
	windowStart := time.Now().Truncate(window)
	windowKey := fmt.Sprintf("rate_limit:%s:%d", key, windowStart.Unix())

	// Get current count
	currentCountStr, err := s.redisClient.Get(ctx, windowKey).Result()
	currentCount := 0
	if err == nil {
		currentCount, _ = strconv.Atoi(currentCountStr)
	}

	// Check if limit exceeded (allow if currentCount < limit, so 2 requests allowed with limit=2)
	allowed := currentCount < limit
	remaining := limit - currentCount
	if remaining < 0 {
		remaining = 0
	}

	result := &domain.RateLimitResult{
		Allowed:      allowed,
		Key:          key,
		CurrentCount: currentCount,
		Limit:        limit,
		Window:       window,
		ResetTime:    windowStart.Add(window),
		Remaining:    remaining,
	}

	if !allowed {
		result.RetryAfter = time.Until(windowStart.Add(window))
		s.logger.Warn("Rate limit exceeded",
			"key", key,
			"current_count", currentCount,
			"limit", limit,
			"window", window,
			"retry_after", result.RetryAfter,
		)
	}

	return result, nil
}

// IncrementCounter increments the request counter for rate limiting
func (s *RateLimitValidationServiceImpl) IncrementCounter(ctx context.Context, key string, window time.Duration) error {
	if s.redisClient == nil {
		if s.enableGracefulMode {
			return nil
		}
		return fmt.Errorf("redis client not available for rate limiting")
	}

	windowStart := time.Now().Truncate(window)
	windowKey := fmt.Sprintf("rate_limit:%s:%d", key, windowStart.Unix())

	// Increment counter and set expiration
	pipe := s.redisClient.Pipeline()
	pipe.Incr(ctx, windowKey)
	pipe.Expire(ctx, windowKey, window+time.Minute) // Add buffer for cleanup
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to increment rate limit counter: %w", err)
	}

	return nil
}

// GetRateLimitStatus gets the current rate limit status for a key
func (s *RateLimitValidationServiceImpl) GetRateLimitStatus(ctx context.Context, key string) (*domain.RateLimitStatus, error) {
	if s.redisClient == nil {
		if s.enableGracefulMode {
			return &domain.RateLimitStatus{
				Key:          key,
				CurrentCount: 0,
				Limit:        s.defaultLimit,
				Window:       s.defaultWindowSize,
				ResetTime:    time.Now().Add(s.defaultWindowSize),
				IsBlocked:    false,
			}, nil
		}
		return nil, fmt.Errorf("redis client not available for rate limiting")
	}

	windowStart := time.Now().Truncate(s.defaultWindowSize)
	windowKey := fmt.Sprintf("rate_limit:%s:%d", key, windowStart.Unix())

	// Get current count
	currentCountStr, err := s.redisClient.Get(ctx, windowKey).Result()
	currentCount := 0
	if err == nil {
		currentCount, _ = strconv.Atoi(currentCountStr)
	}

	// Check if blocked
	blockKey := fmt.Sprintf("blocked:%s", key)
	isBlocked := s.redisClient.Exists(ctx, blockKey).Val() > 0

	return &domain.RateLimitStatus{
		Key:            key,
		CurrentCount:   currentCount,
		Limit:          s.defaultLimit,
		Window:         s.defaultWindowSize,
		FirstRequestAt: windowStart,
		LastRequestAt:  time.Now(),
		ResetTime:      windowStart.Add(s.defaultWindowSize),
		IsBlocked:      isBlocked,
	}, nil
}

// CheckSlidingWindowLimit checks rate limits using sliding window algorithm
func (s *RateLimitValidationServiceImpl) CheckSlidingWindowLimit(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
	if s.redisClient == nil {
		if s.enableGracefulMode {
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
		return nil, fmt.Errorf("redis client not available for rate limiting")
	}

	now := time.Now()
	windowStart := now.Add(-window)
	
	// Use sorted set for sliding window
	zsetKey := fmt.Sprintf("sliding_rate_limit:%s", key)
	
	// Remove old entries outside the window
	s.redisClient.ZRemRangeByScore(ctx, zsetKey, "-inf", fmt.Sprintf("%.0f", float64(windowStart.UnixNano())))
	
	// Count current entries in the window
	currentCount, err := s.redisClient.ZCard(ctx, zsetKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to get sliding window count: %w", err)
	}

	// Check if limit exceeded
	allowed := int(currentCount) < limit
	remaining := limit - int(currentCount)
	if remaining < 0 {
		remaining = 0
	}

	result := &domain.RateLimitResult{
		Allowed:      allowed,
		Key:          key,
		CurrentCount: int(currentCount),
		Limit:        limit,
		Window:       window,
		ResetTime:    now.Add(window),
		Remaining:    remaining,
	}

	if !allowed {
		// Get the oldest entry to calculate retry after
		oldestEntries, err := s.redisClient.ZRangeByScore(ctx, zsetKey, &redis.ZRangeBy{
			Min:   "-inf",
			Max:   "+inf",
			Count: 1,
		}).Result()
		
		if err == nil && len(oldestEntries) > 0 {
			if oldestTime, err := strconv.ParseInt(oldestEntries[0], 10, 64); err == nil {
				oldestTimestamp := time.Unix(0, oldestTime)
				result.RetryAfter = time.Until(oldestTimestamp.Add(window))
			}
		}
	}

	return result, nil
}

// CheckTokenBucketLimit checks rate limits using token bucket algorithm
func (s *RateLimitValidationServiceImpl) CheckTokenBucketLimit(ctx context.Context, key string, capacity int, refillRate float64) (*domain.RateLimitResult, error) {
	if s.redisClient == nil {
		if s.enableGracefulMode {
			return &domain.RateLimitResult{
				Allowed:      true,
				Key:          key,
				CurrentCount: 0,
				Limit:        capacity,
				Remaining:    capacity,
			}, nil
		}
		return nil, fmt.Errorf("redis client not available for rate limiting")
	}

	bucketKey := fmt.Sprintf("token_bucket:%s", key)
	lastRefillKey := fmt.Sprintf("token_bucket_refill:%s", key)
	
	// Lua script for atomic token bucket operations
	luaScript := `
		local bucket_key = KEYS[1]
		local refill_key = KEYS[2]
		local capacity = tonumber(ARGV[1])
		local refill_rate = tonumber(ARGV[2])
		local now = tonumber(ARGV[3])
		
		-- Get current tokens and last refill time
		local current_tokens = tonumber(redis.call('GET', bucket_key) or capacity)
		local last_refill = tonumber(redis.call('GET', refill_key) or now)
		
		-- Calculate tokens to add based on elapsed time
		local elapsed = math.max(0, now - last_refill)
		local tokens_to_add = elapsed * refill_rate / 1000000000  -- Convert nanoseconds to seconds
		current_tokens = math.min(capacity, current_tokens + tokens_to_add)
		
		-- Check if we can consume a token
		local allowed = 0
		if current_tokens >= 1 then
			current_tokens = current_tokens - 1
			allowed = 1
		end
		
		-- Update Redis
		redis.call('SET', bucket_key, current_tokens, 'EX', 3600)  -- 1 hour expiry
		redis.call('SET', refill_key, now, 'EX', 3600)
		
		return {allowed, math.floor(current_tokens)}
	`
	
	now := time.Now().UnixNano()
	result := s.redisClient.Eval(ctx, luaScript, []string{bucketKey, lastRefillKey}, capacity, refillRate, now)
	
	if result.Err() != nil {
		return nil, fmt.Errorf("token bucket evaluation failed: %w", result.Err())
	}
	
	values := result.Val().([]interface{})
	allowed := values[0].(int64) == 1
	remaining := int(values[1].(int64))
	
	return &domain.RateLimitResult{
		Allowed:      allowed,
		Key:          key,
		CurrentCount: capacity - remaining,
		Limit:        capacity,
		Remaining:    remaining,
	}, nil
}

// RecordFailedAttempt records a failed attempt for brute force detection
func (s *RateLimitValidationServiceImpl) RecordFailedAttempt(ctx context.Context, identifier string, attemptType string) error {
	if s.redisClient == nil {
		if s.enableGracefulMode {
			return nil
		}
		return fmt.Errorf("redis client not available")
	}

	attemptKey := fmt.Sprintf("failed_attempts:%s:%s", attemptType, identifier)
	
	// Increment failed attempts counter
	pipe := s.redisClient.Pipeline()
	pipe.Incr(ctx, attemptKey)
	pipe.Expire(ctx, attemptKey, s.bruteForceWindow)
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to record failed attempt: %w", err)
	}

	// Check if we should block after this attempt
	currentAttempts, err := s.redisClient.Get(ctx, attemptKey).Int()
	if err == nil && currentAttempts >= s.bruteForceThreshold {
		// Block the identifier
		blockKey := fmt.Sprintf("blocked:%s:%s", attemptType, identifier)
		if err := s.redisClient.Set(ctx, blockKey, "blocked", s.blockDuration).Err(); err != nil {
			s.logger.Error("Failed to block identifier after brute force detection",
				"identifier", identifier,
				"attempt_type", attemptType,
				"attempts", currentAttempts,
				"error", err,
			)
		} else {
			s.logger.Warn("Identifier blocked due to brute force attempts",
				"identifier", identifier,
				"attempt_type", attemptType,
				"attempts", currentAttempts,
				"block_duration", s.blockDuration,
			)
		}
	}

	return nil
}

// IsBlocked checks if an identifier is currently blocked
func (s *RateLimitValidationServiceImpl) IsBlocked(ctx context.Context, identifier string, attemptType string) (bool, time.Duration, error) {
	if s.redisClient == nil {
		if s.enableGracefulMode {
			return false, 0, nil
		}
		return false, 0, fmt.Errorf("redis client not available")
	}

	blockKey := fmt.Sprintf("blocked:%s:%s", attemptType, identifier)
	
	// Check if block key exists and get TTL
	exists := s.redisClient.Exists(ctx, blockKey).Val() > 0
	if !exists {
		return false, 0, nil
	}

	ttl := s.redisClient.TTL(ctx, blockKey).Val()
	if ttl < 0 {
		// Key exists but has no TTL or is expired
		return false, 0, nil
	}

	return true, ttl, nil
}

// ResetFailedAttempts resets the failed attempts counter for an identifier
func (s *RateLimitValidationServiceImpl) ResetFailedAttempts(ctx context.Context, identifier string, attemptType string) error {
	if s.redisClient == nil {
		if s.enableGracefulMode {
			return nil
		}
		return fmt.Errorf("redis client not available")
	}

	attemptKey := fmt.Sprintf("failed_attempts:%s:%s", attemptType, identifier)
	blockKey := fmt.Sprintf("blocked:%s:%s", attemptType, identifier)

	// Delete both the attempts counter and block key
	pipe := s.redisClient.Pipeline()
	pipe.Del(ctx, attemptKey)
	pipe.Del(ctx, blockKey)
	
	_, err := pipe.Exec(ctx)
	return err
}

// BlockUser blocks a user for a specific duration
func (s *RateLimitValidationServiceImpl) BlockUser(ctx context.Context, userID uint, duration time.Duration, reason string) error {
	if s.redisClient == nil {
		if s.enableGracefulMode {
			return nil
		}
		return fmt.Errorf("redis client not available")
	}

	blockKey := fmt.Sprintf("blocked:user:%d", userID)
	blockInfo := fmt.Sprintf("blocked:%s", reason)

	err := s.redisClient.Set(ctx, blockKey, blockInfo, duration).Err()
	if err != nil {
		return fmt.Errorf("failed to block user %d: %w", userID, err)
	}

	s.logger.Warn("User blocked",
		"user_id", userID,
		"duration", duration,
		"reason", reason,
	)

	return nil
}

// UnblockUser removes a user block
func (s *RateLimitValidationServiceImpl) UnblockUser(ctx context.Context, userID uint) error {
	if s.redisClient == nil {
		if s.enableGracefulMode {
			return nil
		}
		return fmt.Errorf("redis client not available")
	}

	blockKey := fmt.Sprintf("blocked:user:%d", userID)
	
	err := s.redisClient.Del(ctx, blockKey).Err()
	if err != nil {
		return fmt.Errorf("failed to unblock user %d: %w", userID, err)
	}

	s.logger.Info("User unblocked", "user_id", userID)
	return nil
}

// BlockIP blocks an IP address for a specific duration
func (s *RateLimitValidationServiceImpl) BlockIP(ctx context.Context, ipAddress string, duration time.Duration, reason string) error {
	if s.redisClient == nil {
		if s.enableGracefulMode {
			return nil
		}
		return fmt.Errorf("redis client not available")
	}

	blockKey := fmt.Sprintf("blocked:ip:%s", ipAddress)
	blockInfo := fmt.Sprintf("blocked:%s", reason)

	err := s.redisClient.Set(ctx, blockKey, blockInfo, duration).Err()
	if err != nil {
		return fmt.Errorf("failed to block IP %s: %w", ipAddress, err)
	}

	s.logger.Warn("IP address blocked",
		"ip_address", ipAddress,
		"duration", duration,
		"reason", reason,
	)

	return nil
}

// UnblockIP removes an IP address block
func (s *RateLimitValidationServiceImpl) UnblockIP(ctx context.Context, ipAddress string) error {
	if s.redisClient == nil {
		if s.enableGracefulMode {
			return nil
		}
		return fmt.Errorf("redis client not available")
	}

	blockKey := fmt.Sprintf("blocked:ip:%s", ipAddress)
	
	err := s.redisClient.Del(ctx, blockKey).Err()
	if err != nil {
		return fmt.Errorf("failed to unblock IP %s: %w", ipAddress, err)
	}

	s.logger.Info("IP address unblocked", "ip_address", ipAddress)
	return nil
}

// IncrementSlidingWindow adds a new request to the sliding window
func (s *RateLimitValidationServiceImpl) IncrementSlidingWindow(ctx context.Context, key string, window time.Duration) error {
	if s.redisClient == nil {
		if s.enableGracefulMode {
			return nil
		}
		return fmt.Errorf("redis client not available")
	}

	now := time.Now()
	zsetKey := fmt.Sprintf("sliding_rate_limit:%s", key)
	
	// Add current request with timestamp as score
	score := float64(now.UnixNano())
	member := fmt.Sprintf("%d", now.UnixNano())
	
	pipe := s.redisClient.Pipeline()
	pipe.ZAdd(ctx, zsetKey, redis.Z{Score: score, Member: member})
	pipe.Expire(ctx, zsetKey, window+time.Minute) // Add buffer for cleanup
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to increment sliding window: %w", err)
	}

	return nil
}

// ConsumeTokenFromBucket consumes a token from the token bucket
func (s *RateLimitValidationServiceImpl) ConsumeTokenFromBucket(ctx context.Context, key string, capacity int, refillRate float64) error {
	result, err := s.CheckTokenBucketLimit(ctx, key, capacity, refillRate)
	if err != nil {
		return err
	}

	if !result.Allowed {
		return fmt.Errorf("token bucket limit exceeded")
	}

	return nil
}

// Compile-time interface compliance verification
var _ domain.RateLimitValidationService = (*RateLimitValidationServiceImpl)(nil)