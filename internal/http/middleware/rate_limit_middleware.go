package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
)

// RateLimitMiddleware provides comprehensive rate limiting with multiple strategies
type RateLimitMiddleware struct {
	redisClient        *redis.Client
	rateLimitValidator domain.RateLimitValidationService
	config            RateLimitConfig
	logger            RateLimitLogger
	metricsCollector  RateLimitMetricsCollector
}

// RateLimitConfig holds configuration for rate limiting
type RateLimitConfig struct {
	// Global settings
	EnableRateLimit     bool
	DefaultWindow       time.Duration
	DefaultLimit        int
	
	// Strategy settings
	EnablePerIP         bool
	EnablePerUser       bool
	EnablePerEndpoint   bool
	EnableSlidingWindow bool
	EnableTokenBucket   bool
	
	// Redis settings
	RedisKeyPrefix     string
	RedisTimeout       time.Duration
	
	// Endpoint-specific limits
	EndpointLimits     map[string]EndpointLimit
	
	// Blocking settings
	EnableAutoBlock    bool
	BlockThreshold     int
	BlockDuration      time.Duration
	
	// Headers
	IncludeHeaders     bool
	HeaderPrefix       string
	
	// Graceful degradation
	AllowOnRedisFailure bool
	FallbackLimit      int
}

// EndpointLimit defines rate limiting for specific endpoints
type EndpointLimit struct {
	Path          string
	Method        string
	Limit         int
	Window        time.Duration
	Strategy      RateLimitStrategy
	UserMultiplier float64  // Multiplier for authenticated users
	IPMultiplier   float64  // Multiplier for IP-based limits
}

// RateLimitStrategy defines the rate limiting algorithm
type RateLimitStrategy string

const (
	StrategyFixedWindow   RateLimitStrategy = "fixed_window"
	StrategySlidingWindow RateLimitStrategy = "sliding_window"
	StrategyTokenBucket   RateLimitStrategy = "token_bucket"
	StrategyLeakyBucket   RateLimitStrategy = "leaky_bucket"
)

// RateLimitLogger interface for rate limit logging
type RateLimitLogger interface {
	LogRateLimitEvent(event RateLimitEvent)
	LogRateLimitViolation(violation RateLimitViolation)
	LogRateLimitError(error RateLimitError)
}

// RateLimitMetricsCollector interface for rate limit metrics
type RateLimitMetricsCollector interface {
	IncrementRateLimitCounter(endpoint string, status string)
	RecordRateLimitLatency(duration time.Duration)
	RecordActiveRateLimits(count int)
	RecordRateLimitViolation(endpoint string, clientType string)
}

// RateLimitEvent represents a rate limiting event
type RateLimitEvent struct {
	ClientID      string    `json:"client_id"`
	Endpoint      string    `json:"endpoint"`
	Method        string    `json:"method"`
	Limit         int       `json:"limit"`
	Current       int       `json:"current"`
	Remaining     int       `json:"remaining"`
	ResetTime     time.Time `json:"reset_time"`
	Strategy      string    `json:"strategy"`
	Allowed       bool      `json:"allowed"`
	Timestamp     time.Time `json:"timestamp"`
}

// RateLimitViolation represents a rate limit violation
type RateLimitViolation struct {
	ClientID      string                 `json:"client_id"`
	ClientIP      string                 `json:"client_ip"`
	UserID        *uint                  `json:"user_id,omitempty"`
	Endpoint      string                 `json:"endpoint"`
	Method        string                 `json:"method"`
	Limit         int                    `json:"limit"`
	Attempts      int                    `json:"attempts"`
	Window        time.Duration          `json:"window"`
	Strategy      string                 `json:"strategy"`
	Blocked       bool                   `json:"blocked"`
	BlockDuration time.Duration          `json:"block_duration,omitempty"`
	Details       map[string]interface{} `json:"details,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
}

// RateLimitError represents a rate limiting error
type RateLimitError struct {
	Operation string                 `json:"operation"`
	ClientID  string                 `json:"client_id"`
	Endpoint  string                 `json:"endpoint"`
	Error     string                 `json:"error"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// RateLimitResult holds the result of a rate limit check
type RateLimitResult struct {
	Allowed     bool
	Limit       int
	Current     int
	Remaining   int
	ResetTime   time.Time
	RetryAfter  time.Duration
}

// NewRateLimitMiddleware creates a new rate limiting middleware
func NewRateLimitMiddleware(
	redisClient *redis.Client,
	rateLimitValidator domain.RateLimitValidationService,
	config RateLimitConfig,
	logger RateLimitLogger,
	metricsCollector RateLimitMetricsCollector,
) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		redisClient:        redisClient,
		rateLimitValidator: rateLimitValidator,
		config:            config,
		logger:            logger,
		metricsCollector:  metricsCollector,
	}
}

// RateLimit creates rate limiting middleware with specified parameters
func (rlm *RateLimitMiddleware) RateLimit(endpoint string, limit int, window time.Duration) gin.HandlerFunc {
	return rlm.RateLimitWithStrategy(endpoint, limit, window, StrategyFixedWindow)
}

// RateLimitWithStrategy creates rate limiting middleware with specified strategy
func (rlm *RateLimitMiddleware) RateLimitWithStrategy(endpoint string, limit int, window time.Duration, strategy RateLimitStrategy) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		if !rlm.config.EnableRateLimit {
			c.Next()
			return
		}
		
		startTime := time.Now()
		
		// Build client identifier
		clientID := rlm.buildClientID(c)
		
		// Get endpoint-specific configuration
		endpointConfig := rlm.getEndpointConfig(endpoint, c.Request.Method)
		if endpointConfig != nil {
			limit = endpointConfig.Limit
			window = endpointConfig.Window
			strategy = endpointConfig.Strategy
			
			// Apply multipliers
			if userID := rlm.getUserID(c); userID != nil {
				limit = int(float64(limit) * endpointConfig.UserMultiplier)
			}
			if rlm.config.EnablePerIP {
				limit = int(float64(limit) * endpointConfig.IPMultiplier)
			}
		}
		
		// Check rate limit
		result, err := rlm.checkRateLimit(c.Request.Context(), clientID, endpoint, limit, window, strategy)
		if err != nil {
			rlm.logError("rate_limit_check", clientID, endpoint, err)
			
			// Handle Redis failure gracefully
			if rlm.config.AllowOnRedisFailure {
				c.Next()
				return
			}
			
			rlm.handleRateLimitError(c, err)
			return
		}
		
		// Add rate limit headers
		if rlm.config.IncludeHeaders {
			rlm.addRateLimitHeaders(c, result)
		}
		
		// Check if request is allowed
		if !result.Allowed {
			rlm.handleRateLimitExceeded(c, clientID, endpoint, result)
			return
		}
		
		// Record metrics
		if rlm.metricsCollector != nil {
			rlm.metricsCollector.IncrementRateLimitCounter(endpoint, "allowed")
			rlm.metricsCollector.RecordRateLimitLatency(time.Since(startTime))
		}
		
		// Log successful rate limit check
		rlm.logEvent(RateLimitEvent{
			ClientID:  clientID,
			Endpoint:  endpoint,
			Method:    c.Request.Method,
			Limit:     limit,
			Current:   result.Current,
			Remaining: result.Remaining,
			ResetTime: result.ResetTime,
			Strategy:  string(strategy),
			Allowed:   true,
			Timestamp: time.Now(),
		})
		
		c.Next()
	})
}

// PerIPRateLimit creates IP-based rate limiting middleware
func (rlm *RateLimitMiddleware) PerIPRateLimit(limit int, window time.Duration) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		if !rlm.config.EnablePerIP {
			c.Next()
			return
		}
		
		clientID := fmt.Sprintf("ip:%s", c.ClientIP())
		endpoint := c.Request.URL.Path
		
		result, err := rlm.checkRateLimit(c.Request.Context(), clientID, endpoint, limit, window, StrategyFixedWindow)
		if err != nil {
			rlm.logError("per_ip_rate_limit", clientID, endpoint, err)
			if rlm.config.AllowOnRedisFailure {
				c.Next()
				return
			}
			rlm.handleRateLimitError(c, err)
			return
		}
		
		if !result.Allowed {
			rlm.handleRateLimitExceeded(c, clientID, endpoint, result)
			return
		}
		
		c.Next()
	})
}

// PerUserRateLimit creates user-based rate limiting middleware
func (rlm *RateLimitMiddleware) PerUserRateLimit(limit int, window time.Duration) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		if !rlm.config.EnablePerUser {
			c.Next()
			return
		}
		
		userID := rlm.getUserID(c)
		if userID == nil {
			c.Next()
			return
		}
		
		clientID := fmt.Sprintf("user:%d", *userID)
		endpoint := c.Request.URL.Path
		
		result, err := rlm.checkRateLimit(c.Request.Context(), clientID, endpoint, limit, window, StrategyFixedWindow)
		if err != nil {
			rlm.logError("per_user_rate_limit", clientID, endpoint, err)
			if rlm.config.AllowOnRedisFailure {
				c.Next()
				return
			}
			rlm.handleRateLimitError(c, err)
			return
		}
		
		if !result.Allowed {
			rlm.handleRateLimitExceeded(c, clientID, endpoint, result)
			return
		}
		
		c.Next()
	})
}

// SlidingWindowRateLimit creates sliding window rate limiting middleware
func (rlm *RateLimitMiddleware) SlidingWindowRateLimit(endpoint string, limit int, window time.Duration) gin.HandlerFunc {
	return rlm.RateLimitWithStrategy(endpoint, limit, window, StrategySlidingWindow)
}

// TokenBucketRateLimit creates token bucket rate limiting middleware
func (rlm *RateLimitMiddleware) TokenBucketRateLimit(endpoint string, capacity int, refillRate float64) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		if !rlm.config.EnableTokenBucket {
			c.Next()
			return
		}
		
		clientID := rlm.buildClientID(c)
		
		// Use rate limit validator for token bucket algorithm
		result, err := rlm.rateLimitValidator.CheckTokenBucketLimit(c.Request.Context(), clientID, capacity, refillRate)
		if err != nil {
			rlm.logError("token_bucket_rate_limit", clientID, endpoint, err)
			if rlm.config.AllowOnRedisFailure {
				c.Next()
				return
			}
			rlm.handleRateLimitError(c, err)
			return
		}
		
		if !result.Allowed {
			rlmResult := &RateLimitResult{
				Allowed:    false,
				Limit:      capacity,
				Current:    capacity,
				Remaining:  0,
				ResetTime:  time.Now().Add(time.Duration(1/refillRate) * time.Second),
				RetryAfter: time.Duration(1/refillRate) * time.Second,
			}
			rlm.handleRateLimitExceeded(c, clientID, endpoint, rlmResult)
			return
		}
		
		c.Next()
	})
}

// checkRateLimit performs rate limiting check using the specified strategy
func (rlm *RateLimitMiddleware) checkRateLimit(ctx context.Context, clientID, endpoint string, limit int, window time.Duration, strategy RateLimitStrategy) (*RateLimitResult, error) {
	key := rlm.buildRedisKey(clientID, endpoint)
	
	switch strategy {
	case StrategySlidingWindow:
		return rlm.checkSlidingWindowLimit(ctx, key, limit, window)
	case StrategyTokenBucket:
		// Token bucket handled separately
		return rlm.checkFixedWindowLimit(ctx, key, limit, window)
	default: // StrategyFixedWindow
		return rlm.checkFixedWindowLimit(ctx, key, limit, window)
	}
}

// checkFixedWindowLimit implements fixed window rate limiting
func (rlm *RateLimitMiddleware) checkFixedWindowLimit(ctx context.Context, key string, limit int, window time.Duration) (*RateLimitResult, error) {
	ctx, cancel := context.WithTimeout(ctx, rlm.config.RedisTimeout)
	defer cancel()
	
	pipe := rlm.redisClient.Pipeline()
	
	// Increment counter
	incrCmd := pipe.Incr(ctx, key)
	
	// Set expiration if key is new
	pipe.Expire(ctx, key, window)
	
	// Get TTL for reset time calculation
	ttlCmd := pipe.TTL(ctx, key)
	
	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, fmt.Errorf("redis pipeline error: %w", err)
	}
	
	// Parse results
	current := int(incrCmd.Val())
	ttl := ttlCmd.Val()
	
	resetTime := time.Now().Add(ttl)
	if ttl < 0 {
		resetTime = time.Now().Add(window)
	}
	
	result := &RateLimitResult{
		Allowed:   current <= limit,
		Limit:     limit,
		Current:   current,
		Remaining: max(0, limit-current),
		ResetTime: resetTime,
	}
	
	if !result.Allowed {
		result.RetryAfter = ttl
		if ttl < 0 {
			result.RetryAfter = window
		}
	}
	
	return result, nil
}

// checkSlidingWindowLimit implements sliding window rate limiting
func (rlm *RateLimitMiddleware) checkSlidingWindowLimit(ctx context.Context, key string, limit int, window time.Duration) (*RateLimitResult, error) {
	ctx, cancel := context.WithTimeout(ctx, rlm.config.RedisTimeout)
	defer cancel()
	
	now := time.Now()
	windowStart := now.Add(-window)
	
	pipe := rlm.redisClient.Pipeline()
	
	// Remove expired entries
	pipe.ZRemRangeByScore(ctx, key, "0", fmt.Sprintf("%d", windowStart.UnixNano()))
	
	// Count current entries
	countCmd := pipe.ZCard(ctx, key)
	
	// Add current request
	pipe.ZAdd(ctx, key, redis.Z{
		Score:  float64(now.UnixNano()),
		Member: now.UnixNano(),
	})
	
	// Set expiration
	pipe.Expire(ctx, key, window)
	
	_, err := pipe.Exec(ctx)
	if err != nil {
		return nil, fmt.Errorf("redis sliding window error: %w", err)
	}
	
	current := int(countCmd.Val()) + 1 // +1 for the current request
	
	result := &RateLimitResult{
		Allowed:   current <= limit,
		Limit:     limit,
		Current:   current,
		Remaining: max(0, limit-current),
		ResetTime: now.Add(window),
	}
	
	if !result.Allowed {
		result.RetryAfter = window
	}
	
	return result, nil
}

// Utility functions

func (rlm *RateLimitMiddleware) buildClientID(c *gin.Context) string {
	if userID := rlm.getUserID(c); userID != nil {
		return fmt.Sprintf("user:%d", *userID)
	}
	return fmt.Sprintf("ip:%s", c.ClientIP())
}

func (rlm *RateLimitMiddleware) getUserID(c *gin.Context) *uint {
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(uint); ok {
			return &uid
		}
	}
	return nil
}

func (rlm *RateLimitMiddleware) buildRedisKey(clientID, endpoint string) string {
	return fmt.Sprintf("%s:rate_limit:%s:%s", rlm.config.RedisKeyPrefix, clientID, endpoint)
}

func (rlm *RateLimitMiddleware) getEndpointConfig(endpoint, method string) *EndpointLimit {
	for _, config := range rlm.config.EndpointLimits {
		if strings.HasPrefix(endpoint, config.Path) && (config.Method == "" || config.Method == method) {
			return &config
		}
	}
	return nil
}

func (rlm *RateLimitMiddleware) addRateLimitHeaders(c *gin.Context, result *RateLimitResult) {
	prefix := rlm.config.HeaderPrefix
	if prefix == "" {
		prefix = "X-RateLimit"
	}
	
	c.Header(fmt.Sprintf("%s-Limit", prefix), strconv.Itoa(result.Limit))
	c.Header(fmt.Sprintf("%s-Remaining", prefix), strconv.Itoa(result.Remaining))
	c.Header(fmt.Sprintf("%s-Reset", prefix), strconv.FormatInt(result.ResetTime.Unix(), 10))
}

// Error handling

func (rlm *RateLimitMiddleware) handleRateLimitExceeded(c *gin.Context, clientID, endpoint string, result *RateLimitResult) {
	// Log violation
	violation := RateLimitViolation{
		ClientID:  clientID,
		ClientIP:  c.ClientIP(),
		UserID:    rlm.getUserID(c),
		Endpoint:  endpoint,
		Method:    c.Request.Method,
		Limit:     result.Limit,
		Attempts:  result.Current,
		Blocked:   true,
		Timestamp: time.Now(),
	}
	
	rlm.logViolation(violation)
	
	// Record metrics
	if rlm.metricsCollector != nil {
		rlm.metricsCollector.IncrementRateLimitCounter(endpoint, "exceeded")
		clientType := "ip"
		if strings.HasPrefix(clientID, "user:") {
			clientType = "user"
		}
		rlm.metricsCollector.RecordRateLimitViolation(endpoint, clientType)
	}
	
	// Add headers
	if rlm.config.IncludeHeaders {
		rlm.addRateLimitHeaders(c, result)
	}
	
	// Send error response
	c.JSON(http.StatusTooManyRequests, gin.H{
		"status":      "error",
		"code":        "RATE_LIMIT_EXCEEDED",
		"message":     "Rate limit exceeded",
		"limit":       result.Limit,
		"remaining":   result.Remaining,
		"reset_time":  result.ResetTime.Unix(),
		"retry_after": int(result.RetryAfter.Seconds()),
		"timestamp":   time.Now().Format(time.RFC3339),
	})
	c.Abort()
}

func (rlm *RateLimitMiddleware) handleRateLimitError(c *gin.Context, err error) {
	c.JSON(http.StatusInternalServerError, gin.H{
		"status":    "error",
		"code":      "RATE_LIMIT_ERROR",
		"message":   "Rate limiting service unavailable",
		"timestamp": time.Now().Format(time.RFC3339),
	})
	c.Abort()
}

// Logging methods

func (rlm *RateLimitMiddleware) logEvent(event RateLimitEvent) {
	if rlm.logger != nil {
		rlm.logger.LogRateLimitEvent(event)
	}
}

func (rlm *RateLimitMiddleware) logViolation(violation RateLimitViolation) {
	if rlm.logger != nil {
		rlm.logger.LogRateLimitViolation(violation)
	}
}

func (rlm *RateLimitMiddleware) logError(operation, clientID, endpoint string, err error) {
	if rlm.logger != nil {
		rlm.logger.LogRateLimitError(RateLimitError{
			Operation: operation,
			ClientID:  clientID,
			Endpoint:  endpoint,
			Error:     err.Error(),
			Timestamp: time.Now(),
		})
	}
}

// Utility function
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// DefaultRateLimitConfig returns default rate limiting configuration
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		EnableRateLimit:     true,
		DefaultWindow:       time.Minute,
		DefaultLimit:        60,
		EnablePerIP:         true,
		EnablePerUser:       true,
		EnablePerEndpoint:   true,
		EnableSlidingWindow: true,
		EnableTokenBucket:   false,
		RedisKeyPrefix:     "authzsvc",
		RedisTimeout:       time.Second * 2,
		EndpointLimits: map[string]EndpointLimit{
			"/auth/register": {
				Path:           "/auth/register",
				Method:         "POST",
				Limit:          5,
				Window:         time.Minute,
				Strategy:       StrategyFixedWindow,
				UserMultiplier: 1.0,
				IPMultiplier:   1.0,
			},
			"/auth/login": {
				Path:           "/auth/login",
				Method:         "POST",
				Limit:          10,
				Window:         time.Minute,
				Strategy:       StrategySlidingWindow,
				UserMultiplier: 1.5,
				IPMultiplier:   1.0,
			},
			"/auth/otp": {
				Path:           "/auth/otp",
				Method:         "POST",
				Limit:          3,
				Window:         time.Minute,
				Strategy:       StrategyFixedWindow,
				UserMultiplier: 1.0,
				IPMultiplier:   1.0,
			},
		},
		EnableAutoBlock:     true,
		BlockThreshold:      10,
		BlockDuration:       time.Hour,
		IncludeHeaders:      true,
		HeaderPrefix:        "X-RateLimit",
		AllowOnRedisFailure: true,
		FallbackLimit:       100,
	}
}