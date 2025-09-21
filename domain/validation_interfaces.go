package domain

import (
	"context"
	"time"
)

// RequestValidator orchestrates comprehensive HTTP request validation
// Coordinates field validation, security checks, business rules, and rate limiting
type RequestValidator interface {
	// Core validation operations
	ValidateRequest(ctx context.Context, request interface{}, validationCtx *ValidationContext) (*ValidationResult, error)
	ValidateFields(ctx context.Context, fields map[string]interface{}, rules []ValidationRule) (*ValidationResult, error)
	ValidateField(ctx context.Context, fieldName string, value interface{}, constraints *FieldConstraint) (*FieldValidationResult, error)
	
	// Cross-field validation
	ValidateCrossFields(ctx context.Context, fields map[string]interface{}, constraints []CrossFieldConstraint) (*ValidationResult, error)
	
	// Batch validation for performance
	ValidateBatch(ctx context.Context, requests []interface{}, validationCtx *ValidationContext) ([]ValidationResult, error)
}

// SecurityValidator provides security-focused validation and threat detection
// Handles XSS prevention, SQL injection detection, and content sanitization
type SecurityValidator interface {
	// Threat detection
	ScanForThreats(ctx context.Context, input map[string]interface{}, rules []SecurityConstraint) (*SecurityValidationResult, error)
	DetectXSS(ctx context.Context, input string) (*SecurityValidationResult, error)
	DetectSQLInjection(ctx context.Context, input string) (*SecurityValidationResult, error)
	DetectScriptInjection(ctx context.Context, input string) (*SecurityValidationResult, error)
	
	// Content sanitization
	SanitizeInput(ctx context.Context, input map[string]interface{}, rules []SecurityConstraint) (map[string]interface{}, error)
	SanitizeHTML(ctx context.Context, html string) (string, error)
	EscapeSpecialChars(ctx context.Context, input string) string
	
	// Pattern matching
	MatchBlockedPatterns(ctx context.Context, input string, patterns []string) ([]string, error)
	ValidateEncoding(ctx context.Context, input string, encoding string, maxLayers int) error
	
	// Violation handling
	RecordViolation(ctx context.Context, violation *SecurityViolation) error
	GetViolationHistory(ctx context.Context, userID uint, timeWindow time.Duration) ([]SecurityViolation, error)
}

// BusinessRuleValidator enforces domain-specific business logic and constraints
// Validates business rules, workflow states, and domain-specific requirements
type BusinessRuleValidator interface {
	// Business logic validation
	ValidateBusinessRules(ctx context.Context, entity interface{}, rules []BusinessConstraint) (*ValidationResult, error)
	ValidateWorkflowState(ctx context.Context, entity interface{}, currentState, targetState string) error
	ValidateResourceLimits(ctx context.Context, userID uint, resource string, requestedAmount int) error
	
	// Quota and limits
	CheckQuotaLimits(ctx context.Context, userID uint, operation string) (*QuotaStatus, error)
	ValidateTimeWindows(ctx context.Context, operation string, windows []TimeWindow) error
	
	// Domain validation
	ValidateDomainConstraints(ctx context.Context, entity interface{}, domain string) (*ValidationResult, error)
	ValidateRecurrenceRules(ctx context.Context, rule string, startTime time.Time) error
	
	// Custom validation
	ExecuteCustomValidation(ctx context.Context, entity interface{}, validatorName string, params map[string]interface{}) (*ValidationResult, error)
}

// RateLimitValidator handles rate limiting and brute force protection
// Manages request throttling, user rate limits, and attack prevention
type RateLimitValidator interface {
	// Rate limiting operations
	CheckRateLimit(ctx context.Context, key string, limit int, window time.Duration) (*RateLimitResult, error)
	IncrementCounter(ctx context.Context, key string, window time.Duration) error
	GetRateLimitStatus(ctx context.Context, key string) (*RateLimitStatus, error)
	
	// Advanced rate limiting
	CheckSlidingWindowLimit(ctx context.Context, key string, limit int, window time.Duration) (*RateLimitResult, error)
	CheckTokenBucketLimit(ctx context.Context, key string, capacity int, refillRate float64) (*RateLimitResult, error)
	
	// Brute force protection
	RecordFailedAttempt(ctx context.Context, identifier string, attemptType string) error
	IsBlocked(ctx context.Context, identifier string, attemptType string) (bool, time.Duration, error)
	ResetFailedAttempts(ctx context.Context, identifier string, attemptType string) error
	
	// Blocking and unblocking
	BlockUser(ctx context.Context, userID uint, duration time.Duration, reason string) error
	UnblockUser(ctx context.Context, userID uint) error
	BlockIP(ctx context.Context, ipAddress string, duration time.Duration, reason string) error
	UnblockIP(ctx context.Context, ipAddress string) error
}

// ValidationErrorHandler manages validation error formatting and response handling
// Provides standardized error responses and localization support
type ValidationErrorHandler interface {
	// Error formatting
	FormatValidationErrors(ctx context.Context, result *ValidationResult) (*FormattedErrorResponse, error)
	FormatSecurityViolations(ctx context.Context, violations []SecurityViolation) (*SecurityErrorResponse, error)
	
	// Error responses
	CreateErrorResponse(ctx context.Context, errors []ValidationError, statusCode int) (*ErrorResponse, error)
	CreateSecurityErrorResponse(ctx context.Context, violation *SecurityViolation) (*ErrorResponse, error)
	
	// Localization
	LocalizeErrors(ctx context.Context, errors []ValidationError, locale string) ([]ValidationError, error)
	GetErrorMessage(ctx context.Context, errorCode string, locale string, params map[string]interface{}) (string, error)
	
	// Logging and monitoring
	LogValidationFailure(ctx context.Context, result *ValidationResult, context *ValidationContext) error
	LogSecurityViolation(ctx context.Context, violation *SecurityViolation, context *ValidationContext) error
}

// ValidationRuleRepository handles persistence of validation rules and configurations
type ValidationRuleRepository interface {
	// Rule management
	CreateRule(ctx context.Context, rule *ValidationRule) error
	UpdateRule(ctx context.Context, rule *ValidationRule) error
	DeleteRule(ctx context.Context, ruleID string) error
	FindRuleByID(ctx context.Context, ruleID string) (*ValidationRule, error)
	
	// Rule queries
	FindRulesByCategory(ctx context.Context, category ValidationCategory) ([]ValidationRule, error)
	FindRulesByField(ctx context.Context, fieldName string) ([]ValidationRule, error)
	FindActiveRules(ctx context.Context) ([]ValidationRule, error)
	FindRulesByPriority(ctx context.Context, minPriority int) ([]ValidationRule, error)
	
	// Rule search and filtering
	SearchRules(ctx context.Context, criteria *RuleSearchCriteria) ([]ValidationRule, error)
	GetRulesForValidation(ctx context.Context, endpoint string, method string) ([]ValidationRule, error)
}

// SecurityViolationRepository handles persistence of security violations and audit logs
type SecurityViolationRepository interface {
	// Violation management
	RecordViolation(ctx context.Context, violation *SecurityViolation) error
	GetViolationByID(ctx context.Context, violationID string) (*SecurityViolation, error)
	
	// Violation queries
	GetViolationsByUser(ctx context.Context, userID uint, limit int, offset int) ([]SecurityViolation, error)
	GetViolationsByIP(ctx context.Context, ipAddress string, limit int, offset int) ([]SecurityViolation, error)
	GetViolationsByType(ctx context.Context, threatType ThreatType, limit int, offset int) ([]SecurityViolation, error)
	GetViolationsByTimeRange(ctx context.Context, startTime, endTime time.Time) ([]SecurityViolation, error)
	
	// Analytics and reporting
	GetViolationStats(ctx context.Context, timeWindow time.Duration) (*ViolationStats, error)
	GetTopThreats(ctx context.Context, timeWindow time.Duration, limit int) ([]ThreatSummary, error)
	GetUserThreatProfile(ctx context.Context, userID uint) (*UserThreatProfile, error)
}

// ValidationCacheRepository provides caching for validation rules and results
type ValidationCacheRepository interface {
	// Rule caching
	CacheRule(ctx context.Context, rule *ValidationRule, ttl time.Duration) error
	GetCachedRule(ctx context.Context, ruleID string) (*ValidationRule, error)
	InvalidateRuleCache(ctx context.Context, ruleID string) error
	
	// Result caching
	CacheValidationResult(ctx context.Context, key string, result *ValidationResult, ttl time.Duration) error
	GetCachedValidationResult(ctx context.Context, key string) (*ValidationResult, error)
	
	// Batch operations
	CacheRules(ctx context.Context, rules []ValidationRule, ttl time.Duration) error
	GetCachedRules(ctx context.Context, ruleIDs []string) ([]ValidationRule, error)
	
	// Cache management
	ClearValidationCache(ctx context.Context) error
	GetCacheStats(ctx context.Context) (*CacheStats, error)
}

// Supporting data structures for interface operations

// QuotaStatus represents current quota usage and limits
type QuotaStatus struct {
	UserID         uint              `json:"user_id"`
	Resource       string            `json:"resource"`
	CurrentUsage   int               `json:"current_usage"`
	Limit          int               `json:"limit"`
	Available      int               `json:"available"`
	ResetTime      time.Time         `json:"reset_time"`
	IsExceeded     bool              `json:"is_exceeded"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// RateLimitResult contains the outcome of rate limit checks
type RateLimitResult struct {
	Allowed        bool              `json:"allowed"`
	Key            string            `json:"key"`
	CurrentCount   int               `json:"current_count"`
	Limit          int               `json:"limit"`
	Window         time.Duration     `json:"window"`
	ResetTime      time.Time         `json:"reset_time"`
	RetryAfter     time.Duration     `json:"retry_after,omitempty"`
	Remaining      int               `json:"remaining"`
}

// RateLimitStatus provides current rate limit status for a key
type RateLimitStatus struct {
	Key            string            `json:"key"`
	CurrentCount   int               `json:"current_count"`
	Limit          int               `json:"limit"`
	Window         time.Duration     `json:"window"`
	FirstRequestAt time.Time         `json:"first_request_at"`
	LastRequestAt  time.Time         `json:"last_request_at"`
	ResetTime      time.Time         `json:"reset_time"`
	IsBlocked      bool              `json:"is_blocked"`
}

// FormattedErrorResponse contains formatted validation errors for client consumption
type FormattedErrorResponse struct {
	Message        string                    `json:"message"`
	Errors         []FormattedError          `json:"errors"`
	FieldErrors    map[string][]FormattedError `json:"field_errors,omitempty"`
	Warnings       []FormattedError          `json:"warnings,omitempty"`
	ErrorCode      string                    `json:"error_code"`
	RequestID      string                    `json:"request_id,omitempty"`
	Timestamp      time.Time                 `json:"timestamp"`
}

// FormattedError represents a single formatted validation error
type FormattedError struct {
	Code        string                 `json:"code"`
	Message     string                 `json:"message"`
	Field       string                 `json:"field,omitempty"`
	Severity    ValidationSeverity     `json:"severity"`
	Suggestions []string               `json:"suggestions,omitempty"`
	HelpURL     string                 `json:"help_url,omitempty"`
}

// SecurityErrorResponse contains formatted security violation information
type SecurityErrorResponse struct {
	Message        string                 `json:"message"`
	ThreatLevel    ThreatLevel            `json:"threat_level"`
	Violations     []FormattedViolation   `json:"violations"`
	Action         ViolationAction        `json:"action"`
	Blocked        bool                   `json:"blocked"`
	RequestID      string                 `json:"request_id,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
}

// FormattedViolation represents a formatted security violation
type FormattedViolation struct {
	Type        ThreatType         `json:"type"`
	Severity    ValidationSeverity `json:"severity"`
	Description string             `json:"description"`
	Field       string             `json:"field,omitempty"`
	Action      ViolationAction    `json:"action"`
}

// ErrorResponse represents a standardized API error response
type ErrorResponse struct {
	Success     bool                   `json:"success"`
	Error       string                 `json:"error"`
	ErrorCode   string                 `json:"error_code"`
	Message     string                 `json:"message"`
	Details     interface{}            `json:"details,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	RequestID   string                 `json:"request_id,omitempty"`
	StatusCode  int                    `json:"status_code"`
}

// RuleSearchCriteria defines search parameters for validation rules
type RuleSearchCriteria struct {
	Category     *ValidationCategory `json:"category,omitempty"`
	Severity     *ValidationSeverity `json:"severity,omitempty"`
	FieldName    string              `json:"field_name,omitempty"`
	Tags         []string            `json:"tags,omitempty"`
	IsActive     *bool               `json:"is_active,omitempty"`
	MinPriority  *int                `json:"min_priority,omitempty"`
	MaxPriority  *int                `json:"max_priority,omitempty"`
	CreatedAfter *time.Time          `json:"created_after,omitempty"`
	CreatedBy    string              `json:"created_by,omitempty"`
	TextSearch   string              `json:"text_search,omitempty"`
	Limit        int                 `json:"limit,omitempty"`
	Offset       int                 `json:"offset,omitempty"`
}

// ViolationStats provides statistical information about security violations
type ViolationStats struct {
	TotalViolations     int                        `json:"total_violations"`
	ViolationsByType    map[ThreatType]int         `json:"violations_by_type"`
	ViolationsBySeverity map[ValidationSeverity]int `json:"violations_by_severity"`
	ViolationsByAction  map[ViolationAction]int    `json:"violations_by_action"`
	UniqueUsers         int                        `json:"unique_users"`
	UniqueIPs           int                        `json:"unique_ips"`
	TopViolationTypes   []ThreatSummary            `json:"top_violation_types"`
	TimeWindow          time.Duration              `json:"time_window"`
	GeneratedAt         time.Time                  `json:"generated_at"`
}

// ThreatSummary provides summary information about specific threat types
type ThreatSummary struct {
	Type        ThreatType `json:"type"`
	Count       int        `json:"count"`
	Severity    ValidationSeverity `json:"avg_severity"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastSeen    time.Time  `json:"last_seen"`
	UniqueUsers int        `json:"unique_users"`
	UniqueIPs   int        `json:"unique_ips"`
}

// UserThreatProfile provides threat analysis for a specific user
type UserThreatProfile struct {
	UserID              uint                       `json:"user_id"`
	TotalViolations     int                        `json:"total_violations"`
	RiskScore           float64                    `json:"risk_score"`
	ThreatLevel         ThreatLevel                `json:"threat_level"`
	ViolationsByType    map[ThreatType]int         `json:"violations_by_type"`
	FirstViolation      *time.Time                 `json:"first_violation,omitempty"`
	LastViolation       *time.Time                 `json:"last_violation,omitempty"`
	IsBlocked           bool                       `json:"is_blocked"`
	BlockedUntil        *time.Time                 `json:"blocked_until,omitempty"`
	RecentViolations    []SecurityViolation        `json:"recent_violations,omitempty"`
	Recommendations     []string                   `json:"recommendations,omitempty"`
	GeneratedAt         time.Time                  `json:"generated_at"`
}

// CacheStats provides cache performance and usage statistics
type CacheStats struct {
	TotalKeys       int           `json:"total_keys"`
	HitRate         float64       `json:"hit_rate"`
	MissRate        float64       `json:"miss_rate"`
	TotalRequests   int64         `json:"total_requests"`
	TotalHits       int64         `json:"total_hits"`
	TotalMisses     int64         `json:"total_misses"`
	MemoryUsage     int64         `json:"memory_usage_bytes"`
	AverageKeySize  float64       `json:"average_key_size_bytes"`
	OldestKey       *time.Time    `json:"oldest_key,omitempty"`
	NewestKey       *time.Time    `json:"newest_key,omitempty"`
	GeneratedAt     time.Time     `json:"generated_at"`
}