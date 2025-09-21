package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
)

// ValidationErrorHandler provides standardized error response handling for validation failures
type ValidationErrorHandler struct {
	logger           ValidationErrorLogger
	metricsCollector ValidationErrorMetricsCollector
	config          ValidationErrorConfig
}

// ValidationErrorConfig holds configuration for error handling
type ValidationErrorConfig struct {
	// Error response settings
	IncludeStackTrace     bool
	IncludeFieldDetails   bool
	IncludeHelpURLs       bool
	IncludeSuggestions    bool
	MaskSensitiveFields   bool
	
	// Security settings
	HideInternalErrors    bool
	SanitizeErrorMessages bool
	LogSecurityViolations bool
	
	// Localization
	DefaultLanguage       string
	SupportedLanguages    []string
	
	// Rate limiting for error responses
	ErrorRateLimit        int
	ErrorRateLimitWindow  time.Duration
	
	// Help URLs
	BaseHelpURL          string
	ValidationHelpPath   string
	SecurityHelpPath     string
}

// ValidationErrorLogger interface for logging validation errors
type ValidationErrorLogger interface {
	LogValidationError(ctx context.Context, event ValidationErrorEvent)
	LogSecurityViolation(ctx context.Context, violation SecurityViolationEvent)
	LogErrorHandlingMetrics(ctx context.Context, metrics ErrorHandlingMetrics)
}

// ValidationErrorMetricsCollector interface for error metrics
type ValidationErrorMetricsCollector interface {
	IncrementErrorCounter(errorType string, severity string)
	RecordErrorHandlingLatency(duration time.Duration)
	RecordSecurityViolationRate(violationType string)
	RecordUserErrorFrequency(userID *uint, errorType string)
}

// ValidationErrorEvent represents a validation error event for logging
type ValidationErrorEvent struct {
	RequestID      string                 `json:"request_id"`
	UserID         *uint                  `json:"user_id,omitempty"`
	ClientIP       string                 `json:"client_ip"`
	UserAgent      string                 `json:"user_agent,omitempty"`
	Endpoint       string                 `json:"endpoint"`
	Method         string                 `json:"method"`
	ErrorCode      string                 `json:"error_code"`
	ErrorMessage   string                 `json:"error_message"`
	ErrorSeverity  string                 `json:"error_severity"`
	ErrorCategory  string                 `json:"error_category"`
	FieldName      string                 `json:"field_name,omitempty"`
	FieldValue     string                 `json:"field_value,omitempty"`
	ValidationRule string                 `json:"validation_rule,omitempty"`
	Context        map[string]interface{} `json:"context,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
}

// SecurityViolationEvent represents a security violation for logging
type SecurityViolationEvent struct {
	RequestID     string                 `json:"request_id"`
	UserID        *uint                  `json:"user_id,omitempty"`
	ClientIP      string                 `json:"client_ip"`
	UserAgent     string                 `json:"user_agent,omitempty"`
	ViolationType string                 `json:"violation_type"`
	ThreatLevel   string                 `json:"threat_level"`
	Description   string                 `json:"description"`
	BlockedContent []string              `json:"blocked_content,omitempty"`
	Context       map[string]interface{} `json:"context,omitempty"`
	Action        string                 `json:"action"`
	Timestamp     time.Time              `json:"timestamp"`
}

// ErrorHandlingMetrics represents metrics for error handling
type ErrorHandlingMetrics struct {
	TotalErrors       int           `json:"total_errors"`
	ErrorsByType      map[string]int `json:"errors_by_type"`
	ErrorsBySeverity  map[string]int `json:"errors_by_severity"`
	AvgResponseTime   time.Duration `json:"avg_response_time"`
	SecurityViolations int          `json:"security_violations"`
	Timestamp         time.Time     `json:"timestamp"`
}

// StandardizedErrorResponse represents the standardized error response format
type StandardizedErrorResponse struct {
	Status     string      `json:"status"`
	Code       string      `json:"code"`
	Message    string      `json:"message"`
	Errors     []FieldError `json:"errors,omitempty"`
	RequestID  string      `json:"request_id"`
	Timestamp  string      `json:"timestamp"`
	HelpURL    string      `json:"help_url,omitempty"`
	Suggestion string      `json:"suggestion,omitempty"`
	Details    interface{} `json:"details,omitempty"`
}

// FieldError represents a field-specific error
type FieldError struct {
	Field       string      `json:"field"`
	Code        string      `json:"code"`
	Message     string      `json:"message"`
	Value       interface{} `json:"value,omitempty"`
	Constraint  string      `json:"constraint,omitempty"`
	Suggestion  string      `json:"suggestion,omitempty"`
	HelpURL     string      `json:"help_url,omitempty"`
}

// SecurityViolationResponse represents a security violation response
type SecurityViolationResponse struct {
	Status       string    `json:"status"`
	Code         string    `json:"code"`
	Message      string    `json:"message"`
	ThreatLevel  string    `json:"threat_level,omitempty"`
	ThreatTypes  []string  `json:"threat_types,omitempty"`
	RequestID    string    `json:"request_id"`
	Timestamp    string    `json:"timestamp"`
	Action       string    `json:"action"`
	BlockReason  string    `json:"block_reason,omitempty"`
}

// RateLimitErrorResponse represents a rate limit exceeded response
type RateLimitErrorResponse struct {
	Status       string `json:"status"`
	Code         string `json:"code"`
	Message      string `json:"message"`
	Limit        int    `json:"limit"`
	Remaining    int    `json:"remaining"`
	ResetTime    int64  `json:"reset_time"`
	RetryAfter   int    `json:"retry_after"`
	RequestID    string `json:"request_id"`
	Timestamp    string `json:"timestamp"`
}

// NewValidationErrorHandler creates a new validation error handler
func NewValidationErrorHandler(
	logger ValidationErrorLogger,
	metricsCollector ValidationErrorMetricsCollector,
	config ValidationErrorConfig,
) *ValidationErrorHandler {
	return &ValidationErrorHandler{
		logger:           logger,
		metricsCollector: metricsCollector,
		config:          config,
	}
}

// HandleValidationError handles general validation errors
func (veh *ValidationErrorHandler) HandleValidationError(c *gin.Context, validationErr *domain.ValidationError, validationCtx *domain.ValidationContext) {
	startTime := time.Now()
	
	// Log the validation error
	veh.logValidationError(c.Request.Context(), validationErr, validationCtx)
	
	// Record metrics
	if veh.metricsCollector != nil {
		veh.metricsCollector.IncrementErrorCounter(validationErr.Code, string(validationErr.Severity))
	}
	
	// Determine HTTP status code
	statusCode := veh.getStatusCodeForValidationError(validationErr)
	
	// Build standardized response
	response := veh.buildValidationErrorResponse(validationErr, validationCtx)
	
	// Record latency
	if veh.metricsCollector != nil {
		veh.metricsCollector.RecordErrorHandlingLatency(time.Since(startTime))
	}
	
	// Send response
	c.JSON(statusCode, response)
	c.Abort()
}

// HandleValidationFailures handles multiple validation failures
func (veh *ValidationErrorHandler) HandleValidationFailures(c *gin.Context, result *domain.ValidationResult, validationCtx *domain.ValidationContext) {
	startTime := time.Now()
	
	// Log each validation error
	for _, err := range result.Errors {
		veh.logValidationError(c.Request.Context(), &err, validationCtx)
		if veh.metricsCollector != nil {
			veh.metricsCollector.IncrementErrorCounter(err.Code, string(err.Severity))
		}
	}
	
	// Determine the highest severity status code
	statusCode := veh.getStatusCodeForValidationResult(result)
	
	// Build aggregated response
	response := veh.buildValidationFailuresResponse(result, validationCtx)
	
	// Record latency
	if veh.metricsCollector != nil {
		veh.metricsCollector.RecordErrorHandlingLatency(time.Since(startTime))
	}
	
	// Send response
	c.JSON(statusCode, response)
	c.Abort()
}

// HandleSecurityViolation handles security violations
func (veh *ValidationErrorHandler) HandleSecurityViolation(c *gin.Context, violation *domain.SecurityViolation, validationCtx *domain.ValidationContext) {
	startTime := time.Now()
	
	// Log security violation
	veh.logSecurityViolation(c.Request.Context(), violation, validationCtx)
	
	// Record metrics
	if veh.metricsCollector != nil {
		veh.metricsCollector.RecordSecurityViolationRate(string(violation.Type))
		veh.metricsCollector.IncrementErrorCounter("SECURITY_VIOLATION", string(violation.Severity))
	}
	
	// Determine status code based on severity
	statusCode := veh.getStatusCodeForSecurityViolation(violation)
	
	// Build security violation response
	response := veh.buildSecurityViolationResponse(violation, validationCtx)
	
	// Record latency
	if veh.metricsCollector != nil {
		veh.metricsCollector.RecordErrorHandlingLatency(time.Since(startTime))
	}
	
	// Send response
	c.JSON(statusCode, response)
	c.Abort()
}

// HandleBusinessValidationError handles business rule validation errors
func (veh *ValidationErrorHandler) HandleBusinessValidationError(c *gin.Context, err error, validationCtx *domain.ValidationContext) {
	startTime := time.Now()
	
	// Create validation error from business error
	validationErr := &domain.ValidationError{
		Code:     "BUSINESS_RULE_VIOLATION",
		Message:  err.Error(),
		Severity: domain.SeverityError,
		Category: domain.CategoryBusiness,
		Timestamp: time.Now(),
	}
	
	veh.HandleValidationError(c, validationErr, validationCtx)
	
	// Record latency
	if veh.metricsCollector != nil {
		veh.metricsCollector.RecordErrorHandlingLatency(time.Since(startTime))
	}
}

// HandleRateLimitExceeded handles rate limit exceeded errors
func (veh *ValidationErrorHandler) HandleRateLimitExceeded(c *gin.Context, limit, remaining int, resetTime time.Time, retryAfter time.Duration, validationCtx *domain.ValidationContext) {
	startTime := time.Now()
	
	// Log rate limit violation
	veh.logRateLimitViolation(c.Request.Context(), validationCtx, limit, remaining)
	
	// Record metrics
	if veh.metricsCollector != nil {
		veh.metricsCollector.IncrementErrorCounter("RATE_LIMIT_EXCEEDED", "error")
	}
	
	// Build rate limit response
	response := RateLimitErrorResponse{
		Status:     "error",
		Code:       "RATE_LIMIT_EXCEEDED",
		Message:    "Rate limit exceeded. Please try again later.",
		Limit:      limit,
		Remaining:  remaining,
		ResetTime:  resetTime.Unix(),
		RetryAfter: int(retryAfter.Seconds()),
		RequestID:  validationCtx.RequestID,
		Timestamp:  time.Now().Format(time.RFC3339),
	}
	
	// Record latency
	if veh.metricsCollector != nil {
		veh.metricsCollector.RecordErrorHandlingLatency(time.Since(startTime))
	}
	
	// Send response
	c.JSON(http.StatusTooManyRequests, response)
	c.Abort()
}

// Helper methods for building responses

func (veh *ValidationErrorHandler) buildValidationErrorResponse(validationErr *domain.ValidationError, validationCtx *domain.ValidationContext) StandardizedErrorResponse {
	response := StandardizedErrorResponse{
		Status:    "error",
		Code:      validationErr.Code,
		Message:   veh.sanitizeErrorMessage(validationErr.Message),
		RequestID: validationCtx.RequestID,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	
	// Add field error if present
	if validationErr.Field != "" {
		fieldError := FieldError{
			Field:      validationErr.Field,
			Code:       validationErr.Code,
			Message:    veh.sanitizeErrorMessage(validationErr.Message),
			Constraint: validationErr.Constraint,
		}
		
		// Add field value if configuration allows and not sensitive
		if veh.config.IncludeFieldDetails && !veh.isSensitiveField(validationErr.Field) {
			fieldError.Value = validationErr.Value
		}
		
		// Add suggestions if enabled
		if veh.config.IncludeSuggestions && len(validationErr.Suggestions) > 0 {
			fieldError.Suggestion = validationErr.Suggestions[0]
		}
		
		// Add help URL if enabled
		if veh.config.IncludeHelpURLs {
			fieldError.HelpURL = veh.buildHelpURL(validationErr.Code, "validation")
		}
		
		response.Errors = []FieldError{fieldError}
	}
	
	// Add help URL
	if veh.config.IncludeHelpURLs {
		response.HelpURL = veh.buildHelpURL(validationErr.Code, "validation")
	}
	
	// Add suggestions
	if veh.config.IncludeSuggestions && len(validationErr.Suggestions) > 0 {
		response.Suggestion = validationErr.Suggestions[0]
	}
	
	// Add details if not hiding internal errors
	if !veh.config.HideInternalErrors && validationErr.Metadata != nil {
		response.Details = validationErr.Metadata
	}
	
	return response
}

func (veh *ValidationErrorHandler) buildValidationFailuresResponse(result *domain.ValidationResult, validationCtx *domain.ValidationContext) StandardizedErrorResponse {
	response := StandardizedErrorResponse{
		Status:    "error",
		Code:      "VALIDATION_FAILED",
		Message:   fmt.Sprintf("Request validation failed with %d errors", len(result.Errors)),
		RequestID: validationCtx.RequestID,
		Timestamp: time.Now().Format(time.RFC3339),
	}
	
	// Build field errors
	fieldErrors := make([]FieldError, 0, len(result.Errors))
	for _, err := range result.Errors {
		fieldError := FieldError{
			Field:      err.Field,
			Code:       err.Code,
			Message:    veh.sanitizeErrorMessage(err.Message),
			Constraint: err.Constraint,
		}
		
		// Add field value if configuration allows and not sensitive
		if veh.config.IncludeFieldDetails && !veh.isSensitiveField(err.Field) {
			fieldError.Value = err.Value
		}
		
		// Add suggestions if enabled
		if veh.config.IncludeSuggestions && len(err.Suggestions) > 0 {
			fieldError.Suggestion = err.Suggestions[0]
		}
		
		// Add help URL if enabled
		if veh.config.IncludeHelpURLs {
			fieldError.HelpURL = veh.buildHelpURL(err.Code, "validation")
		}
		
		fieldErrors = append(fieldErrors, fieldError)
	}
	
	response.Errors = fieldErrors
	
	// Add general help URL
	if veh.config.IncludeHelpURLs {
		response.HelpURL = veh.buildHelpURL("VALIDATION_FAILED", "validation")
	}
	
	// Add performance details if not hiding internal errors
	if !veh.config.HideInternalErrors {
		response.Details = map[string]interface{}{
			"validation_time": result.ValidationTime.String(),
			"rules_applied":   result.RulesApplied,
		}
	}
	
	return response
}

func (veh *ValidationErrorHandler) buildSecurityViolationResponse(violation *domain.SecurityViolation, validationCtx *domain.ValidationContext) SecurityViolationResponse {
	response := SecurityViolationResponse{
		Status:      "error",
		Code:        "SECURITY_VIOLATION",
		Message:     veh.getSecurityViolationMessage(violation),
		ThreatLevel: string(violation.Severity),
		ThreatTypes: []string{string(violation.Type)},
		RequestID:   validationCtx.RequestID,
		Timestamp:   time.Now().Format(time.RFC3339),
		Action:      string(violation.Action),
	}
	
	// Add block reason if blocked
	if violation.Blocked {
		response.BlockReason = "Request blocked due to security policy violation"
	}
	
	return response
}

// Helper methods for status codes

func (veh *ValidationErrorHandler) getStatusCodeForValidationError(validationErr *domain.ValidationError) int {
	switch validationErr.Severity {
	case domain.SeverityCritical:
		return http.StatusForbidden
	case domain.SeverityError:
		return http.StatusBadRequest
	case domain.SeverityWarning:
		return http.StatusBadRequest
	default:
		return http.StatusBadRequest
	}
}

func (veh *ValidationErrorHandler) getStatusCodeForValidationResult(result *domain.ValidationResult) int {
	highestSeverity := domain.SeverityInfo
	for _, err := range result.Errors {
		if veh.isSeverityHigher(err.Severity, highestSeverity) {
			highestSeverity = err.Severity
		}
	}
	
	switch highestSeverity {
	case domain.SeverityCritical:
		return http.StatusForbidden
	case domain.SeverityError:
		return http.StatusBadRequest
	case domain.SeverityWarning:
		return http.StatusBadRequest
	default:
		return http.StatusBadRequest
	}
}

func (veh *ValidationErrorHandler) getStatusCodeForSecurityViolation(violation *domain.SecurityViolation) int {
	switch violation.Severity {
	case domain.SeverityCritical:
		return http.StatusForbidden
	case domain.SeverityError:
		return http.StatusBadRequest
	case domain.SeverityWarning:
		return http.StatusBadRequest
	default:
		return http.StatusBadRequest
	}
}

// Utility methods

func (veh *ValidationErrorHandler) sanitizeErrorMessage(message string) string {
	if !veh.config.SanitizeErrorMessages {
		return message
	}
	
	// Remove potentially sensitive information
	sanitized := message
	
	// Remove file paths
	sanitized = strings.ReplaceAll(sanitized, "/var/", "***/")
	sanitized = strings.ReplaceAll(sanitized, "/usr/", "***/")
	sanitized = strings.ReplaceAll(sanitized, "/home/", "***/")
	
	// Remove database connection strings
	if strings.Contains(strings.ToLower(sanitized), "connection") {
		sanitized = "Database connection error"
	}
	
	return sanitized
}

func (veh *ValidationErrorHandler) isSensitiveField(fieldName string) bool {
	sensitiveFields := []string{"password", "token", "secret", "key", "auth", "credential"}
	lowerFieldName := strings.ToLower(fieldName)
	
	for _, sensitive := range sensitiveFields {
		if strings.Contains(lowerFieldName, sensitive) {
			return true
		}
	}
	
	return false
}

func (veh *ValidationErrorHandler) buildHelpURL(errorCode, category string) string {
	if veh.config.BaseHelpURL == "" {
		return ""
	}
	
	var path string
	switch category {
	case "validation":
		path = veh.config.ValidationHelpPath
	case "security":
		path = veh.config.SecurityHelpPath
	default:
		path = "/help"
	}
	
	return fmt.Sprintf("%s%s/%s", veh.config.BaseHelpURL, path, strings.ToLower(errorCode))
}

func (veh *ValidationErrorHandler) getSecurityViolationMessage(violation *domain.SecurityViolation) string {
	switch violation.Type {
	case domain.ThreatXSS:
		return "Cross-site scripting attempt detected"
	case domain.ThreatSQLInjection:
		return "SQL injection attempt detected"
	case domain.ThreatScriptInjection:
		return "Script injection attempt detected"
	default:
		return "Security violation detected"
	}
}

func (veh *ValidationErrorHandler) isSeverityHigher(sev1, sev2 domain.ValidationSeverity) bool {
	severityOrder := map[domain.ValidationSeverity]int{
		domain.SeverityInfo:     1,
		domain.SeverityWarning:  2,
		domain.SeverityError:    3,
		domain.SeverityCritical: 4,
	}
	
	return severityOrder[sev1] > severityOrder[sev2]
}

// Logging methods

func (veh *ValidationErrorHandler) logValidationError(ctx context.Context, validationErr *domain.ValidationError, validationCtx *domain.ValidationContext) {
	if veh.logger == nil {
		return
	}
	
	event := ValidationErrorEvent{
		RequestID:      validationCtx.RequestID,
		UserID:         validationCtx.UserID,
		ClientIP:       validationCtx.IPAddress,
		UserAgent:      validationCtx.UserAgent,
		Endpoint:       validationCtx.Endpoint,
		Method:         validationCtx.Method,
		ErrorCode:      validationErr.Code,
		ErrorMessage:   validationErr.Message,
		ErrorSeverity:  string(validationErr.Severity),
		ErrorCategory:  string(validationErr.Category),
		FieldName:      validationErr.Field,
		ValidationRule: validationErr.Constraint,
		Context:        validationErr.Metadata,
		Timestamp:      time.Now(),
	}
	
	// Mask sensitive field values
	if veh.isSensitiveField(validationErr.Field) {
		event.FieldValue = "***REDACTED***"
	} else if validationErr.Value != nil {
		event.FieldValue = fmt.Sprintf("%v", validationErr.Value)
	}
	
	veh.logger.LogValidationError(ctx, event)
}

func (veh *ValidationErrorHandler) logSecurityViolation(ctx context.Context, violation *domain.SecurityViolation, validationCtx *domain.ValidationContext) {
	if veh.logger == nil || !veh.config.LogSecurityViolations {
		return
	}
	
	event := SecurityViolationEvent{
		RequestID:     validationCtx.RequestID,
		UserID:        validationCtx.UserID,
		ClientIP:      validationCtx.IPAddress,
		UserAgent:     validationCtx.UserAgent,
		ViolationType: string(violation.Type),
		ThreatLevel:   string(violation.Severity),
		Description:   violation.Description,
		Context:       violation.Context,
		Action:        string(violation.Action),
		Timestamp:     time.Now(),
	}
	
	veh.logger.LogSecurityViolation(ctx, event)
}

func (veh *ValidationErrorHandler) logRateLimitViolation(ctx context.Context, validationCtx *domain.ValidationContext, limit, remaining int) {
	if veh.logger == nil {
		return
	}
	
	event := ValidationErrorEvent{
		RequestID:     validationCtx.RequestID,
		UserID:        validationCtx.UserID,
		ClientIP:      validationCtx.IPAddress,
		UserAgent:     validationCtx.UserAgent,
		Endpoint:      validationCtx.Endpoint,
		Method:        validationCtx.Method,
		ErrorCode:     "RATE_LIMIT_EXCEEDED",
		ErrorMessage:  "Rate limit exceeded",
		ErrorSeverity: "error",
		ErrorCategory: "rate_limit",
		Context: map[string]interface{}{
			"limit":     limit,
			"remaining": remaining,
		},
		Timestamp: time.Now(),
	}
	
	veh.logger.LogValidationError(ctx, event)
}

// DefaultValidationErrorConfig returns default validation error configuration
func DefaultValidationErrorConfig() ValidationErrorConfig {
	return ValidationErrorConfig{
		IncludeStackTrace:     false,
		IncludeFieldDetails:   true,
		IncludeHelpURLs:       true,
		IncludeSuggestions:    true,
		MaskSensitiveFields:   true,
		HideInternalErrors:    true,
		SanitizeErrorMessages: true,
		LogSecurityViolations: true,
		DefaultLanguage:       "en",
		SupportedLanguages:    []string{"en", "pt", "es"},
		ErrorRateLimit:        100,
		ErrorRateLimitWindow:  time.Minute,
		BaseHelpURL:          "https://docs.example.com",
		ValidationHelpPath:   "/validation",
		SecurityHelpPath:     "/security",
	}
}