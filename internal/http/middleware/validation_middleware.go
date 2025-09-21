package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
)

// ValidationMiddleware provides comprehensive request validation with multi-layer security
type ValidationMiddleware struct {
	requestValidator  domain.RequestValidationService
	securityValidator domain.SecurityValidationService
	businessValidator domain.BusinessValidationService
	rateLimitValidator domain.RateLimitValidationService
	metricsCollector  ValidationMetricsCollector
	logger           ValidationLogger
	config           ValidationConfig
}

// ValidationConfig holds configuration for validation middleware
type ValidationConfig struct {
	EnableSecurityValidation bool
	EnableBusinessValidation bool  
	EnableRateLimiting      bool
	MaxRequestSize          int64
	ValidationTimeout       time.Duration
	SkipValidationPaths     []string
	LogValidationEvents     bool
	EnableMetrics           bool
	ShadowMode             bool // CB-182: Log violations but don't block requests
}

// ValidationMetricsCollector interface for validation metrics
type ValidationMetricsCollector interface {
	IncrementValidationCounter(status string, endpoint string)
	RecordValidationDuration(duration time.Duration, endpoint string)
	RecordSecurityViolation(violationType string, endpoint string)
	RecordRateLimitHit(endpoint string, clientID string)
}

// ValidationLogger interface for validation logging
type ValidationLogger interface {
	LogValidationEvent(ctx context.Context, event ValidationEvent)
	LogSecurityViolation(ctx context.Context, violation *domain.SecurityViolation)
	LogValidationError(ctx context.Context, err *domain.ValidationError, requestCtx *domain.ValidationContext)
}

// ValidationEvent represents a validation event for logging
type ValidationEvent struct {
	RequestID     string                    `json:"request_id"`
	Endpoint      string                    `json:"endpoint"`
	Method        string                    `json:"method"`
	UserID        *uint                     `json:"user_id,omitempty"`
	IPAddress     string                    `json:"ip_address"`
	ValidationResult *domain.ValidationResult `json:"validation_result"`
	Duration      time.Duration             `json:"duration"`
	Timestamp     time.Time                 `json:"timestamp"`
}

// NewValidationMiddleware creates a new validation middleware with dependencies
func NewValidationMiddleware(
	requestValidator domain.RequestValidationService,
	securityValidator domain.SecurityValidationService,
	businessValidator domain.BusinessValidationService,
	rateLimitValidator domain.RateLimitValidationService,
	metricsCollector ValidationMetricsCollector,
	logger ValidationLogger,
	config ValidationConfig,
) *ValidationMiddleware {
	return &ValidationMiddleware{
		requestValidator:   requestValidator,
		securityValidator:  securityValidator,
		businessValidator:  businessValidator,
		rateLimitValidator: rateLimitValidator,
		metricsCollector:   metricsCollector,
		logger:            logger,
		config:            config,
	}
}

// ValidateRequest is the main validation middleware handler
func (vm *ValidationMiddleware) ValidateRequest() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		startTime := time.Now()
		
		// Skip validation for configured paths
		if vm.shouldSkipValidation(c.Request.URL.Path) {
			c.Next()
			return
		}
		
		// Build validation context
		validationCtx := vm.buildValidationContext(c)
		
		// Set timeout for validation
		ctx, cancel := context.WithTimeout(c.Request.Context(), vm.config.ValidationTimeout)
		defer cancel()
		
		// Phase 1: Rate limiting validation (if enabled)
		if vm.config.EnableRateLimiting {
			if err := vm.validateRateLimit(ctx, validationCtx, c); err != nil {
				vm.handleRateLimitExceeded(c, err, validationCtx)
				return
			}
		}
		
		// Phase 2: Extract and validate request body
		requestBody, err := vm.extractRequestBody(c)
		if err != nil {
			vm.handleValidationError(c, &domain.ValidationError{
				Code:     "INVALID_REQUEST_BODY",
				Message:  "Failed to parse request body",
				Severity: domain.SeverityError,
				Category: domain.CategoryField,
				Metadata: map[string]interface{}{"error": err.Error()},
			}, validationCtx)
			return
		}
		
		// Phase 3: Security validation (if enabled)
		if vm.config.EnableSecurityValidation {
			securityResult, err := vm.validateSecurity(ctx, requestBody, validationCtx)
			if err != nil {
				vm.handleSecurityViolation(c, err, validationCtx)
				return
			}
			
			// Handle security violations
			if securityResult != nil && securityResult.ThreatLevel != domain.ThreatNone {
				vm.handleSecurityThreat(c, securityResult, validationCtx)
				return
			}
		}
		
		// Phase 4: Request structure validation (call appropriate validation method based on endpoint)
		var validationResult *domain.ValidationResult
		var validationErr error
		
		switch validationCtx.Endpoint {
		case "/auth/login":
			// Extract email and password from request body for login validation
			if requestMap, ok := requestBody.(map[string]interface{}); ok {
				email, _ := requestMap["email"].(string)
				password, _ := requestMap["password"].(string)
				validationResult, validationErr = vm.requestValidator.ValidateLoginRequest(ctx, email, password, validationCtx)
			} else {
				validationResult, validationErr = vm.requestValidator.ValidateRequest(ctx, requestBody, validationCtx)
			}
		case "/auth/register":
			// Extract fields from request body for registration validation
			if requestMap, ok := requestBody.(map[string]interface{}); ok {
				email, _ := requestMap["email"].(string)
				phone, _ := requestMap["phone"].(string)
				password, _ := requestMap["password"].(string)
				role, _ := requestMap["role"].(string)
				validationResult, validationErr = vm.requestValidator.ValidateRegistrationRequest(ctx, email, phone, password, role, validationCtx)
			} else {
				validationResult, validationErr = vm.requestValidator.ValidateRequest(ctx, requestBody, validationCtx)
			}
		case "/auth/otp/verify":
			// Extract fields from request body for OTP validation
			if requestMap, ok := requestBody.(map[string]interface{}); ok {
				phone, _ := requestMap["phone"].(string)
				code, _ := requestMap["code"].(string)
				userID, _ := requestMap["user_id"].(uint)
				validationResult, validationErr = vm.requestValidator.ValidateOTPRequest(ctx, phone, code, userID, validationCtx)
			} else {
				validationResult, validationErr = vm.requestValidator.ValidateRequest(ctx, requestBody, validationCtx)
			}
		default:
			// Use generic validation for other endpoints
			validationResult, validationErr = vm.requestValidator.ValidateRequest(ctx, requestBody, validationCtx)
		}
		
		if validationErr != nil {
			vm.handleValidationError(c, &domain.ValidationError{
				Code:     "VALIDATION_SERVICE_ERROR",
				Message:  "Internal validation service error",
				Severity: domain.SeverityError,
				Category: domain.CategoryField,
				Metadata: map[string]interface{}{"error": validationErr.Error()},
			}, validationCtx)
			return
		}
		
		// Handle validation failures
		if !validationResult.IsValid {
			vm.handleValidationFailures(c, validationResult, validationCtx)
			return
		}
		
		// Phase 5: Business rule validation (if enabled)
		if vm.config.EnableBusinessValidation {
			if err := vm.validateBusinessRules(ctx, requestBody, validationCtx, c); err != nil {
				vm.handleBusinessValidationError(c, err, validationCtx)
				return
			}
		}
		
		// Store validation context for downstream handlers
		c.Set("validation_context", validationCtx)
		c.Set("validation_result", validationResult)
		
		// Record metrics
		duration := time.Since(startTime)
		if vm.config.EnableMetrics {
			vm.metricsCollector.IncrementValidationCounter("success", validationCtx.Endpoint)
			vm.metricsCollector.RecordValidationDuration(duration, validationCtx.Endpoint)
		}
		
		// Log validation event
		if vm.config.LogValidationEvents {
			vm.logger.LogValidationEvent(ctx, ValidationEvent{
				RequestID:        validationCtx.RequestID,
				Endpoint:         validationCtx.Endpoint,
				Method:           validationCtx.Method,
				UserID:           validationCtx.UserID,
				IPAddress:        validationCtx.IPAddress,
				ValidationResult: validationResult,
				Duration:         duration,
				Timestamp:        time.Now(),
			})
		}
		
		c.Next()
	})
}

// buildValidationContext creates comprehensive validation context from Gin context
func (vm *ValidationMiddleware) buildValidationContext(c *gin.Context) *domain.ValidationContext {
	requestID := uuid.New().String()
	if existingID := c.GetHeader("X-Request-ID"); existingID != "" {
		requestID = existingID
	}
	
	ctx := &domain.ValidationContext{
		RequestID: requestID,
		Endpoint:  c.Request.URL.Path,
		Method:    c.Request.Method,
		IPAddress: c.ClientIP(),
		UserAgent: c.GetHeader("User-Agent"),
		Timestamp: time.Now(),
		Headers:   make(map[string]string),
	}
	
	// Extract headers (excluding sensitive ones)
	for key, values := range c.Request.Header {
		if len(values) > 0 && !vm.isSensitiveHeader(key) {
			ctx.Headers[key] = values[0]
		}
	}
	
	// Extract user context if authenticated
	if userID, exists := c.Get("user_id"); exists {
		if uid, ok := userID.(uint); ok {
			ctx.UserID = &uid
		}
	}
	
	if role, exists := c.Get("user_role"); exists {
		if r, ok := role.(string); ok {
			ctx.Role = r
		}
	}
	
	if sessionID, exists := c.Get("session_id"); exists {
		if sid, ok := sessionID.(string); ok {
			ctx.SessionID = sid
		}
	}
	
	// Set anonymous flag
	ctx.IsAnonymous = ctx.UserID == nil
	
	return ctx
}

// extractRequestBody safely extracts and validates request body
func (vm *ValidationMiddleware) extractRequestBody(c *gin.Context) (interface{}, error) {
	// Skip body extraction for GET, DELETE, HEAD methods
	if c.Request.Method == "GET" || c.Request.Method == "DELETE" || c.Request.Method == "HEAD" {
		return nil, nil
	}
	
	// Check content length
	if c.Request.ContentLength > vm.config.MaxRequestSize {
		return nil, fmt.Errorf("request body too large: %d bytes", c.Request.ContentLength)
	}
	
	// Read body with size limit
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, vm.config.MaxRequestSize))
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	
	// Restore body for downstream handlers
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
	
	// Parse JSON body if present
	if len(body) == 0 {
		return nil, nil
	}
	
	var requestData interface{}
	if err := json.Unmarshal(body, &requestData); err != nil {
		return nil, fmt.Errorf("invalid JSON format: %w", err)
	}
	
	return requestData, nil
}

// validateRateLimit checks rate limiting constraints
func (vm *ValidationMiddleware) validateRateLimit(ctx context.Context, validationCtx *domain.ValidationContext, c *gin.Context) error {
	// Build rate limit key based on IP and endpoint
	rateLimitKey := fmt.Sprintf("rate_limit:%s:%s", validationCtx.IPAddress, validationCtx.Endpoint)
	
	// Check rate limit (1 minute window, configurable limits per endpoint)
	limit := vm.getRateLimitForEndpoint(validationCtx.Endpoint)
	result, err := vm.rateLimitValidator.CheckRateLimit(ctx, rateLimitKey, limit, time.Minute)
	if err != nil {
		return fmt.Errorf("rate limit check failed: %w", err)
	}
	
	if !result.Allowed {
		// Record rate limit hit
		if vm.config.EnableMetrics {
			vm.metricsCollector.RecordRateLimitHit(validationCtx.Endpoint, validationCtx.IPAddress)
		}
		
		return fmt.Errorf("rate limit exceeded for %s", validationCtx.Endpoint)
	}
	
	// Increment counter for successful requests
	return vm.rateLimitValidator.IncrementCounter(ctx, rateLimitKey, time.Minute)
}

// validateSecurity performs security validation on request data
func (vm *ValidationMiddleware) validateSecurity(ctx context.Context, requestBody interface{}, validationCtx *domain.ValidationContext) (*domain.SecurityValidationResult, error) {
	if requestBody == nil {
		return &domain.SecurityValidationResult{ThreatLevel: domain.ThreatNone}, nil
	}
	
	// Convert request body to map for security scanning
	requestMap, ok := requestBody.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid request format for security validation")
	}
	
	// Build security constraints for scanning
	securityConstraints := []domain.SecurityConstraint{
		{
			XSSProtection:         true,
			SQLInjectionCheck:     true,
			ScriptInjectionCheck:  true,
			ThreatScanEnabled:     true,
			BlockedPatterns:       []string{"<script", "javascript:", "eval(", "alert("},
		},
	}
	
	// Perform threat scanning
	result, err := vm.securityValidator.ScanForThreats(ctx, requestMap, securityConstraints)
	if err != nil {
		return nil, fmt.Errorf("security validation failed: %w", err)
	}
	
	return result, nil
}

// validateBusinessRules validates business-specific rules based on endpoint
func (vm *ValidationMiddleware) validateBusinessRules(ctx context.Context, requestBody interface{}, validationCtx *domain.ValidationContext, c *gin.Context) error {
	if requestBody == nil {
		return nil
	}
	
	// Route-specific business validation
	switch {
	case strings.Contains(validationCtx.Endpoint, "/auth/register"):
		return vm.validateRegistrationBusinessRules(ctx, requestBody, validationCtx)
	case strings.Contains(validationCtx.Endpoint, "/auth/login"):
		return vm.validateLoginBusinessRules(ctx, requestBody, validationCtx)
	case strings.Contains(validationCtx.Endpoint, "/auth/otp"):
		return vm.validateOTPBusinessRules(ctx, requestBody, validationCtx)
	default:
		return nil
	}
}

// validateRegistrationBusinessRules validates registration-specific business rules
func (vm *ValidationMiddleware) validateRegistrationBusinessRules(ctx context.Context, requestBody interface{}, validationCtx *domain.ValidationContext) error {
	requestMap, ok := requestBody.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid registration request format")
	}
	
	email, _ := requestMap["email"].(string)
	phone, _ := requestMap["phone"].(string)
	password, _ := requestMap["password"].(string)
	role, _ := requestMap["role"].(string)
	
	result, err := vm.businessValidator.ValidateRegistrationRules(ctx, email, phone, password, role)
	if err != nil {
		return err
	}
	
	if !result.IsValid {
		return fmt.Errorf("registration business validation failed: %d errors", len(result.Errors))
	}
	
	return nil
}

// validateLoginBusinessRules validates login-specific business rules
func (vm *ValidationMiddleware) validateLoginBusinessRules(ctx context.Context, requestBody interface{}, validationCtx *domain.ValidationContext) error {
	requestMap, ok := requestBody.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid login request format")
	}
	
	email, _ := requestMap["email"].(string)
	password, _ := requestMap["password"].(string)
	
	result, err := vm.businessValidator.ValidateLoginRules(ctx, email, password, nil)
	if err != nil {
		return err
	}
	
	if !result.IsValid {
		return fmt.Errorf("login business validation failed: %d errors", len(result.Errors))
	}
	
	return nil
}

// validateOTPBusinessRules validates OTP-specific business rules
func (vm *ValidationMiddleware) validateOTPBusinessRules(ctx context.Context, requestBody interface{}, validationCtx *domain.ValidationContext) error {
	requestMap, ok := requestBody.(map[string]interface{})
	if !ok {
		return fmt.Errorf("invalid OTP request format")
	}
	
	phone, _ := requestMap["phone"].(string)
	code, _ := requestMap["code"].(string)
	
	var userID uint
	if userIDFloat, ok := requestMap["user_id"].(float64); ok {
		userID = uint(userIDFloat)
	}
	
	result, err := vm.businessValidator.ValidateOTPRules(ctx, phone, code, userID)
	if err != nil {
		return err
	}
	
	if !result.IsValid {
		return fmt.Errorf("OTP business validation failed: %d errors", len(result.Errors))
	}
	
	return nil
}

// Error handling methods

func (vm *ValidationMiddleware) handleRateLimitExceeded(c *gin.Context, err error, validationCtx *domain.ValidationContext) {
	// Get rate limit for this endpoint
	limit := vm.getRateLimitForEndpoint(validationCtx.Endpoint)
	
	// Set rate limit headers
	c.Header("X-RateLimit-Limit", fmt.Sprintf("%d", limit))
	c.Header("X-RateLimit-Remaining", "0")
	c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))
	c.Header("Retry-After", "60")
	
	// CB-182: In shadow mode, log but don't block
	if vm.config.ShadowMode {
		vm.logger.LogValidationError(c.Request.Context(), &domain.ValidationError{
			Code:     "RATE_LIMIT_EXCEEDED",
			Message:  "Rate limit exceeded (shadow mode)",
			Severity: domain.SeverityWarning,
			Category: domain.CategoryRateLimit,
			Metadata: map[string]interface{}{
				"shadow_mode": true,
				"retry_after": 60,
				"error":      err.Error(),
			},
		}, validationCtx)
		c.Next() // Continue processing in shadow mode
		return
	}
	
	vm.respondWithError(c, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", "Rate limit exceeded", map[string]interface{}{
		"retry_after": 60,
		"error":      err.Error(),
	}, validationCtx)
}

func (vm *ValidationMiddleware) handleSecurityViolation(c *gin.Context, err error, validationCtx *domain.ValidationContext) {
	if vm.config.EnableMetrics {
		vm.metricsCollector.RecordSecurityViolation("unknown", validationCtx.Endpoint)
	}
	
	// CB-182: In shadow mode, log but don't block
	if vm.config.ShadowMode {
		vm.logger.LogValidationError(c.Request.Context(), &domain.ValidationError{
			Code:     "SECURITY_VIOLATION",
			Message:  "Security violation detected (shadow mode)",
			Severity: domain.SeverityWarning,
			Category: domain.CategorySecurity,
			Metadata: map[string]interface{}{
				"shadow_mode": true,
				"error": "Request contains potentially malicious content",
			},
		}, validationCtx)
		c.Next() // Continue processing in shadow mode
		return
	}
	
	vm.respondWithError(c, http.StatusBadRequest, "SECURITY_VIOLATION", "Security violation detected", map[string]interface{}{
		"error": "Request contains potentially malicious content",
	}, validationCtx)
}

func (vm *ValidationMiddleware) handleSecurityThreat(c *gin.Context, result *domain.SecurityValidationResult, validationCtx *domain.ValidationContext) {
	threatType := "unknown"
	if len(result.ThreatTypes) > 0 {
		threatType = string(result.ThreatTypes[0])
	}
	
	if vm.config.EnableMetrics {
		vm.metricsCollector.RecordSecurityViolation(threatType, validationCtx.Endpoint)
	}
	
	statusCode := http.StatusBadRequest
	if result.ThreatLevel == domain.ThreatCritical {
		statusCode = http.StatusForbidden
	}
	
	vm.respondWithError(c, statusCode, "SECURITY_THREAT_DETECTED", "Security threat detected", map[string]interface{}{
		"threat_level": result.ThreatLevel,
		"threat_types": result.ThreatTypes,
	}, validationCtx)
}

func (vm *ValidationMiddleware) handleValidationError(c *gin.Context, validationError *domain.ValidationError, validationCtx *domain.ValidationContext) {
	vm.logger.LogValidationError(c.Request.Context(), validationError, validationCtx)
	
	vm.respondWithError(c, http.StatusBadRequest, validationError.Code, validationError.Message, map[string]interface{}{
		"field":      validationError.Field,
		"constraint": validationError.Constraint,
		"metadata":   validationError.Metadata,
	}, validationCtx)
}

func (vm *ValidationMiddleware) handleValidationFailures(c *gin.Context, result *domain.ValidationResult, validationCtx *domain.ValidationContext) {
	errors := make([]map[string]interface{}, len(result.Errors))
	
	// Determine the appropriate HTTP status code based on error categories
	statusCode := http.StatusBadRequest // Default to 400
	primaryErrorCode := "VALIDATION_FAILED"
	primaryErrorMessage := "Request validation failed"
	hasSecurity := false
	
	// Check for specific error categories to determine status code and message
	for i, err := range result.Errors {
		errors[i] = map[string]interface{}{
			"code":       err.Code,
			"field":      err.Field,
			"message":    err.Message,
			"severity":   err.Severity,
			"constraint": err.Constraint,
		}
		
		// Prioritize more severe error types
		switch err.Category {
		case domain.CategoryRateLimit:
			if err.Code == "RATE_LIMIT_EXCEEDED" {
				statusCode = http.StatusTooManyRequests // 429
				primaryErrorCode = "RATE_LIMIT_EXCEEDED"
				primaryErrorMessage = err.Message // Use the specific error message
			}
		case domain.CategorySecurity:
			hasSecurity = true
			if statusCode == http.StatusBadRequest { // Only override if not already set to rate limit
				statusCode = http.StatusForbidden // 403
				primaryErrorCode = "SECURITY_VIOLATION"
				primaryErrorMessage = err.Message // Use the specific error message
			}
		}
	}
	
	// Set security headers if this is a security-related error
	if hasSecurity || (result.SecurityResult != nil && len(result.SecurityResult.Violations) > 0) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("X-Frame-Options", "DENY")
		c.Header("X-XSS-Protection", "1; mode=block")
	}
	
	details := map[string]interface{}{
		"errors":        errors,
		"rules_applied": result.RulesApplied,
	}
	
	// Include security violations if present
	if result.SecurityResult != nil && len(result.SecurityResult.Violations) > 0 {
		securityViolations := make([]map[string]interface{}, len(result.SecurityResult.Violations))
		for i, violation := range result.SecurityResult.Violations {
			securityViolations[i] = map[string]interface{}{
				"type":        violation.Type,
				"severity":    violation.Severity,
				"description": violation.Description,
				"field_name":  violation.FieldName,
				"pattern":     violation.Pattern,
				"action":      violation.Action,
				"blocked":     violation.Blocked,
				"risk_score":  violation.RiskScore,
				"confidence":  violation.Confidence,
			}
		}
		details["security_violations"] = securityViolations
		details["threat_level"] = result.SecurityResult.ThreatLevel
		details["threat_types"] = result.SecurityResult.ThreatTypes
	}
	
	// CB-182: In shadow mode, log but don't block
	if vm.config.ShadowMode {
		// Log all validation errors for analysis
		for _, err := range result.Errors {
			vm.logger.LogValidationError(c.Request.Context(), &err, validationCtx)
		}
		
		// Add shadow mode header for debugging
		c.Header("X-Validation-Shadow-Mode", "true")
		c.Header("X-Validation-Errors", fmt.Sprintf("%d", len(result.Errors)))
		
		c.Next() // Continue processing in shadow mode
		return
	}
	
	vm.respondWithError(c, statusCode, primaryErrorCode, primaryErrorMessage, details, validationCtx)
}

func (vm *ValidationMiddleware) handleBusinessValidationError(c *gin.Context, err error, validationCtx *domain.ValidationContext) {
	vm.respondWithError(c, http.StatusBadRequest, "BUSINESS_VALIDATION_FAILED", "Business rule validation failed", map[string]interface{}{
		"error": err.Error(),
	}, validationCtx)
}

// respondWithError sends standardized error response
func (vm *ValidationMiddleware) respondWithError(c *gin.Context, statusCode int, code, message string, details map[string]interface{}, validationCtx *domain.ValidationContext) {
	if vm.config.EnableMetrics {
		vm.metricsCollector.IncrementValidationCounter("error", validationCtx.Endpoint)
	}
	
	response := map[string]interface{}{
		"status":     "error",
		"code":       code,
		"message":    message,
		"error":      message, // Add error field for test compatibility
		"request_id": validationCtx.RequestID,
		"timestamp":  time.Now().Format(time.RFC3339),
	}
	
	if details != nil {
		response["details"] = details
	}
	
	c.JSON(statusCode, response)
	c.Abort()
}

// Utility methods

func (vm *ValidationMiddleware) shouldSkipValidation(path string) bool {
	for _, skipPath := range vm.config.SkipValidationPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}
	return false
}

func (vm *ValidationMiddleware) isSensitiveHeader(headerName string) bool {
	sensitiveHeaders := []string{"authorization", "cookie", "x-api-key", "x-auth-token"}
	lowerName := strings.ToLower(headerName)
	for _, sensitive := range sensitiveHeaders {
		if lowerName == sensitive {
			return true
		}
	}
	return false
}

func (vm *ValidationMiddleware) getRateLimitForEndpoint(endpoint string) int {
	// Define rate limits per endpoint
	rateLimits := map[string]int{
		"/auth/register": 5,   // 5 registrations per minute
		"/auth/login":    10,  // 10 login attempts per minute
		"/auth/otp":      3,   // 3 OTP requests per minute
		"/auth/refresh":  20,  // 20 token refreshes per minute
	}
	
	for path, limit := range rateLimits {
		if strings.Contains(endpoint, path) {
			return limit
		}
	}
	
	return 60 // Default rate limit
}

// DefaultValidationConfig returns default validation configuration
func DefaultValidationConfig() ValidationConfig {
	return ValidationConfig{
		EnableSecurityValidation: true,
		EnableBusinessValidation: true,
		EnableRateLimiting:      true,
		MaxRequestSize:          1024 * 1024, // 1MB
		ValidationTimeout:       5 * time.Second,
		SkipValidationPaths:     []string{"/health", "/metrics", "/external/health"},
		LogValidationEvents:     true,
		EnableMetrics:          true,
	}
}