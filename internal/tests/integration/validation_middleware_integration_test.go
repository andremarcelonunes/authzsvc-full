package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/http/handlers"
	httpx "github.com/you/authzsvc/internal/http"
	"github.com/you/authzsvc/internal/http/middleware"
	"github.com/you/authzsvc/internal/mocks"
)

func TestValidationMiddlewareIntegration(t *testing.T) {
	// Setup test environment
	gin.SetMode(gin.TestMode)
	
	// Create mock dependencies
	deps := createMockDependencies(t)
	config := createTestMiddlewareConfig()
	
	// Create test router with validation middleware
	router := createTestRouterWithValidation(t, deps, config)
	
	tests := []struct {
		name           string
		method         string
		path           string
		headers        map[string]string
		body           interface{}
		setupMocks     func(*MockDependencies)
		expectedStatus int
		expectedBody   map[string]interface{}
		checkResponse  func(t *testing.T, response *httptest.ResponseRecorder)
	}{
		{
			name:   "Valid registration request passes validation",
			method: "POST",
			path:   "/auth/register",
			headers: map[string]string{
				"Content-Type": "application/json",
				"User-Agent":   "TestClient/1.0",
			},
			body: map[string]interface{}{
				"email":    "test@example.com",
				"phone":    "+1234567890",
				"password": "SecurePassword123!",
				"role":     "user",
			},
			setupMocks: func(deps *MockDependencies) {
				// Setup successful validation
				deps.RequestValidator.ValidateRequestFunc = func(ctx context.Context, request interface{}, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid:      true,
						Passed:       true,
						Errors:       []domain.ValidationError{},
						RulesApplied: 5,
					}, nil
				}
				
				deps.SecurityValidator.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatNone,
						ThreatTypes: []domain.ThreatType{},
					}, nil
				}
				
				deps.BusinessValidator.ValidateRegistrationRulesFunc = func(ctx context.Context, email, phone, password, role string) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid: true,
						Passed:  true,
					}, nil
				}
				
				deps.RateLimitValidator.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{
						Allowed:      true,
						Limit:        5,
						CurrentCount: 1,
						Remaining:    4,
						ResetTime:    time.Now().Add(time.Minute),
					}, nil
				}
			},
			expectedStatus: http.StatusOK,
			checkResponse: func(t *testing.T, response *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, response.Code)
				// Check that validation context was set
				assert.Contains(t, response.Body.String(), "validation passed")
			},
		},
		{
			name:   "XSS attack in email field is blocked",
			method: "POST",
			path:   "/auth/register",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			body: map[string]interface{}{
				"email":    "test@example.com<script>alert('xss')</script>",
				"phone":    "+1234567890",
				"password": "SecurePassword123!",
				"role":     "user",
			},
			setupMocks: func(deps *MockDependencies) {
				deps.SecurityValidator.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatHigh,
						ThreatTypes: []domain.ThreatType{domain.ThreatXSS},
						Violations: []domain.SecurityViolation{
							{
								Type:        domain.ThreatXSS,
								Severity:    domain.SeverityError,
								Description: "XSS attempt detected in email field",
								FieldName:   "email",
								Blocked:     true,
							},
						},
					}, nil
				}
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response *httptest.ResponseRecorder) {
				var responseBody map[string]interface{}
				err := json.Unmarshal(response.Body.Bytes(), &responseBody)
				require.NoError(t, err)
				
				assert.Equal(t, "error", responseBody["status"])
				assert.Equal(t, "SECURITY_THREAT_DETECTED", responseBody["code"])
				
				// Check threat_types in details section
				details, ok := responseBody["details"].(map[string]interface{})
				require.True(t, ok, "details should be present in response")
				threatTypes, ok := details["threat_types"].([]interface{})
				require.True(t, ok, "threat_types should be present in details")
				assert.Contains(t, threatTypes, "xss")
			},
		},
		{
			name:   "Rate limit exceeded is handled properly",
			method: "POST",
			path:   "/auth/login",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			body: map[string]interface{}{
				"email":    "test@example.com",
				"password": "password123",
			},
			setupMocks: func(deps *MockDependencies) {
				deps.RateLimitValidator.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{
						Allowed:      false,
						Limit:        10,
						CurrentCount: 11,
						Remaining:    0,
						ResetTime:    time.Now().Add(time.Minute),
						RetryAfter:   time.Minute,
					}, nil
				}
			},
			expectedStatus: http.StatusTooManyRequests,
			checkResponse: func(t *testing.T, response *httptest.ResponseRecorder) {
				var responseBody map[string]interface{}
				err := json.Unmarshal(response.Body.Bytes(), &responseBody)
				require.NoError(t, err)
				
				assert.Equal(t, "error", responseBody["status"])
				assert.Equal(t, "RATE_LIMIT_EXCEEDED", responseBody["code"])
				assert.Contains(t, response.Header().Get("X-RateLimit-Limit"), "10")
			},
		},
		{
			name:   "Invalid Content-Type is rejected",
			method: "POST",
			path:   "/auth/register",
			headers: map[string]string{
				"Content-Type": "text/xml",
			},
			body: `<?xml version="1.0"?><request></request>`,
			setupMocks: func(deps *MockDependencies) {
				// No mocks needed - security middleware will reject before validation
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response *httptest.ResponseRecorder) {
				var responseBody map[string]interface{}
				err := json.Unmarshal(response.Body.Bytes(), &responseBody)
				require.NoError(t, err)
				
				assert.Equal(t, "error", responseBody["status"])
				assert.Equal(t, "INVALID_CONTENT_TYPE", responseBody["code"])
			},
		},
		{
			name:   "Request too large is rejected",
			method: "POST",
			path:   "/auth/register",
			headers: map[string]string{
				"Content-Type":   "application/json",
				"Content-Length": "2097152", // 2MB
			},
			body: map[string]interface{}{
				"email":    "test@example.com",
				"password": string(make([]byte, 2*1024*1024)), // 2MB password
			},
			setupMocks: func(deps *MockDependencies) {
				// No mocks needed - security middleware will reject
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response *httptest.ResponseRecorder) {
				var responseBody map[string]interface{}
				err := json.Unmarshal(response.Body.Bytes(), &responseBody)
				require.NoError(t, err)
				
				assert.Equal(t, "error", responseBody["status"])
				assert.Equal(t, "REQUEST_TOO_LARGE", responseBody["code"])
			},
		},
		{
			name:   "Multiple validation errors are aggregated",
			method: "POST",
			path:   "/auth/register",
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			body: map[string]interface{}{
				"email":    "invalid-email",
				"phone":    "123", // Too short
				"password": "weak", // Too weak
			},
			setupMocks: func(deps *MockDependencies) {
				// Use ValidateRegistrationRequest for /auth/register endpoint
				deps.RequestValidator.ValidateRegistrationRequestFunc = func(ctx context.Context, email, phone, password, role string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid: false,
						Passed:  false,
						Errors: []domain.ValidationError{
							{
								Code:     "INVALID_EMAIL_FORMAT",
								Field:    "email",
								Message:  "Invalid email format",
								Severity: domain.SeverityError,
								Category: domain.CategoryField,
							},
							{
								Code:     "PHONE_TOO_SHORT",
								Field:    "phone",
								Message:  "Phone number too short",
								Severity: domain.SeverityError,
								Category: domain.CategoryField,
							},
							{
								Code:     "PASSWORD_TOO_WEAK",
								Field:    "password",
								Message:  "Password does not meet complexity requirements",
								Severity: domain.SeverityError,
								Category: domain.CategoryField,
							},
						},
						RulesApplied: 3,
					}, nil
				}
				
				deps.SecurityValidator.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatNone,
					}, nil
				}
				
				// Ensure rate limiting passes for this test
				deps.RateLimitValidator.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{
						Allowed:      true,
						Limit:        5,
						CurrentCount: 1,
						Remaining:    4,
						ResetTime:    time.Now().Add(time.Minute),
					}, nil
				}
				
				deps.RateLimitValidator.IncrementCounterFunc = func(ctx context.Context, key string, window time.Duration) error {
					return nil
				}
			},
			expectedStatus: http.StatusBadRequest,
			checkResponse: func(t *testing.T, response *httptest.ResponseRecorder) {
				var responseBody map[string]interface{}
				err := json.Unmarshal(response.Body.Bytes(), &responseBody)
				require.NoError(t, err)
				
				assert.Equal(t, "error", responseBody["status"])
				assert.Equal(t, "VALIDATION_FAILED", responseBody["code"])
				
				// Check errors in details section
				details, ok := responseBody["details"].(map[string]interface{})
				require.True(t, ok, "details should be present in response")
				
				errors, ok := details["errors"].([]interface{})
				require.True(t, ok, "errors should be present in details")
				assert.Len(t, errors, 3)
				
				// Check each error
				errorCodes := make([]string, len(errors))
				for i, errInterface := range errors {
					err, ok := errInterface.(map[string]interface{})
					require.True(t, ok)
					errorCodes[i] = err["code"].(string)
				}
				
				assert.Contains(t, errorCodes, "INVALID_EMAIL_FORMAT")
				assert.Contains(t, errorCodes, "PHONE_TOO_SHORT")
				assert.Contains(t, errorCodes, "PASSWORD_TOO_WEAK")
			},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks for this test
			if tt.setupMocks != nil {
				tt.setupMocks(deps)
			}
			
			// Create request
			var bodyReader *bytes.Reader
			if tt.body != nil {
				if bodyBytes, ok := tt.body.(string); ok {
					bodyReader = bytes.NewReader([]byte(bodyBytes))
				} else {
					bodyJSON, err := json.Marshal(tt.body)
					require.NoError(t, err)
					bodyReader = bytes.NewReader(bodyJSON)
				}
			} else {
				bodyReader = bytes.NewReader([]byte{})
			}
			
			req, err := http.NewRequest(tt.method, tt.path, bodyReader)
			require.NoError(t, err)
			
			// Add headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			
			// Execute request
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			
			// Check status code
			assert.Equal(t, tt.expectedStatus, w.Code, "Response body: %s", w.Body.String())
			
			// Additional response checks
			if tt.checkResponse != nil {
				tt.checkResponse(t, w)
			}
		})
	}
}

// Mock dependencies for testing
type MockDependencies struct {
	RequestValidator         *mocks.MockRequestValidationService
	SecurityValidator        *mocks.MockSecurityValidationService
	BusinessValidator        *mocks.MockBusinessValidationService
	RateLimitValidator       *mocks.MockRateLimitValidationService
	RedisClient              *redis.Client
	ValidationLogger         *MockLogger
	SecurityLogger           *MockSecurityLogger  
	ValidationErrorLogger    *MockValidationErrorLogger
	MetricsCollector         *MockMetricsCollector
}

func createMockDependencies(t *testing.T) *MockDependencies {
	// Create Redis client for testing (use miniredis for unit tests)
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   15, // Use test database
	})
	
	return &MockDependencies{
		RequestValidator:      mocks.NewMockRequestValidationService(),
		SecurityValidator:     mocks.NewMockSecurityValidationService(),
		BusinessValidator:     mocks.NewMockBusinessValidationService(),
		RateLimitValidator:    mocks.NewMockRateLimitValidationService(),
		RedisClient:           redisClient,
		ValidationLogger:      &MockLogger{},
		SecurityLogger:        &MockSecurityLogger{},
		ValidationErrorLogger: &MockValidationErrorLogger{},
		MetricsCollector:      &MockMetricsCollector{},
	}
}

func createTestMiddlewareConfig() httpx.MiddlewareConfig {
	config := httpx.DefaultMiddlewareConfig()
	
	// Enable all features for testing
	config.EnableValidationMiddleware = true
	config.EnableSecurityMiddleware = true
	config.EnableRateLimitMiddleware = true
	config.EnableEnhancedErrorHandling = true
	
	// Configure for testing
	config.ValidationConfig.ValidationTimeout = 5 * time.Second
	config.ValidationConfig.LogValidationEvents = true
	config.SecurityConfig.MaxRequestSize = 1024 * 1024 // 1MB
	config.RateLimitConfig.RedisTimeout = 2 * time.Second
	config.ErrorHandlerConfig.IncludeStackTrace = true
	
	return config
}

func createTestRouterWithValidation(t *testing.T, deps *MockDependencies, config httpx.MiddlewareConfig) *gin.Engine {
	// Create middleware dependencies
	_ = httpx.MiddlewareDependencies{
		RequestValidator:              deps.RequestValidator,
		SecurityValidator:             deps.SecurityValidator,
		BusinessValidator:             deps.BusinessValidator,
		RateLimitValidator:           deps.RateLimitValidator,
		RedisClient:                  deps.RedisClient,
		ValidationLogger:             deps.ValidationLogger,
		SecurityLogger:               deps.SecurityLogger,
		RateLimitLogger:              deps.ValidationLogger,
		ValidationErrorLogger:        deps.ValidationErrorLogger,
		ValidationMetricsCollector:   deps.MetricsCollector,
		RateLimitMetricsCollector:    deps.MetricsCollector,
		ErrorMetricsCollector:        deps.MetricsCollector,
	}
	
	// Create test router
	router := gin.New()
	router.Use(gin.Recovery())
	
	// Add security middleware
	if config.EnableSecurityMiddleware {
		securityMW := middleware.NewSecurityMiddleware(config.SecurityConfig, deps.SecurityLogger)
		router.Use(securityMW.AddSecurityHeaders())
	}
	
	// Create auth group with validation middleware
	auth := router.Group("/auth")
	
	if config.EnableValidationMiddleware {
		validationMW := middleware.NewValidationMiddleware(
			deps.RequestValidator,
			deps.SecurityValidator,
			deps.BusinessValidator,
			deps.RateLimitValidator,
			deps.MetricsCollector,
			deps.ValidationLogger,
			config.ValidationConfig,
		)
		
		securityMW := middleware.NewSecurityMiddleware(config.SecurityConfig, deps.SecurityLogger)
		
		auth.Use(
			securityMW.ValidateContentType(),
			securityMW.LimitRequestSize(),
			securityMW.ValidateCharacterEncoding(),
			securityMW.ValidateHeaders(),
			validationMW.ValidateRequest(),
		)
	}
	
	// Add rate limiting
	if config.EnableRateLimitMiddleware {
		rateLimitMW := middleware.NewRateLimitMiddleware(
			deps.RedisClient,
			deps.RateLimitValidator,
			config.RateLimitConfig,
			deps.ValidationLogger,
			deps.MetricsCollector,
		)
		
		auth.POST("/register", rateLimitMW.RateLimit("/auth/register", 5, time.Minute), func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "validation passed", "endpoint": "register"})
		})
		
		auth.POST("/login", rateLimitMW.RateLimit("/auth/login", 10, time.Minute), func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "validation passed", "endpoint": "login"})
		})
	} else {
		auth.POST("/register", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "validation passed", "endpoint": "register"})
		})
		
		auth.POST("/login", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "validation passed", "endpoint": "login"})
		})
	}
	
	return router
}

// Mock implementations for testing

type MockLogger struct{}

// Implement middleware.ValidationLogger interface
func (ml *MockLogger) LogValidationEvent(ctx context.Context, event middleware.ValidationEvent) {}
func (ml *MockLogger) LogSecurityViolation(ctx context.Context, violation *domain.SecurityViolation) {}
func (ml *MockLogger) LogValidationError(ctx context.Context, err *domain.ValidationError, requestCtx *domain.ValidationContext) {}

// Implement middleware.RateLimitLogger interface
func (ml *MockLogger) LogRateLimitEvent(event middleware.RateLimitEvent) {}
func (ml *MockLogger) LogRateLimitViolation(violation middleware.RateLimitViolation) {}
func (ml *MockLogger) LogRateLimitError(error middleware.RateLimitError) {}

type MockSecurityLogger struct{}

// Implement middleware.SecurityLogger interface
func (msl *MockSecurityLogger) LogSecurityEvent(event middleware.SecurityEvent) {}
func (msl *MockSecurityLogger) LogSecurityViolation(violation middleware.SecurityViolation) {}

type MockValidationErrorLogger struct{}

// Implement handlers.ValidationErrorLogger interface  
func (mvel *MockValidationErrorLogger) LogValidationError(ctx context.Context, event handlers.ValidationErrorEvent) {}
func (mvel *MockValidationErrorLogger) LogSecurityViolation(ctx context.Context, violation handlers.SecurityViolationEvent) {}
func (mvel *MockValidationErrorLogger) LogErrorHandlingMetrics(ctx context.Context, metrics handlers.ErrorHandlingMetrics) {}

type MockMetricsCollector struct{}

func (mmc *MockMetricsCollector) IncrementValidationCounter(status string, endpoint string) {}
func (mmc *MockMetricsCollector) RecordValidationDuration(duration time.Duration, endpoint string) {}
func (mmc *MockMetricsCollector) RecordSecurityViolation(violationType string, endpoint string) {}
func (mmc *MockMetricsCollector) RecordRateLimitHit(endpoint string, clientID string) {}
func (mmc *MockMetricsCollector) IncrementRateLimitCounter(endpoint string, status string) {}
func (mmc *MockMetricsCollector) RecordRateLimitLatency(duration time.Duration) {}
func (mmc *MockMetricsCollector) RecordActiveRateLimits(count int) {}
func (mmc *MockMetricsCollector) RecordRateLimitViolation(endpoint string, clientType string) {}
func (mmc *MockMetricsCollector) IncrementErrorCounter(errorType string, severity string) {}
func (mmc *MockMetricsCollector) RecordErrorHandlingLatency(duration time.Duration) {}
func (mmc *MockMetricsCollector) RecordSecurityViolationRate(violationType string) {}
func (mmc *MockMetricsCollector) RecordUserErrorFrequency(userID *uint, errorType string) {}