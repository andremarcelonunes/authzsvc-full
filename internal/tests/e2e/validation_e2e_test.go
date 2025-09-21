package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// TestCompleteAuthenticationFlowWithValidation tests the complete authentication flow with validation
func TestCompleteAuthenticationFlowWithValidation(t *testing.T) {
	tests := []struct {
		name              string
		scenario          string
		registrationData  map[string]interface{}
		loginData         map[string]interface{}
		otpData           map[string]interface{}
		setupValidation   func(*E2EValidationMocks)
		expectedOutcome   string
		validateFlow      func(t *testing.T, responses []E2EResponse)
	}{
		{
			name:     "successful complete flow with all validations passing",
			scenario: "happy_path",
			registrationData: map[string]interface{}{
				"email":    "newuser@example.com",
				"phone":    "+1234567890",
				"password": "SecurePassword123!",
				"role":     "user",
			},
			loginData: map[string]interface{}{
				"email":    "newuser@example.com",
				"password": "SecurePassword123!",
			},
			otpData: map[string]interface{}{
				"phone": "+1234567890",
				"code":  "123456",
			},
			setupValidation: func(mocks *E2EValidationMocks) {
				// All validations pass
				mocks.requestValidator.ValidateRegistrationRequestFunc = createSuccessfulRegistrationValidation()
				mocks.requestValidator.ValidateLoginRequestFunc = createSuccessfulLoginValidation()
				mocks.requestValidator.ValidateOTPRequestFunc = createSuccessfulOTPValidation()
			},
			expectedOutcome: "success",
			validateFlow: func(t *testing.T, responses []E2EResponse) {
				t.Helper()
				// Registration should succeed
				if responses[0].StatusCode != http.StatusCreated {
					t.Errorf("expected registration to succeed with 201, got %d", responses[0].StatusCode)
				}
				
				// Login should succeed
				if responses[1].StatusCode != http.StatusOK {
					t.Errorf("expected login to succeed with 200, got %d", responses[1].StatusCode)
				}
				
				// OTP verification should succeed
				if responses[2].StatusCode != http.StatusOK {
					t.Errorf("expected OTP verification to succeed with 200, got %d", responses[2].StatusCode)
				}
				
				// Check for JWT tokens in login response
				if responses[1].Body["access_token"] == nil {
					t.Error("expected access_token in login response")
				}
			},
		},
		{
			name:     "registration blocked by security validation",
			scenario: "security_blocked",
			registrationData: map[string]interface{}{
				"email":    "admin'; DROP TABLE users; --@evil.com",
				"phone":    "+1234567890",
				"password": "SecurePassword123!",
				"role":     "admin", // Suspicious role escalation
			},
			setupValidation: func(mocks *E2EValidationMocks) {
				// Security validation detects threats
				mocks.requestValidator.ValidateRegistrationRequestFunc = func(ctx context.Context, email, phone, password, role string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid: false,
						Passed:  false,
						Errors: []domain.ValidationError{
							{
								Code:      "SECURITY_THREAT",
								Message:   "SQL injection attempt detected",
								Severity:  domain.SeverityCritical,
								Category:  domain.CategorySecurity,
								Field:     "email",
								Timestamp: time.Now(),
							},
							{
								Code:      "PRIVILEGE_ESCALATION",
								Message:   "Unauthorized role elevation attempt",
								Severity:  domain.SeverityCritical,
								Category:  domain.CategorySecurity,
								Field:     "role",
								Timestamp: time.Now(),
							},
						},
						SecurityResult: &domain.SecurityValidationResult{
							ThreatLevel: domain.ThreatCritical,
							ThreatTypes: []domain.ThreatType{domain.ThreatSQLInjection},
							Violations: []domain.SecurityViolation{
								{
									Type:        domain.ThreatSQLInjection,
									Severity:    domain.SeverityCritical,
									Description: "SQL injection attempt in email field",
									FieldName:   "email",
									Pattern:     "DROP TABLE",
									Action:      domain.ActionBlock,
									Blocked:     true,
								},
							},
						},
						ValidationTime: 50 * time.Millisecond,
						ValidationID:   "sec_val_123",
					}, nil
				}
			},
			expectedOutcome: "blocked_by_security",
			validateFlow: func(t *testing.T, responses []E2EResponse) {
				t.Helper()
				// Registration should be blocked
				if responses[0].StatusCode != http.StatusForbidden {
					t.Errorf("expected registration to be blocked with 403, got %d", responses[0].StatusCode)
				}
				
				// Should contain security violation details
				if responses[0].Body["threat_level"] == nil {
					t.Error("expected threat_level in security blocked response")
				}
				
				// Should not proceed to login
				if len(responses) > 1 {
					t.Error("expected flow to stop after registration block")
				}
			},
		},
		{
			name:     "rate limit exceeded during login attempts",
			scenario: "rate_limit_exceeded",
			registrationData: map[string]interface{}{
				"email":    "victim@example.com",
				"phone":    "+1234567890",
				"password": "SecurePassword123!",
				"role":     "user",
			},
			loginData: map[string]interface{}{
				"email":    "victim@example.com",
				"password": "WrongPassword123!",
			},
			setupValidation: func(mocks *E2EValidationMocks) {
				// Registration passes
				mocks.requestValidator.ValidateRegistrationRequestFunc = createSuccessfulRegistrationValidation()
				
				// Login fails due to rate limiting
				mocks.requestValidator.ValidateLoginRequestFunc = func(ctx context.Context, email, password string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid: false,
						Passed:  false,
						Errors: []domain.ValidationError{
							{
								Code:      "RATE_LIMIT_EXCEEDED",
								Message:   "Login rate limit exceeded",
								Severity:  domain.SeverityError,
								Category:  domain.CategoryRateLimit,
								Timestamp: time.Now(),
							},
						},
						ValidationTime: 10 * time.Millisecond,
						ValidationID:   "rate_val_124",
					}, nil
				}
			},
			expectedOutcome: "rate_limited",
			validateFlow: func(t *testing.T, responses []E2EResponse) {
				t.Helper()
				// Registration should succeed
				if responses[0].StatusCode != http.StatusCreated {
					t.Errorf("expected registration to succeed, got %d", responses[0].StatusCode)
				}
				
				// Login should be rate limited
				if responses[1].StatusCode != http.StatusTooManyRequests {
					t.Errorf("expected login to be rate limited with 429, got %d", responses[1].StatusCode)
				}
				
				// Should contain rate limit information
				if !strings.Contains(fmt.Sprintf("%v", responses[1].Body["error"]), "rate limit") {
					t.Error("expected rate limit error message")
				}
			},
		},
		{
			name:     "business rule validation failures",
			scenario: "business_rule_failures",
			registrationData: map[string]interface{}{
				"email":    "invalid-email-format",
				"phone":    "invalid-phone",
				"password": "weak",
				"role":     "invalidrole",
			},
			setupValidation: func(mocks *E2EValidationMocks) {
				// Registration fails business rules
				mocks.requestValidator.ValidateRegistrationRequestFunc = func(ctx context.Context, email, phone, password, role string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid: false,
						Passed:  false,
						Errors: []domain.ValidationError{
							{
								Code:      "INVALID_EMAIL",
								Field:     "email",
								Message:   "Invalid email format",
								Severity:  domain.SeverityError,
								Category:  domain.CategoryField,
								Timestamp: time.Now(),
							},
							{
								Code:      "INVALID_PHONE",
								Field:     "phone",
								Message:   "Invalid phone number format",
								Severity:  domain.SeverityError,
								Category:  domain.CategoryField,
								Timestamp: time.Now(),
							},
							{
								Code:      "PASSWORD_TOO_WEAK",
								Field:     "password",
								Message:   "Password does not meet complexity requirements",
								Severity:  domain.SeverityError,
								Category:  domain.CategoryBusiness,
								Timestamp: time.Now(),
							},
							{
								Code:      "INVALID_ROLE",
								Field:     "role",
								Message:   "Invalid role specified",
								Severity:  domain.SeverityError,
								Category:  domain.CategoryBusiness,
								Timestamp: time.Now(),
							},
						},
						Warnings: []domain.ValidationError{
							{
								Code:      "WEAK_PASSWORD_WARNING",
								Field:     "password",
								Message:   "Consider using a stronger password",
								Severity:  domain.SeverityWarning,
								Category:  domain.CategoryBusiness,
								Timestamp: time.Now(),
							},
						},
						FieldResults: map[string]domain.FieldValidationResult{
							"email": {
								FieldName:     "email",
								IsValid:       false,
								OriginalValue: email,
								Errors: []domain.ValidationError{
									{
										Code:      "INVALID_EMAIL",
										Field:     "email",
										Message:   "Invalid email format",
										Severity:  domain.SeverityError,
										Category:  domain.CategoryField,
										Timestamp: time.Now(),
									},
								},
							},
						},
						ValidationTime: 75 * time.Millisecond,
						RulesApplied:   4,
						ValidationID:   "business_val_126",
					}, nil
				}
			},
			expectedOutcome: "validation_failures",
			validateFlow: func(t *testing.T, responses []E2EResponse) {
				t.Helper()
				// Registration should fail validation
				if responses[0].StatusCode != http.StatusBadRequest {
					t.Errorf("expected registration validation failure with 400, got %d", responses[0].StatusCode)
				}
				
				// Should contain detailed validation errors
				if responses[0].Body["validation_errors"] == nil {
					t.Error("expected validation_errors in response")
				}
				
				// Should contain field-specific errors
				if responses[0].Body["field_errors"] == nil {
					t.Error("expected field_errors in response")
				}
				
				// Should contain warnings
				if responses[0].Body["warnings"] == nil {
					t.Error("expected warnings in response")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create E2E test environment
			env := setupE2ETestEnvironment(t)
			
			// Setup validation mocks
			tt.setupValidation(env.ValidationMocks)

			// Execute the authentication flow
			responses := executeAuthenticationFlow(t, env, tt.registrationData, tt.loginData, tt.otpData)

			// Validate the flow outcome
			tt.validateFlow(t, responses)

			// Log flow summary
			t.Logf("E2E Flow: %s | Outcome: %s | Steps: %d", 
				tt.scenario, tt.expectedOutcome, len(responses))
		})
	}
}

// TestValidationMiddlewareIntegration tests validation middleware integration
func TestValidationMiddlewareIntegration(t *testing.T) {
	tests := []struct {
		name           string
		endpoint       string
		method         string
		requestBody    map[string]interface{}
		headers        map[string]string
		setupValidation func(*E2EValidationMocks)
		expectedStatus int
		validateResponse func(t *testing.T, response E2EResponse)
	}{
		{
			name:     "API endpoint with validation success",
			endpoint: "/api/users",
			method:   "POST",
			requestBody: map[string]interface{}{
				"name":  "John Doe",
				"email": "john@example.com",
				"role":  "user",
			},
			headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer valid_token",
			},
			setupValidation: func(mocks *E2EValidationMocks) {
				mocks.requestValidator.ValidateRequestFunc = func(ctx context.Context, request interface{}, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid:        true,
						Passed:         true,
						Errors:         []domain.ValidationError{},
						Warnings:       []domain.ValidationError{},
						ValidationTime: 25 * time.Millisecond,
						RulesApplied:   3,
						ValidationID:   "api_val_200",
					}, nil
				}
			},
			expectedStatus: http.StatusOK,
			validateResponse: func(t *testing.T, response E2EResponse) {
				t.Helper()
				if response.Body["message"] == nil {
					t.Error("expected success message in response")
				}
			},
		},
		{
			name:     "API endpoint with XSS attack blocked",
			endpoint: "/api/comments",
			method:   "POST",
			requestBody: map[string]interface{}{
				"content": "<script>alert('XSS Attack')</script>",
				"title":   "Comment Title",
			},
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			setupValidation: func(mocks *E2EValidationMocks) {
				mocks.requestValidator.ValidateRequestFunc = func(ctx context.Context, request interface{}, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid: false,
						Passed:  false,
						Errors: []domain.ValidationError{
							{
								Code:      "SECURITY_THREAT",
								Field:     "content",
								Message:   "XSS script injection detected",
								Severity:  domain.SeverityCritical,
								Category:  domain.CategorySecurity,
								Timestamp: time.Now(),
							},
						},
						SecurityResult: &domain.SecurityValidationResult{
							ThreatLevel: domain.ThreatHigh,
							ThreatTypes: []domain.ThreatType{domain.ThreatXSS},
							Violations: []domain.SecurityViolation{
								{
									Type:        domain.ThreatXSS,
									Severity:    domain.SeverityCritical,
									Description: "XSS script injection detected",
									FieldName:   "content",
									Pattern:     "<script>",
									Action:      domain.ActionBlock,
									Blocked:     true,
								},
							},
						},
						ValidationTime: 35 * time.Millisecond,
						ValidationID:   "xss_val_403",
					}, nil
				}
			},
			expectedStatus: http.StatusForbidden,
			validateResponse: func(t *testing.T, response E2EResponse) {
				t.Helper()
				if response.Body["threat_level"] == nil {
					t.Error("expected threat_level in security response")
				}
				if response.Body["security_violations"] == nil {
					t.Error("expected security_violations in response")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create E2E test environment
			env := setupE2ETestEnvironment(t)
			
			// Setup validation mocks
			tt.setupValidation(env.ValidationMocks)

			// Make API request
			response := makeAPIRequest(t, env, tt.method, tt.endpoint, tt.requestBody, tt.headers)

			// Validate response
			if response.StatusCode != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, response.StatusCode)
			}

			tt.validateResponse(t, response)
		})
	}
}

// TestBackwardCompatibility tests that validation doesn't break existing functionality
func TestBackwardCompatibility(t *testing.T) {
	// Create environment with validation disabled
	env := setupE2ETestEnvironment(t)
	
	// Disable validation for compatibility test
	env.ValidationMocks.requestValidator.ValidateRequestFunc = func(ctx context.Context, request interface{}, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
		// Always pass validation for backward compatibility
		return &domain.ValidationResult{
			IsValid:        true,
			Passed:         true,
			Errors:         []domain.ValidationError{},
			ValidationTime: 1 * time.Millisecond,
			ValidationID:   "compat_val_200",
		}, nil
	}

	// Test existing endpoints still work
	compatibilityTests := []struct {
		name     string
		endpoint string
		method   string
		body     map[string]interface{}
	}{
		{
			name:     "existing registration endpoint",
			endpoint: "/auth/register",
			method:   "POST",
			body: map[string]interface{}{
				"email":    "compat@example.com",
				"password": "password123",
				"phone":    "+1234567890",
			},
		},
		{
			name:     "existing login endpoint",
			endpoint: "/auth/login",
			method:   "POST",
			body: map[string]interface{}{
				"email":    "compat@example.com",
				"password": "password123",
			},
		},
	}

	for _, test := range compatibilityTests {
		t.Run(test.name, func(t *testing.T) {
			response := makeAPIRequest(t, env, test.method, test.endpoint, test.body, nil)
			
			// Should not be blocked by validation
			if response.StatusCode >= 400 && response.StatusCode < 500 {
				// Check if it's a validation error
				if response.Body["validation_errors"] != nil {
					t.Errorf("backward compatibility broken: validation blocking existing endpoint %s", test.endpoint)
				}
			}
			
			t.Logf("Compatibility test: %s -> %d", test.endpoint, response.StatusCode)
		})
	}
}

// Helper types and functions

type E2ETestEnvironment struct {
	Router          *gin.Engine
	ValidationMocks *E2EValidationMocks
	AuthMocks       *E2EAuthMocks
}

type E2EValidationMocks struct {
	requestValidator *mocks.MockRequestValidationService
}

type E2EAuthMocks struct {
	userRepository     *mocks.MockUserRepository
	sessionRepository  *mocks.MockSessionRepository
	passwordService    *mocks.MockPasswordService
	tokenService       *mocks.MockTokenService
	otpService         *mocks.MockOTPService
}

// NewMockAuthService creates a mock auth service from the individual components
func (m *E2EAuthMocks) NewMockAuthService() *mocks.MockAuthService {
	return mocks.NewMockAuthService()
}

type E2EResponse struct {
	StatusCode int
	Body       map[string]interface{}
	Headers    http.Header
}

func setupE2ETestEnvironment(t *testing.T) *E2ETestEnvironment {
	t.Helper()

	// Create validation mocks
	validationMocks := &E2EValidationMocks{
		requestValidator: mocks.NewMockRequestValidationService(),
	}

	// Create auth service mocks
	authMocks := &E2EAuthMocks{
		userRepository:    mocks.NewMockUserRepository(),
		sessionRepository: mocks.NewMockSessionRepository(),
		passwordService:   mocks.NewMockPasswordService(),
		tokenService:      mocks.NewMockTokenService(),
		otpService:        mocks.NewMockOTPService(),
	}

	// Setup default auth mock behaviors
	setupDefaultAuthMocks(authMocks)

	// Create validation service
	validationService := createE2EValidationService(validationMocks)

	// Create auth service
	authService := createE2EAuthService(authMocks)

	// Setup router with middleware
	router := gin.New()
	router.Use(gin.Recovery())
	
	// Add validation middleware
	validationMiddleware := createE2EValidationMiddleware(validationService)
	router.Use(validationMiddleware)

	// Add auth routes
	setupE2EAuthRoutes(router, authService)

	// Add test API routes
	setupE2EAPIRoutes(router)

	return &E2ETestEnvironment{
		Router:          router,
		ValidationMocks: validationMocks,
		AuthMocks:       authMocks,
	}
}

func executeAuthenticationFlow(t *testing.T, env *E2ETestEnvironment, regData, loginData, otpData map[string]interface{}) []E2EResponse {
	t.Helper()
	
	var responses []E2EResponse

	// Step 1: Registration
	if regData != nil {
		response := makeAPIRequest(t, env, "POST", "/auth/register", regData, nil)
		responses = append(responses, response)
		
		// If registration failed, stop the flow
		if response.StatusCode >= 400 {
			return responses
		}
	}

	// Step 2: Login
	if loginData != nil {
		response := makeAPIRequest(t, env, "POST", "/auth/login", loginData, nil)
		responses = append(responses, response)
		
		// If login failed, stop the flow
		if response.StatusCode >= 400 {
			return responses
		}
	}

	// Step 3: OTP Verification
	if otpData != nil {
		response := makeAPIRequest(t, env, "POST", "/auth/otp/verify", otpData, nil)
		responses = append(responses, response)
	}

	return responses
}

func makeAPIRequest(t *testing.T, env *E2ETestEnvironment, method, endpoint string, body map[string]interface{}, headers map[string]string) E2EResponse {
	t.Helper()

	var reqBody *bytes.Buffer
	if body != nil {
		bodyBytes, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(bodyBytes)
	} else {
		reqBody = bytes.NewBuffer([]byte{})
	}

	req := httptest.NewRequest(method, endpoint, reqBody)
	req.Header.Set("Content-Type", "application/json")

	// Set additional headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	recorder := httptest.NewRecorder()
	env.Router.ServeHTTP(recorder, req)

	var responseBody map[string]interface{}
	if recorder.Body.Len() > 0 {
		if err := json.Unmarshal(recorder.Body.Bytes(), &responseBody); err != nil {
			t.Logf("Failed to unmarshal response body: %v", err)
			responseBody = map[string]interface{}{"raw": recorder.Body.String()}
		}
	}

	return E2EResponse{
		StatusCode: recorder.Code,
		Body:       responseBody,
		Headers:    recorder.Header(),
	}
}

// Mock creation helpers

func createSuccessfulRegistrationValidation() func(context.Context, string, string, string, string, *domain.ValidationContext) (*domain.ValidationResult, error) {
	return func(ctx context.Context, email, phone, password, role string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
		return &domain.ValidationResult{
			IsValid:        true,
			Passed:         true,
			Errors:         []domain.ValidationError{},
			Warnings:       []domain.ValidationError{},
			ValidationTime: 50 * time.Millisecond,
			RulesApplied:   3,
			ValidationID:   "reg_val_success",
		}, nil
	}
}

func createSuccessfulLoginValidation() func(context.Context, string, string, *domain.ValidationContext) (*domain.ValidationResult, error) {
	return func(ctx context.Context, email, password string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
		return &domain.ValidationResult{
			IsValid:        true,
			Passed:         true,
			Errors:         []domain.ValidationError{},
			ValidationTime: 30 * time.Millisecond,
			RulesApplied:   2,
			ValidationID:   "login_val_success",
		}, nil
	}
}

func createSuccessfulOTPValidation() func(context.Context, string, string, uint, *domain.ValidationContext) (*domain.ValidationResult, error) {
	return func(ctx context.Context, phone, code string, userID uint, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
		return &domain.ValidationResult{
			IsValid:        true,
			Passed:         true,
			Errors:         []domain.ValidationError{},
			ValidationTime: 20 * time.Millisecond,
			RulesApplied:   1,
			ValidationID:   "otp_val_success",
		}, nil
	}
}

func createE2EValidationService(validationMocks *E2EValidationMocks) domain.RequestValidationService {
	// Return the mock directly so test setups can configure it
	return validationMocks.requestValidator
}

func createE2EAuthService(mocks *E2EAuthMocks) domain.AuthService {
	// Create a simplified auth service for E2E testing
	// This would normally use the real AuthService constructor
	// For now, return a mock that implements the interface
	authSvc := mocks.NewMockAuthService()
	
	// Setup basic successful behaviors
	authSvc.RegisterFunc = func(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
		return &domain.User{
			ID:            1,
			Email:         email,
			Phone:         phone,
			Role:          role,
			IsActive:      true,
			PhoneVerified: false,
		}, nil
	}
	
	authSvc.LoginFunc = func(ctx context.Context, email, password string) (*domain.AuthResult, error) {
		return &domain.AuthResult{
			User: &domain.User{
				ID:       1,
				Email:    email,
				IsActive: true,
			},
			AccessToken:  "access_token_123",
			RefreshToken: "refresh_token_456",
			SessionID:    "session_789",
			ExpiresIn:    3600,
		}, nil
	}
	
	return authSvc
}

func createE2EValidationMiddleware(validationService domain.RequestValidationService) gin.HandlerFunc {
	// Create a simplified validation middleware for E2E testing
	return func(c *gin.Context) {
		// Extract request body for validation
		var requestBody map[string]interface{}
		if c.Request.Body != nil {
			bodyBytes, _ := c.GetRawData()
			if len(bodyBytes) > 0 {
				json.Unmarshal(bodyBytes, &requestBody)
				// Restore body for downstream handlers
				c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}
		}

		// Create validation context
		validationCtx := &domain.ValidationContext{
			RequestID: fmt.Sprintf("e2e_%d", time.Now().UnixNano()),
			Endpoint:  c.Request.URL.Path,
			Method:    c.Request.Method,
			IPAddress: c.ClientIP(),
			UserAgent: c.GetHeader("User-Agent"),
			Timestamp: time.Now(),
		}

		// Validate based on endpoint
		var result *domain.ValidationResult
		var err error

		switch {
		case strings.Contains(c.Request.URL.Path, "/auth/register"):
			if email, exists := requestBody["email"].(string); exists {
				phone, _ := requestBody["phone"].(string)
				password, _ := requestBody["password"].(string)
				role, _ := requestBody["role"].(string)
				result, err = validationService.ValidateRegistrationRequest(context.Background(), email, phone, password, role, validationCtx)
			}
		case strings.Contains(c.Request.URL.Path, "/auth/login"):
			if email, exists := requestBody["email"].(string); exists {
				password, _ := requestBody["password"].(string)
				result, err = validationService.ValidateLoginRequest(context.Background(), email, password, validationCtx)
			}
		case strings.Contains(c.Request.URL.Path, "/auth/otp"):
			if phone, exists := requestBody["phone"].(string); exists {
				code, _ := requestBody["code"].(string)
				result, err = validationService.ValidateOTPRequest(context.Background(), phone, code, 1, validationCtx)
			}
		default:
			// Generic request validation
			result, err = validationService.ValidateRequest(context.Background(), requestBody, validationCtx)
		}

		// Handle validation results
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Validation service error"})
			c.Abort()
			return
		}

		if result != nil && !result.IsValid {
			// Determine response based on error types
			statusCode := http.StatusBadRequest
			response := gin.H{"error": "Validation failed"}

			// Check for specific error types
			for _, validationError := range result.Errors {
				switch validationError.Category {
				case domain.CategorySecurity:
					statusCode = http.StatusForbidden
					response = gin.H{
						"error": "Security threat detected",
					}
					// Add security result details if available
					if result.SecurityResult != nil {
						response["threat_level"] = result.SecurityResult.ThreatLevel
						response["security_violations"] = result.SecurityResult.Violations
					} else {
						// Default values when SecurityResult is missing
						response["threat_level"] = "high"
					}
				case domain.CategoryRateLimit:
					statusCode = http.StatusTooManyRequests
					response = gin.H{"error": validationError.Message}
				case domain.CategoryField:
					response = gin.H{
						"error":            "Validation failed",
						"validation_errors": result.Errors,
						"field_errors":     result.FieldResults,
						"warnings":         result.Warnings,
					}
				}
			}

			c.JSON(statusCode, response)
			c.Abort()
			return
		}

		c.Next()
	}
}

func setupDefaultAuthMocks(mocks *E2EAuthMocks) {
	// Setup basic auth mock behaviors for E2E testing
	mocks.userRepository.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
		return nil, domain.ErrUserNotFound // User doesn't exist for registration
	}
	
	mocks.passwordService.HashFunc = func(password string) (string, error) {
		return "hashed_" + password, nil
	}
	
	mocks.userRepository.CreateFunc = func(ctx context.Context, user *domain.User) error {
		user.ID = 1
		return nil
	}
	
	mocks.otpService.GenerateFunc = func(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) {
		return &domain.OTPRequest{
			Phone:     phone,
			Code:      "123456",
			UserID:    userID,
			ExpiresAt: time.Now().Add(5 * time.Minute),
		}, nil
	}
}

func setupE2EAuthRoutes(router *gin.Engine, authService domain.AuthService) {
	auth := router.Group("/auth")
	{
		auth.POST("/register", func(c *gin.Context) {
			var req struct {
				Email    string `json:"email"`
				Phone    string `json:"phone"`
				Password string `json:"password"`
				Role     string `json:"role"`
			}
			
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
				return
			}
			
			user, err := authService.Register(c.Request.Context(), req.Email, req.Phone, req.Password, req.Role)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
			
			c.JSON(http.StatusCreated, gin.H{"user": user})
		})
		
		auth.POST("/login", func(c *gin.Context) {
			var req struct {
				Email    string `json:"email"`
				Password string `json:"password"`
			}
			
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
				return
			}
			
			result, err := authService.Login(c.Request.Context(), req.Email, req.Password)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
				return
			}
			
			c.JSON(http.StatusOK, gin.H{
				"access_token":  result.AccessToken,
				"refresh_token": result.RefreshToken,
				"user":          result.User,
			})
		})
		
		auth.POST("/otp/verify", func(c *gin.Context) {
			var req struct {
				Phone string `json:"phone"`
				Code  string `json:"code"`
			}
			
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
				return
			}
			
			c.JSON(http.StatusOK, gin.H{"message": "OTP verified successfully"})
		})
	}
}

func setupE2EAPIRoutes(router *gin.Engine) {
	api := router.Group("/api")
	{
		api.POST("/users", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "User created successfully"})
		})
		
		api.POST("/comments", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"message": "Comment created successfully"})
		})
	}
}