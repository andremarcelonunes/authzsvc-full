package services

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

func TestRequestValidationServiceImpl_ValidateRequest(t *testing.T) {
	tests := []struct {
		name            string
		request         interface{}
		validationCtx   *domain.ValidationContext
		setupMocks      func(*mocks.MockSecurityValidationService, *mocks.MockBusinessValidationService, *mocks.MockRateLimitValidationService)
		expectedResult  *domain.ValidationResult
		expectedError   string
		validateResult  func(t *testing.T, result *domain.ValidationResult)
	}{
		{
			name:    "successful validation - all phases pass",
			request: map[string]interface{}{"email": "test@example.com", "password": "securePassword123"},
			validationCtx: &domain.ValidationContext{
				RequestID: "req_123",
				Endpoint:  "/auth/login",
				Method:    "POST",
				IPAddress: "192.168.1.100",
				UserAgent: "Mozilla/5.0",
				Timestamp: time.Now(),
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// Rate limiting passes
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{
						Allowed:      true,
						CurrentCount: 5,
						Limit:        100,
						Remaining:    95,
					}, nil
				}
				
				// Security validation passes
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel:    domain.ThreatNone,
						ThreatTypes:    []domain.ThreatType{},
						Violations:     []domain.SecurityViolation{},
						ScanResults:    make(map[string]interface{}),
					}, nil
				}
				
				// Business validation passes
				businessSvc.ValidateBusinessRulesFunc = func(ctx context.Context, entity interface{}, rules []domain.BusinessConstraint) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid:      true,
						Passed:       true,
						Errors:       []domain.ValidationError{},
						Warnings:     []domain.ValidationError{},
						RulesApplied: 2,
					}, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if !result.IsValid {
					t.Error("expected validation to pass")
				}
				if !result.Passed {
					t.Error("expected passed to be true")
				}
				if len(result.Errors) > 0 {
					t.Errorf("expected no errors, got %d", len(result.Errors))
				}
				if result.ValidationTime == 0 {
					t.Error("expected validation time to be recorded")
				}
			},
		},
		{
			name:    "rate limit exceeded",
			request: map[string]interface{}{"email": "test@example.com"},
			validationCtx: &domain.ValidationContext{
				RequestID: "req_124",
				Endpoint:  "/auth/login",
				Method:    "POST",
				IPAddress: "192.168.1.100",
				Timestamp: time.Now(),
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// Rate limiting fails
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{
						Allowed:      false,
						CurrentCount: 101,
						Limit:        100,
						Remaining:    0,
						RetryAfter:   5 * time.Minute,
					}, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected validation to fail due to rate limit")
				}
				if result.Passed {
					t.Error("expected passed to be false")
				}
				if len(result.Errors) == 0 {
					t.Error("expected rate limit errors")
				}
				// Check for specific rate limit error
				found := false
				for _, err := range result.Errors {
					if err.Category == domain.CategoryRateLimit {
						found = true
						break
					}
				}
				if !found {
					t.Error("expected rate limit error in results")
				}
			},
		},
		{
			name:    "security threat detected - high level",
			request: map[string]interface{}{"comment": "<script>alert('xss')</script>"},
			validationCtx: &domain.ValidationContext{
				RequestID: "req_125",
				Endpoint:  "/api/comments",
				Method:    "POST",
				IPAddress: "192.168.1.101",
				Timestamp: time.Now(),
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// Rate limiting passes
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				// Security validation detects XSS
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatHigh,
						ThreatTypes: []domain.ThreatType{domain.ThreatXSS},
						Violations: []domain.SecurityViolation{
							{
								Type:        domain.ThreatXSS,
								Severity:    domain.SeverityError,
								Description: "XSS script injection detected",
								FieldName:   "comment",
								Pattern:     "<script>",
								Action:      domain.ActionBlock,
								Blocked:     true,
							},
						},
					}, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected validation to fail due to security threat")
				}
				if result.Passed {
					t.Error("expected passed to be false")
				}
				if result.SecurityResult == nil {
					t.Error("expected security result to be present")
				}
				if result.SecurityResult.ThreatLevel != domain.ThreatHigh {
					t.Errorf("expected threat level high, got %s", result.SecurityResult.ThreatLevel)
				}
				// Check for security error
				found := false
				for _, err := range result.Errors {
					if err.Category == domain.CategorySecurity {
						found = true
						break
					}
				}
				if !found {
					t.Error("expected security error in results")
				}
			},
		},
		{
			name:    "validation timeout",
			request: map[string]interface{}{"data": "test"},
			validationCtx: &domain.ValidationContext{
				RequestID: "req_126",
				Endpoint:  "/api/test",
				Method:    "POST",
				IPAddress: "192.168.1.100",
				Timestamp: time.Now(),
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// Rate limiting passes
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				// Security validation times out
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					// Simulate timeout by checking context
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-time.After(50 * time.Millisecond): // Shorter than typical timeout for testing
						return nil, errors.New("validation timeout")
					}
				}
			},
			expectedError: "security validation failed",
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				// Should not reach here due to error
				if result != nil {
					t.Error("expected nil result due to timeout error")
				}
			},
		},
		{
			name:    "field validation errors",
			request: map[string]interface{}{"email": "invalid-email", "password": "short"},
			validationCtx: &domain.ValidationContext{
				RequestID: "req_127",
				Endpoint:  "/auth/register",
				Method:    "POST",
				IPAddress: "192.168.1.100",
				Timestamp: time.Now(),
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// Rate limiting passes
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				// Security validation passes
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatNone,
					}, nil
				}
				
				// Business validation fails
				businessSvc.ValidateBusinessRulesFunc = func(ctx context.Context, entity interface{}, rules []domain.BusinessConstraint) (*domain.ValidationResult, error) {
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
								Code:      "PASSWORD_TOO_SHORT",
								Field:     "password",
								Message:   "Password must be at least 8 characters",
								Severity:  domain.SeverityError,
								Category:  domain.CategoryField,
								Timestamp: time.Now(),
							},
						},
						RulesApplied: 2,
					}, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected validation to fail due to field errors")
				}
				if result.Passed {
					t.Error("expected passed to be false")
				}
				if len(result.Errors) < 2 {
					t.Errorf("expected at least 2 errors, got %d", len(result.Errors))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			securitySvc := mocks.NewMockSecurityValidationService()
			businessSvc := mocks.NewMockBusinessValidationService()
			rateLimitSvc := mocks.NewMockRateLimitValidationService()

			// Setup test-specific mock behavior
			tt.setupMocks(securitySvc, businessSvc, rateLimitSvc)

			// Create validation service
			config := RequestValidationConfig{
				EnableCaching:     false, // Disable caching for testing
				MaxValidationTime: 1 * time.Second,
				EnableMetrics:     false,
			}
			
			service := NewRequestValidationService(
				securitySvc,
				businessSvc,
				rateLimitSvc,
				nil, // No Redis client for basic tests
				config,
			)

			// Execute test
			ctx := context.Background()
			result, err := service.ValidateRequest(ctx, tt.request, tt.validationCtx)

			// Validate error
			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error containing '%s', got nil", tt.expectedError)
				}
				if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Validate result
			tt.validateResult(t, result)
		})
	}
}

func TestRequestValidationServiceImpl_ValidateRegistrationRequest(t *testing.T) {
	tests := []struct {
		name           string
		email          string
		phone          string
		password       string
		role           string
		validationCtx  *domain.ValidationContext
		setupMocks     func(*mocks.MockSecurityValidationService, *mocks.MockBusinessValidationService, *mocks.MockRateLimitValidationService)
		expectedError  string
		validateResult func(t *testing.T, result *domain.ValidationResult)
	}{
		{
			name:     "successful registration validation",
			email:    "newuser@example.com",
			phone:    "+1234567890",
			password: "SecurePassword123!",
			role:     "user",
			validationCtx: &domain.ValidationContext{
				RequestID: "reg_123",
				Endpoint:  "/auth/register",
				Method:    "POST",
				IPAddress: "192.168.1.100",
				Timestamp: time.Now(),
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// Rate limiting passes
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					if strings.Contains(key, "reg_limit") {
						return &domain.RateLimitResult{
							Allowed:      true,
							CurrentCount: 2,
							Limit:        5,
							Remaining:    3,
						}, nil
					}
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				// Security validation passes
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatNone,
						ThreatTypes: []domain.ThreatType{},
						Violations:  []domain.SecurityViolation{},
					}, nil
				}
				
				// Business validation passes
				businessSvc.ValidateRegistrationRulesFunc = func(ctx context.Context, email, phone, password, role string) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid:      true,
						Passed:       true,
						Errors:       []domain.ValidationError{},
						Warnings:     []domain.ValidationError{},
						RulesApplied: 3,
					}, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if !result.IsValid {
					t.Error("expected registration validation to pass")
				}
				if !result.Passed {
					t.Error("expected passed to be true")
				}
				if len(result.Errors) > 0 {
					t.Errorf("expected no errors, got %d", len(result.Errors))
				}
				if !strings.Contains(result.ValidationID, "reg_val_") {
					t.Error("expected registration validation ID to contain 'reg_val_'")
				}
			},
		},
		{
			name:     "registration rate limit exceeded",
			email:    "spammer@example.com",
			phone:    "+1234567890",
			password: "password123",
			role:     "user",
			validationCtx: &domain.ValidationContext{
				RequestID: "reg_124",
				Endpoint:  "/auth/register",
				Method:    "POST",
				IPAddress: "192.168.1.101", // Different IP for rate limiting
				Timestamp: time.Now(),
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// Rate limiting fails for registration
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					if strings.Contains(key, "reg_limit") {
						return &domain.RateLimitResult{
							Allowed:      false,
							CurrentCount: 6,
							Limit:        5,
							Remaining:    0,
							RetryAfter:   1 * time.Hour,
						}, nil
					}
					return &domain.RateLimitResult{Allowed: true}, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected registration validation to fail due to rate limit")
				}
				if result.Passed {
					t.Error("expected passed to be false")
				}
				// Check for rate limit error
				found := false
				for _, err := range result.Errors {
					if err.Code == "RATE_LIMIT_EXCEEDED" && err.Category == domain.CategoryRateLimit {
						found = true
						break
					}
				}
				if !found {
					t.Error("expected registration rate limit error")
				}
			},
		},
		{
			name:     "registration with security threats",
			email:    "test@example.com'; DROP TABLE users; --",
			phone:    "+1234567890",
			password: "password123",
			role:     "admin", // Suspicious role elevation attempt
			validationCtx: &domain.ValidationContext{
				RequestID: "reg_125",
				Endpoint:  "/auth/register",
				Method:    "POST",
				IPAddress: "192.168.1.100",
				Timestamp: time.Now(),
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// Rate limiting passes
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				// Security validation detects SQL injection
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatCritical,
						ThreatTypes: []domain.ThreatType{domain.ThreatSQLInjection},
						Violations: []domain.SecurityViolation{
							{
								Type:        domain.ThreatSQLInjection,
								Severity:    domain.SeverityCritical,
								Description: "SQL injection attempt detected in email field",
								FieldName:   "email",
								Pattern:     "DROP TABLE",
								Action:      domain.ActionBlock,
								Blocked:     true,
							},
						},
					}, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected registration validation to fail due to security threat")
				}
				if result.Passed {
					t.Error("expected passed to be false")
				}
				if result.SecurityResult == nil {
					t.Error("expected security result to be present")
				}
				if result.SecurityResult.ThreatLevel != domain.ThreatCritical {
					t.Errorf("expected critical threat level, got %s", result.SecurityResult.ThreatLevel)
				}
			},
		},
		{
			name:     "registration business rule violations",
			email:    "test@example.com",
			phone:    "+1234567890",
			password: "weak",
			role:     "invalidrole",
			validationCtx: &domain.ValidationContext{
				RequestID: "reg_126",
				Endpoint:  "/auth/register",
				Method:    "POST",
				IPAddress: "192.168.1.100",
				Timestamp: time.Now(),
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// Rate limiting passes
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				// Security validation passes
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatNone,
					}, nil
				}
				
				// Business validation fails with multiple errors
				businessSvc.ValidateRegistrationRulesFunc = func(ctx context.Context, email, phone, password, role string) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid: false,
						Passed:  false,
						Errors: []domain.ValidationError{
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
								Code:      "EMAIL_DOMAIN_WARNING",
								Field:     "email",
								Message:   "Email domain not commonly used",
								Severity:  domain.SeverityWarning,
								Category:  domain.CategoryBusiness,
								Timestamp: time.Now(),
							},
						},
						RulesApplied: 3,
					}, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected registration validation to fail due to business rules")
				}
				if result.Passed {
					t.Error("expected passed to be false")
				}
				if len(result.Errors) < 2 {
					t.Errorf("expected at least 2 errors, got %d", len(result.Errors))
				}
				if len(result.Warnings) < 1 {
					t.Errorf("expected at least 1 warning, got %d", len(result.Warnings))
				}
				if result.RulesApplied < 3 {
					t.Errorf("expected at least 3 rules applied, got %d", result.RulesApplied)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			securitySvc := mocks.NewMockSecurityValidationService()
			businessSvc := mocks.NewMockBusinessValidationService()
			rateLimitSvc := mocks.NewMockRateLimitValidationService()

			// Setup test-specific mock behavior
			tt.setupMocks(securitySvc, businessSvc, rateLimitSvc)

			// Create validation service
			config := RequestValidationConfig{
				EnableCaching:     false,
				MaxValidationTime: 30 * time.Second,
				EnableMetrics:     false,
			}
			
			service := NewRequestValidationService(
				securitySvc,
				businessSvc,
				rateLimitSvc,
				nil,
				config,
			)

			// Execute test
			ctx := context.Background()
			result, err := service.ValidateRegistrationRequest(ctx, tt.email, tt.phone, tt.password, tt.role, tt.validationCtx)

			// Validate error
			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error containing '%s', got nil", tt.expectedError)
				}
				if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Validate result
			tt.validateResult(t, result)
		})
	}
}

func TestRequestValidationServiceImpl_ValidateLoginRequest(t *testing.T) {
	tests := []struct {
		name           string
		email          string
		password       string
		validationCtx  *domain.ValidationContext
		setupMocks     func(*mocks.MockSecurityValidationService, *mocks.MockBusinessValidationService, *mocks.MockRateLimitValidationService)
		expectedError  string
		validateResult func(t *testing.T, result *domain.ValidationResult)
	}{
		{
			name:     "successful login validation",
			email:    "user@example.com",
			password: "correctPassword123",
			validationCtx: &domain.ValidationContext{
				RequestID: "login_123",
				Endpoint:  "/auth/login",
				Method:    "POST",
				IPAddress: "192.168.1.100",
				Timestamp: time.Now(),
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// Rate limiting passes
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{
						Allowed:      true,
						CurrentCount: 3,
						Limit:        10,
						Remaining:    7,
					}, nil
				}
				
				// Brute force check passes
				rateLimitSvc.IsBlockedFunc = func(ctx context.Context, identifier string, attemptType string) (bool, time.Duration, error) {
					return false, 0, nil
				}
				
				// Security validation passes
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatNone,
					}, nil
				}
				
				// Business validation passes
				businessSvc.ValidateLoginRulesFunc = func(ctx context.Context, email, password string, user *domain.User) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid:      true,
						Passed:       true,
						Errors:       []domain.ValidationError{},
						RulesApplied: 2,
					}, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if !result.IsValid {
					t.Error("expected login validation to pass")
				}
				if !result.Passed {
					t.Error("expected passed to be true")
				}
				if !strings.Contains(result.ValidationID, "login_val_") {
					t.Error("expected login validation ID to contain 'login_val_'")
				}
			},
		},
		{
			name:     "login rate limit exceeded",
			email:    "user@example.com",
			password: "password123",
			validationCtx: &domain.ValidationContext{
				RequestID: "login_124",
				Endpoint:  "/auth/login",
				Method:    "POST",
				IPAddress: "192.168.1.200", // Different IP for rate limiting
				Timestamp: time.Now(),
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// Rate limiting fails
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					if strings.Contains(key, "login_limit") {
						return &domain.RateLimitResult{
							Allowed:      false,
							CurrentCount: 11,
							Limit:        10,
							Remaining:    0,
							RetryAfter:   15 * time.Minute,
						}, nil
					}
					return &domain.RateLimitResult{Allowed: true}, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected login validation to fail due to rate limit")
				}
				// Check for specific error code
				found := false
				for _, err := range result.Errors {
					if err.Code == "RATE_LIMIT_EXCEEDED" {
						found = true
						break
					}
				}
				if !found {
					t.Error("expected rate limit exceeded error")
				}
			},
		},
		{
			name:     "brute force protection triggered",
			email:    "victim@example.com",
			password: "password123",
			validationCtx: &domain.ValidationContext{
				RequestID: "login_125",
				Endpoint:  "/auth/login",
				Method:    "POST",
				IPAddress: "192.168.1.100",
				Timestamp: time.Now(),
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// Rate limiting passes
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				// Brute force check fails
				rateLimitSvc.IsBlockedFunc = func(ctx context.Context, identifier string, attemptType string) (bool, time.Duration, error) {
					if strings.Contains(identifier, "victim@example.com") {
						return true, 30 * time.Minute, nil
					}
					return false, 0, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected login validation to fail due to brute force protection")
				}
				// Check for brute force error
				found := false
				for _, err := range result.Errors {
					if err.Code == "BRUTE_FORCE_DETECTED" {
						found = true
						if !strings.Contains(err.Message, "30m") {
							t.Error("expected error message to contain block duration")
						}
						break
					}
				}
				if !found {
					t.Error("expected brute force detected error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			securitySvc := mocks.NewMockSecurityValidationService()
			businessSvc := mocks.NewMockBusinessValidationService()
			rateLimitSvc := mocks.NewMockRateLimitValidationService()

			// Setup test-specific mock behavior
			tt.setupMocks(securitySvc, businessSvc, rateLimitSvc)

			// Create validation service
			config := RequestValidationConfig{
				EnableCaching:     false,
				MaxValidationTime: 30 * time.Second,
				EnableMetrics:     false,
			}
			
			service := NewRequestValidationService(
				securitySvc,
				businessSvc,
				rateLimitSvc,
				nil,
				config,
			)

			// Execute test
			ctx := context.Background()
			result, err := service.ValidateLoginRequest(ctx, tt.email, tt.password, tt.validationCtx)

			// Validate error
			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error containing '%s', got nil", tt.expectedError)
				}
				if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Validate result
			tt.validateResult(t, result)
		})
	}
}

func TestRequestValidationServiceImpl_ValidateOTPRequest(t *testing.T) {
	tests := []struct {
		name           string
		phone          string
		code           string
		userID         uint
		validationCtx  *domain.ValidationContext
		setupMocks     func(*mocks.MockBusinessValidationService, *mocks.MockRateLimitValidationService)
		expectedError  string
		validateResult func(t *testing.T, result *domain.ValidationResult)
	}{
		{
			name:   "successful OTP validation",
			phone:  "+1234567890",
			code:   "123456",
			userID: 1,
			validationCtx: &domain.ValidationContext{
				RequestID: "otp_123",
				Endpoint:  "/auth/otp/verify",
				Method:    "POST",
				IPAddress: "192.168.1.100",
				Timestamp: time.Now(),
			},
			setupMocks: func(businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// Rate limiting passes
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{
						Allowed:      true,
						CurrentCount: 2,
						Limit:        5,
						Remaining:    3,
					}, nil
				}
				
				// Business validation passes
				businessSvc.ValidateOTPRulesFunc = func(ctx context.Context, phone, code string, userID uint) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid:      true,
						Passed:       true,
						Errors:       []domain.ValidationError{},
						RulesApplied: 1,
					}, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if !result.IsValid {
					t.Error("expected OTP validation to pass")
				}
				if !strings.Contains(result.ValidationID, "otp_val_") {
					t.Error("expected OTP validation ID to contain 'otp_val_'")
				}
			},
		},
		{
			name:   "OTP rate limit exceeded",
			phone:  "+1234567890",
			code:   "123456",
			userID: 1,
			validationCtx: &domain.ValidationContext{
				RequestID: "otp_124",
				Endpoint:  "/auth/otp/verify",
				Method:    "POST",
				IPAddress: "192.168.1.100",
				Timestamp: time.Now(),
			},
			setupMocks: func(businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// Rate limiting fails
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					if strings.Contains(key, "otp_limit") {
						return &domain.RateLimitResult{
							Allowed:      false,
							CurrentCount: 6,
							Limit:        5,
							Remaining:    0,
							RetryAfter:   5 * time.Minute,
						}, nil
					}
					return &domain.RateLimitResult{Allowed: true}, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected OTP validation to fail due to rate limit")
				}
				// Check for OTP rate limit error
				found := false
				for _, err := range result.Errors {
					if strings.Contains(err.Message, "OTP verification rate limit exceeded") {
						found = true
						break
					}
				}
				if !found {
					t.Error("expected OTP rate limit error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			securitySvc := mocks.NewMockSecurityValidationService()
			businessSvc := mocks.NewMockBusinessValidationService()
			rateLimitSvc := mocks.NewMockRateLimitValidationService()

			// Setup test-specific mock behavior
			tt.setupMocks(businessSvc, rateLimitSvc)

			// Create validation service
			config := RequestValidationConfig{
				EnableCaching:     false,
				MaxValidationTime: 30 * time.Second,
				EnableMetrics:     false,
			}
			
			service := NewRequestValidationService(
				securitySvc,
				businessSvc,
				rateLimitSvc,
				nil,
				config,
			)

			// Execute test
			ctx := context.Background()
			result, err := service.ValidateOTPRequest(ctx, tt.phone, tt.code, tt.userID, tt.validationCtx)

			// Validate error
			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error containing '%s', got nil", tt.expectedError)
				}
				if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Validate result
			tt.validateResult(t, result)
		})
	}
}

func TestRequestValidationServiceImpl_ValidateFields(t *testing.T) {
	tests := []struct {
		name           string
		fields         map[string]interface{}
		rules          []domain.ValidationRule
		expectedResult *domain.ValidationResult
		validateResult func(t *testing.T, result *domain.ValidationResult)
	}{
		{
			name: "successful field validation",
			fields: map[string]interface{}{
				"email": "test@example.com",
				"name":  "John Doe",
			},
			rules: []domain.ValidationRule{
				{
					ID:        "rule_1",
					FieldName: "email",
					IsActive:  true,
					Constraint: &domain.FieldConstraint{
						DataType:  "string",
						MinLength: intPtr(5),
						MaxLength: intPtr(100),
						Pattern:   `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
					},
				},
				{
					ID:        "rule_2",
					FieldName: "name",
					IsActive:  true,
					Constraint: &domain.FieldConstraint{
						DataType:  "string",
						MinLength: intPtr(2),
						MaxLength: intPtr(50),
					},
				},
			},
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if !result.IsValid {
					t.Error("expected field validation to pass")
				}
				if len(result.FieldResults) != 2 {
					t.Errorf("expected 2 field results, got %d", len(result.FieldResults))
				}
				if result.RulesApplied != 2 {
					t.Errorf("expected 2 rules applied, got %d", result.RulesApplied)
				}
			},
		},
		{
			name: "field validation with errors",
			fields: map[string]interface{}{
				"email": "invalid-email",
				"name":  "", // Empty name
			},
			rules: []domain.ValidationRule{
				{
					ID:        "rule_3",
					FieldName: "email",
					IsActive:  true,
					Constraint: &domain.FieldConstraint{
						DataType: "string",
						Pattern:  `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
					},
				},
				{
					ID:        "rule_4",
					FieldName: "name",
					IsActive:  true,
					Constraint: &domain.FieldConstraint{
						DataType:  "string",
						MinLength: intPtr(2),
					},
				},
			},
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected field validation to fail")
				}
				if len(result.Errors) == 0 {
					t.Error("expected validation errors")
				}
				// Check specific field errors
				emailResult, exists := result.FieldResults["email"]
				if !exists {
					t.Error("expected email field result")
				} else if emailResult.IsValid {
					t.Error("expected email field to be invalid")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create validation service
			config := RequestValidationConfig{
				EnableCaching:     false,
				MaxValidationTime: 30 * time.Second,
				EnableMetrics:     false,
			}
			
			service := NewRequestValidationService(
				mocks.NewMockSecurityValidationService(),
				mocks.NewMockBusinessValidationService(),
				mocks.NewMockRateLimitValidationService(),
				nil,
				config,
			)

			// Execute test
			ctx := context.Background()
			result, err := service.ValidateFields(ctx, tt.fields, tt.rules)

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			// Validate result
			tt.validateResult(t, result)
		})
	}
}

func TestRequestValidationServiceImpl_ValidateField(t *testing.T) {
	tests := []struct {
		name           string
		fieldName      string
		value          interface{}
		constraints    *domain.FieldConstraint
		expectedValid  bool
		expectedErrors int
	}{
		{
			name:      "valid email field",
			fieldName: "email",
			value:     "test@example.com",
			constraints: &domain.FieldConstraint{
				DataType:  "string",
				MinLength: intPtr(5),
				MaxLength: intPtr(100),
				Pattern:   `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
			},
			expectedValid:  true,
			expectedErrors: 0,
		},
		{
			name:      "invalid email format",
			fieldName: "email",
			value:     "invalid-email",
			constraints: &domain.FieldConstraint{
				DataType: "string",
				Pattern:  `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`,
			},
			expectedValid:  false,
			expectedErrors: 1,
		},
		{
			name:      "string too short",
			fieldName: "password",
			value:     "123",
			constraints: &domain.FieldConstraint{
				DataType:  "string",
				MinLength: intPtr(8),
			},
			expectedValid:  false,
			expectedErrors: 1,
		},
		{
			name:      "string too long",
			fieldName: "comment",
			value:     strings.Repeat("a", 1001),
			constraints: &domain.FieldConstraint{
				DataType:  "string",
				MaxLength: intPtr(1000),
			},
			expectedValid:  false,
			expectedErrors: 1,
		},
		{
			name:      "forbidden value",
			fieldName: "username",
			value:     "admin",
			constraints: &domain.FieldConstraint{
				DataType:        "string",
				ForbiddenValues: []string{"admin", "root", "administrator"},
			},
			expectedValid:  false,
			expectedErrors: 1,
		},
		{
			name:      "allowed value",
			fieldName: "role",
			value:     "user",
			constraints: &domain.FieldConstraint{
				DataType:      "string",
				AllowedValues: []string{"user", "moderator", "admin"},
			},
			expectedValid:  true,
			expectedErrors: 0,
		},
		{
			name:      "disallowed value",
			fieldName: "role",
			value:     "superuser",
			constraints: &domain.FieldConstraint{
				DataType:      "string",
				AllowedValues: []string{"user", "moderator", "admin"},
			},
			expectedValid:  false,
			expectedErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create validation service
			config := RequestValidationConfig{
				EnableCaching:     false,
				MaxValidationTime: 30 * time.Second,
				EnableMetrics:     false,
			}
			
			service := NewRequestValidationService(
				mocks.NewMockSecurityValidationService(),
				mocks.NewMockBusinessValidationService(),
				mocks.NewMockRateLimitValidationService(),
				nil,
				config,
			)

			// Execute test
			ctx := context.Background()
			result, err := service.ValidateField(ctx, tt.fieldName, tt.value, tt.constraints)

			if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}

			if result.IsValid != tt.expectedValid {
				t.Errorf("expected valid=%v, got %v", tt.expectedValid, result.IsValid)
			}

			if len(result.Errors) != tt.expectedErrors {
				t.Errorf("expected %d errors, got %d", tt.expectedErrors, len(result.Errors))
			}

			if result.FieldName != tt.fieldName {
				t.Errorf("expected field name %s, got %s", tt.fieldName, result.FieldName)
			}

			if result.OriginalValue != tt.value {
				t.Errorf("expected original value %v, got %v", tt.value, result.OriginalValue)
			}
		})
	}
}

func TestRequestValidationServiceImpl_ValidateBatch(t *testing.T) {
	tests := []struct {
		name           string
		requests       []interface{}
		validationCtx  *domain.ValidationContext
		setupMocks     func(*mocks.MockSecurityValidationService, *mocks.MockBusinessValidationService, *mocks.MockRateLimitValidationService)
		expectedError  string
		validateResult func(t *testing.T, results []domain.ValidationResult)
	}{
		{
			name: "successful batch validation",
			requests: []interface{}{
				map[string]interface{}{"email": "user1@example.com"},
				map[string]interface{}{"email": "user2@example.com"},
				map[string]interface{}{"email": "user3@example.com"},
			},
			validationCtx: &domain.ValidationContext{
				RequestID: "batch_123",
				Endpoint:  "/api/batch",
				Method:    "POST",
				IPAddress: "192.168.1.100",
				Timestamp: time.Now(),
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				// All validations pass for batch
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{ThreatLevel: domain.ThreatNone}, nil
				}
				
				businessSvc.ValidateBusinessRulesFunc = func(ctx context.Context, entity interface{}, rules []domain.BusinessConstraint) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{IsValid: true, Passed: true}, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, results []domain.ValidationResult) {
				t.Helper()
				if len(results) != 3 {
					t.Errorf("expected 3 results, got %d", len(results))
				}
				for i, result := range results {
					if !result.IsValid {
						t.Errorf("expected result %d to be valid", i)
					}
					if !result.Passed {
						t.Errorf("expected result %d to pass", i)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			securitySvc := mocks.NewMockSecurityValidationService()
			businessSvc := mocks.NewMockBusinessValidationService()
			rateLimitSvc := mocks.NewMockRateLimitValidationService()

			// Setup test-specific mock behavior
			tt.setupMocks(securitySvc, businessSvc, rateLimitSvc)

			// Create validation service
			config := RequestValidationConfig{
				EnableCaching:     false,
				MaxValidationTime: 30 * time.Second,
				EnableMetrics:     false,
			}
			
			service := NewRequestValidationService(
				securitySvc,
				businessSvc,
				rateLimitSvc,
				nil,
				config,
			)

			// Execute test
			ctx := context.Background()
			results, err := service.ValidateBatch(ctx, tt.requests, tt.validationCtx)

			// Validate error
			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error containing '%s', got nil", tt.expectedError)
				}
				if !strings.Contains(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Validate results
			if results != nil {
				tt.validateResult(t, results)
			}
		})
	}
}

// Helper functions

func intPtr(i int) *int {
	return &i
}

// Compile-time interface compliance verification
var _ domain.RequestValidationService = (*RequestValidationServiceImpl)(nil)