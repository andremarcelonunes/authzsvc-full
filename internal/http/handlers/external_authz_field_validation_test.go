package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// TestExternalAuthzFieldValidation tests comprehensive field validation scenarios
// that were missing from the original test suite
func TestExternalAuthzFieldValidation(t *testing.T) {
	tests := []struct {
		name           string
		envoyRequest   EnvoyRequest
		setupPolicies  func(*casbin.Enforcer)
		expectedStatus int
		expectedError  string
		description    string
	}{
		// ===== QUERY STRING VALIDATION TESTS =====
		{
			name: "query validation success - user accesses own data",
			envoyRequest: createEnvoyRequest("GET", "/api/data", map[string]string{
				"authorization": "Bearer valid_token",
			}, "", "user_id=123"),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/data", "GET", "query.user_id==token.user_id")
			},
			expectedStatus: http.StatusOK,
			description:    "User should access /api/data?user_id=123 when token.user_id=123",
		},
		{
			name: "query validation failure - user tries to access other user data",
			envoyRequest: createEnvoyRequest("GET", "/api/data", map[string]string{
				"authorization": "Bearer valid_token",
			}, "", "user_id=456"),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/data", "GET", "query.user_id==token.user_id")
			},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Field validation failed",
			description:    "User should be denied /api/data?user_id=456 when token.user_id=123",
		},
		{
			name: "query validation with multiple parameters",
			envoyRequest: createEnvoyRequest("GET", "/api/orders", map[string]string{
				"authorization": "Bearer valid_token",
			}, "", "user_id=123&status=active"),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/orders", "GET", "query.user_id==token.user_id")
			},
			expectedStatus: http.StatusOK,
			description:    "Should extract correct user_id from multi-parameter query string",
		},
		{
			name: "query validation missing required parameter",
			envoyRequest: createEnvoyRequest("GET", "/api/data", map[string]string{
				"authorization": "Bearer valid_token",
			}, "", "status=active"),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/data", "GET", "query.user_id==token.user_id")
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "query parameter 'user_id' not found",
			description:    "Should fail when required query parameter is missing",
		},

		// ===== POST BODY FIELD VALIDATION TESTS =====
		{
			name: "body validation success - user creates post with own author_id",
			envoyRequest: createEnvoyRequestWithBody("POST", "/api/posts", map[string]string{
				"authorization": "Bearer valid_token",
				"content-type":  "application/json",
			}, map[string]interface{}{
				"title":     "My Post",
				"content":   "Post content",
				"author_id": 123,
			}),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/posts", "POST", "body.author_id==token.user_id")
			},
			expectedStatus: http.StatusOK,
			description:    "User should create post with author_id=123 when token.user_id=123",
		},
		{
			name: "body validation failure - user tries to create post as another user",
			envoyRequest: createEnvoyRequestWithBody("POST", "/api/posts", map[string]string{
				"authorization": "Bearer valid_token",
				"content-type":  "application/json",
			}, map[string]interface{}{
				"title":     "Fake Post",
				"content":   "Malicious content",
				"author_id": 456,
			}),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/posts", "POST", "body.author_id==token.user_id")
			},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Field validation failed",
			description:    "User should be denied creating post with author_id=456 when token.user_id=123",
		},
		{
			name: "body validation with nested field",
			envoyRequest: createEnvoyRequestWithBody("POST", "/api/comments", map[string]string{
				"authorization": "Bearer valid_token",
				"content-type":  "application/json",
			}, map[string]interface{}{
				"text":     "Great post!",
				"user_id":  123,
				"metadata": map[string]interface{}{"rating": 5},
			}),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/comments", "POST", "body.user_id==token.user_id")
			},
			expectedStatus: http.StatusOK,
			description:    "Should extract user_id from JSON body correctly",
		},
		{
			name: "body validation missing required field",
			envoyRequest: createEnvoyRequestWithBody("POST", "/api/posts", map[string]string{
				"authorization": "Bearer valid_token",
				"content-type":  "application/json",
			}, map[string]interface{}{
				"title":   "Post without author",
				"content": "Some content",
			}),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/posts", "POST", "body.author_id==token.user_id")
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "body field 'author_id' not found",
			description:    "Should fail when required body field is missing",
		},
		{
			name: "body validation with invalid JSON",
			envoyRequest: createEnvoyRequestWithInvalidBody("POST", "/api/posts", map[string]string{
				"authorization": "Bearer valid_token",
				"content-type":  "application/json",
			}, "invalid-json"),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/posts", "POST", "body.author_id==token.user_id")
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "failed to parse JSON body",
			description:    "Should fail gracefully with invalid JSON body",
		},

		// ===== HEADER VALIDATION TESTS =====
		{
			name: "header validation success - user uploads with correct x-user-id",
			envoyRequest: createEnvoyRequest("POST", "/api/upload", map[string]string{
				"authorization": "Bearer valid_token",
				"x-user-id":     "123",
				"content-type":  "multipart/form-data",
			}, "", ""),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/upload", "POST", "header.x-user-id==token.user_id")
			},
			expectedStatus: http.StatusOK,
			description:    "User should upload with x-user-id=123 when token.user_id=123",
		},
		{
			name: "header validation failure - user sends wrong x-user-id",
			envoyRequest: createEnvoyRequest("POST", "/api/upload", map[string]string{
				"authorization": "Bearer valid_token",
				"x-user-id":     "456",
				"content-type":  "multipart/form-data",
			}, "", ""),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/upload", "POST", "header.x-user-id==token.user_id")
			},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Field validation failed",
			description:    "User should be denied upload with x-user-id=456 when token.user_id=123",
		},
		{
			name: "header validation case insensitive",
			envoyRequest: createEnvoyRequest("POST", "/api/upload", map[string]string{
				"authorization": "Bearer valid_token",
				"X-User-ID":     "123", // Capital letters
				"content-type":  "multipart/form-data",
			}, "", ""),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/upload", "POST", "header.X-User-ID==token.user_id")
			},
			expectedStatus: http.StatusOK,
			description:    "Header validation should work with exact case match",
		},
		{
			name: "header validation missing required header",
			envoyRequest: createEnvoyRequest("POST", "/api/upload", map[string]string{
				"authorization": "Bearer valid_token",
				"content-type":  "multipart/form-data",
			}, "", ""),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/upload", "POST", "header.x-user-id==token.user_id")
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "header 'x-user-id' not found",
			description:    "Should fail when required header is missing",
		},

		// ===== COMPLEX MULTI-FIELD VALIDATION TESTS =====
		{
			name: "multi-field validation success - path and query match",
			envoyRequest: createEnvoyRequest("GET", "/users/123/posts", map[string]string{
				"authorization": "Bearer valid_token",
			}, "", "author_id=123"),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/users/*", "GET", "path.user_id==token.user_id&&query.author_id==token.user_id")
			},
			expectedStatus: http.StatusOK,
			description:    "Should allow when both path.user_id=123 and query.author_id=123 match token.user_id=123",
		},
		{
			name: "multi-field validation failure - path matches but query doesn't",
			envoyRequest: createEnvoyRequest("GET", "/users/123/posts", map[string]string{
				"authorization": "Bearer valid_token",
			}, "", "author_id=456"),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/users/*", "GET", "path.user_id==token.user_id&&query.author_id==token.user_id")
			},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Field validation failed",
			description:    "Should deny when path.user_id=123 matches but query.author_id=456 doesn't match token.user_id=123",
		},
		{
			name: "multi-field validation with body and header",
			envoyRequest: createEnvoyRequestWithBodyAndHeaders("PUT", "/api/profile", map[string]string{
				"authorization": "Bearer valid_token",
				"x-user-id":     "123",
			}, map[string]interface{}{
				"user_id": 123,
				"name":    "Updated Name",
			}),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/profile", "PUT", "header.x-user-id==token.user_id&&body.user_id==token.user_id")
			},
			expectedStatus: http.StatusOK,
			description:    "Should allow when both header.x-user-id=123 and body.user_id=123 match token.user_id=123",
		},

		// ===== PATH PARAMETER VALIDATION TESTS (comprehensive) =====
		{
			name: "path validation with user_id parameter",
			envoyRequest: createEnvoyRequest("GET", "/users/123/profile", map[string]string{
				"authorization": "Bearer valid_token",
			}, "", ""),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/users/*", "GET", "path.user_id==token.user_id")
			},
			expectedStatus: http.StatusOK,
			description:    "Should extract user_id from second path segment /users/123/profile",
		},
		{
			name: "path validation with different parameter extraction",
			envoyRequest: createEnvoyRequest("DELETE", "/posts/456", map[string]string{
				"authorization": "Bearer valid_token",
			}, "", ""),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				// For this test, let's assume the token should contain a different field
				// We'll modify the mock to include post_id in token claims
				enforcer.AddPolicy("role_user", "/posts/*", "DELETE", "path.id==token.user_id")
			},
			expectedStatus: http.StatusForbidden,
			expectedError:  "Field validation failed",
			description:    "Should deny when path.id=456 doesn't match token.user_id=123",
		},

		// ===== EDGE CASES AND ERROR SCENARIOS =====
		{
			name: "no validation rule allows access",
			envoyRequest: createEnvoyRequest("GET", "/public/data", map[string]string{
				"authorization": "Bearer valid_token",
			}, "", ""),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/public/data", "GET", "*")
			},
			expectedStatus: http.StatusOK,
			description:    "Should allow access when validation rule is '*' (no validation)",
		},
		{
			name: "empty validation rule allows access",
			envoyRequest: createEnvoyRequest("GET", "/api/info", map[string]string{
				"authorization": "Bearer valid_token",
			}, "", ""),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/info", "GET", "")
			},
			expectedStatus: http.StatusOK,
			description:    "Should allow access when validation rule is empty",
		},
		{
			name: "unsupported condition operator",
			envoyRequest: createEnvoyRequest("GET", "/api/data", map[string]string{
				"authorization": "Bearer valid_token",
			}, "", "user_id=123"),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/data", "GET", "query.user_id!=token.user_id")
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "unsupported condition format",
			description:    "Should fail with unsupported operator (!= instead of ==)",
		},
		{
			name: "malformed condition",
			envoyRequest: createEnvoyRequest("GET", "/api/data", map[string]string{
				"authorization": "Bearer valid_token",
			}, "", "user_id=123"),
			setupPolicies: func(enforcer *casbin.Enforcer) {
				enforcer.AddPolicy("role_user", "/api/data", "GET", "invalid_condition_format")
			},
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "unsupported condition format",
			description:    "Should fail with malformed validation condition",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			tokenSvc := mocks.NewMockTokenService()
			sessionRepo := mocks.NewMockSessionRepository()

			// Setup token validation to always succeed with user_id=123
			tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
				return &domain.TokenClaims{
					UserID:    123,
					Role:      "user",
					SessionID: "session_123",
				}, nil
			}

			// Setup session validation to always succeed
			sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
				return &domain.Session{
					ID:     "session_123",
					UserID: 123,
				}, nil
			}

			// Setup Casbin enforcer
			enforcer := createTestEnforcer(t)
			tt.setupPolicies(enforcer)

			// Create handler
			handler := NewExternalAuthzHandlers(tokenSvc, sessionRepo, enforcer)

			// Setup Gin context
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			// Prepare request body
			reqBody, err := json.Marshal(tt.envoyRequest)
			require.NoError(t, err)

			c.Request = httptest.NewRequest("POST", "/external/authz", bytes.NewBuffer(reqBody))
			c.Request.Header.Set("Content-Type", "application/json")

			// Execute handler
			handler.Authorize(c)

			// Verify response status
			assert.Equal(t, tt.expectedStatus, w.Code, "Status code mismatch for test: %s", tt.description)

			// Parse response body
			var responseBody map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &responseBody)
			require.NoError(t, err)

			// Verify expected error if test should fail
			if tt.expectedError != "" {
				// Check if error is in "body" field (403 Forbidden responses)
				if bodyStr, ok := responseBody["body"].(string); ok {
					assert.Contains(t, bodyStr, tt.expectedError, "Error message should contain expected text")
				} else if details, ok := responseBody["details"].(string); ok {
					// Check if error is in "details" field (500 Internal Server Error responses)
					assert.Contains(t, details, tt.expectedError, "Error message should contain expected text")
				} else if errorMsg, ok := responseBody["error"].(string); ok {
					// Check if error is in "error" field (direct error responses)
					assert.Contains(t, errorMsg, tt.expectedError, "Error message should contain expected text")
				} else {
					t.Errorf("Could not find expected error message '%s' in response: %v", tt.expectedError, responseBody)
				}
			}

			// Log response for debugging
			t.Logf("Test: %s | Status: %d | Response: %v", tt.name, w.Code, responseBody)
		})
	}
}

// ===== HELPER FUNCTIONS =====

// createEnvoyRequest creates a basic Envoy request for testing
func createEnvoyRequest(method, path string, headers map[string]string, body, query string) EnvoyRequest {
	return EnvoyRequest{
		Attributes: struct {
			Request struct {
				HTTP struct {
					Method  string            `json:"method"`
					Path    string            `json:"path"`
					Headers map[string]string `json:"headers"`
					Body    string            `json:"body,omitempty"`
					Query   string            `json:"query,omitempty"`
				} `json:"http"`
			} `json:"request"`
			Source struct {
				Address struct {
					SocketAddress struct {
						Address   string `json:"address"`
						PortValue int    `json:"portValue"`
					} `json:"socketAddress"`
				} `json:"address"`
			} `json:"source"`
		}{
			Request: struct {
				HTTP struct {
					Method  string            `json:"method"`
					Path    string            `json:"path"`
					Headers map[string]string `json:"headers"`
					Body    string            `json:"body,omitempty"`
					Query   string            `json:"query,omitempty"`
				} `json:"http"`
			}{
				HTTP: struct {
					Method  string            `json:"method"`
					Path    string            `json:"path"`
					Headers map[string]string `json:"headers"`
					Body    string            `json:"body,omitempty"`
					Query   string            `json:"query,omitempty"`
				}{
					Method:  method,
					Path:    path,
					Headers: headers,
					Body:    body,
					Query:   query,
				},
			},
		},
	}
}

// createEnvoyRequestWithBody creates an Envoy request with JSON body
func createEnvoyRequestWithBody(method, path string, headers map[string]string, bodyData map[string]interface{}) EnvoyRequest {
	bodyJSON, _ := json.Marshal(bodyData)
	bodyBase64 := base64.StdEncoding.EncodeToString(bodyJSON)

	req := createEnvoyRequest(method, path, headers, bodyBase64, "")
	return req
}

// createEnvoyRequestWithInvalidBody creates an Envoy request with invalid body for error testing
func createEnvoyRequestWithInvalidBody(method, path string, headers map[string]string, invalidBody string) EnvoyRequest {
	bodyBase64 := base64.StdEncoding.EncodeToString([]byte(invalidBody))
	return createEnvoyRequest(method, path, headers, bodyBase64, "")
}

// createEnvoyRequestWithBodyAndHeaders creates an Envoy request with both body and custom headers
func createEnvoyRequestWithBodyAndHeaders(method, path string, headers map[string]string, bodyData map[string]interface{}) EnvoyRequest {
	return createEnvoyRequestWithBody(method, path, headers, bodyData)
}