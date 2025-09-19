package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

func TestExternalAuthzHandlers_Authorize(t *testing.T) {
	tests := []struct {
		name           string
		envoyRequest   EnvoyRequest
		setupMocks     func(*mocks.MockTokenService, *mocks.MockSessionRepository, *casbin.Enforcer)
		expectedStatus int
		expectedBody   map[string]interface{}
	}{
		{
			name: "successful authorization with valid token and permissions",
			envoyRequest: EnvoyRequest{
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
							Method: "GET",
							Path:   "/auth/me",
							Headers: map[string]string{
								"authorization": "Bearer valid_token",
							},
						},
					},
				},
			},
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository, enforcer *casbin.Enforcer) {
				// Token validation succeeds
				tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return &domain.TokenClaims{
						UserID:    123,
						Role:      "user",
						SessionID: "session_123",
					}, nil
				}
				
				// Session validation succeeds
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					return &domain.Session{
						ID:     "session_123",
						UserID: 123,
					}, nil
				}
				
				// Add policy for user role to access /auth/me
				enforcer.AddPolicy("role_user", "/auth/me", "GET", "*")
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"status": map[string]interface{}{
					"code": float64(200),
				},
				"headers": map[string]interface{}{
					"x-user-id":   "123",
					"x-user-role": "user",
				},
			},
		},
		{
			name: "unauthorized - missing authorization header",
			envoyRequest: EnvoyRequest{
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
							Method:  "GET",
							Path:    "/auth/me",
							Headers: map[string]string{},
						},
					},
				},
			},
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository, enforcer *casbin.Enforcer) {
				// No mocks needed for this test case
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"status": map[string]interface{}{
					"code": float64(401),
				},
				"body": `{"error": "Authorization header required"}`,
			},
		},
		{
			name: "unauthorized - invalid token",
			envoyRequest: EnvoyRequest{
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
							Method: "GET",
							Path:   "/auth/me",
							Headers: map[string]string{
								"authorization": "Bearer invalid_token",
							},
						},
					},
				},
			},
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository, enforcer *casbin.Enforcer) {
				// Token validation fails
				tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return nil, domain.ErrTokenInvalid
				}
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"status": map[string]interface{}{
					"code": float64(401),
				},
				"body": `{"error": "Invalid token"}`,
			},
		},
		{
			name: "forbidden - no permission for endpoint",
			envoyRequest: EnvoyRequest{
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
							Method: "GET",
							Path:   "/admin/policies",
							Headers: map[string]string{
								"authorization": "Bearer valid_token",
							},
						},
					},
				},
			},
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository, enforcer *casbin.Enforcer) {
				// Token validation succeeds
				tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return &domain.TokenClaims{
						UserID:    123,
						Role:      "user",
						SessionID: "session_123",
					}, nil
				}
				
				// Session validation succeeds
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					return &domain.Session{
						ID:     "session_123",
						UserID: 123,
					}, nil
				}
				
				// No policy for user role to access /admin/policies
				// (enforcer starts empty)
			},
			expectedStatus: http.StatusForbidden,
			expectedBody: map[string]interface{}{
				"status": map[string]interface{}{
					"code": float64(403),
				},
				"body": `{"error": "Access denied"}`,
			},
		},
		{
			name: "successful authorization with field validation",
			envoyRequest: EnvoyRequest{
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
							Method: "GET",
							Path:   "/users/123",
							Headers: map[string]string{
								"authorization": "Bearer valid_token",
							},
						},
					},
				},
			},
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository, enforcer *casbin.Enforcer) {
				// Token validation succeeds
				tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return &domain.TokenClaims{
						UserID:    123,
						Role:      "user",
						SessionID: "session_123",
					}, nil
				}
				
				// Session validation succeeds
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					return &domain.Session{
						ID:     "session_123",
						UserID: 123,
					}, nil
				}
				
				// Add policy with field validation: user can only access their own user data
				enforcer.AddPolicy("role_user", "/users/*", "GET", "path.id==token.user_id")
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"status": map[string]interface{}{
					"code": float64(200),
				},
				"headers": map[string]interface{}{
					"x-user-id":   "123",
					"x-user-role": "user",
				},
			},
		},
		{
			name: "forbidden - field validation fails",
			envoyRequest: EnvoyRequest{
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
							Method: "GET",
							Path:   "/users/456", // Different user ID
							Headers: map[string]string{
								"authorization": "Bearer valid_token",
							},
						},
					},
				},
			},
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository, enforcer *casbin.Enforcer) {
				// Token validation succeeds
				tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return &domain.TokenClaims{
						UserID:    123, // Token belongs to user 123
						Role:      "user",
						SessionID: "session_123",
					}, nil
				}
				
				// Session validation succeeds
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					return &domain.Session{
						ID:     "session_123",
						UserID: 123,
					}, nil
				}
				
				// Add policy with field validation: user can only access their own user data
				enforcer.AddPolicy("role_user", "/users/*", "GET", "path.id==token.user_id")
			},
			expectedStatus: http.StatusForbidden,
			expectedBody: map[string]interface{}{
				"status": map[string]interface{}{
					"code": float64(403),
				},
				"body": `{"error": "Field validation failed: Request values do not match token claims"}`,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			tokenSvc := mocks.NewMockTokenService()
			sessionRepo := mocks.NewMockSessionRepository()
			
			// Setup Casbin enforcer with in-memory model
			enforcer := createTestEnforcer(t)
			
			// Setup test-specific mocks
			tt.setupMocks(tokenSvc, sessionRepo, enforcer)
			
			// Create handler
			handler := NewExternalAuthzHandlers(tokenSvc, sessionRepo, enforcer)
			
			// Setup Gin context
			gin.SetMode(gin.TestMode)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			
			// Prepare request body
			reqBody, err := json.Marshal(tt.envoyRequest)
			if err != nil {
				t.Fatalf("Failed to marshal request: %v", err)
			}
			
			c.Request = httptest.NewRequest("POST", "/external/authz", bytes.NewBuffer(reqBody))
			c.Request.Header.Set("Content-Type", "application/json")
			
			// Execute handler
			handler.Authorize(c)
			
			// Verify response status
			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
			
			// Verify response body
			var responseBody map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &responseBody)
			if err != nil {
				t.Fatalf("Failed to unmarshal response body: %v", err)
			}
			
			// Compare expected and actual response
			if !compareJSON(t, tt.expectedBody, responseBody) {
				t.Errorf("Response body mismatch.\nExpected: %+v\nActual: %+v", tt.expectedBody, responseBody)
			}
		})
	}
}

func TestExternalAuthzHandlers_Health(t *testing.T) {
	// Create handler with minimal dependencies (health check doesn't need them)
	handler := &ExternalAuthzHandlers{}
	
	// Setup Gin context
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	
	c.Request = httptest.NewRequest("GET", "/external/health", nil)
	
	// Execute handler
	handler.Health(c)
	
	// Verify response
	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
	
	var responseBody map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &responseBody)
	if err != nil {
		t.Fatalf("Failed to unmarshal response body: %v", err)
	}
	
	expectedResponse := map[string]interface{}{
		"status":  "healthy",
		"service": "external-authz",
		"version": "1.0.0",
	}
	
	if !compareJSON(t, expectedResponse, responseBody) {
		t.Errorf("Response body mismatch.\nExpected: %+v\nActual: %+v", expectedResponse, responseBody)
	}
}

// Helper functions

func createTestEnforcer(t *testing.T) *casbin.Enforcer {
	t.Helper()
	
	// Create in-memory model for testing
	modelText := `
[request_definition]
r = sub, obj, act, field

[policy_definition]
p = sub, obj, act, field

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`
	
	m, err := model.NewModelFromString(modelText)
	if err != nil {
		t.Fatalf("Failed to create Casbin model: %v", err)
	}
	
	enforcer, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatalf("Failed to create Casbin enforcer: %v", err)
	}
	
	return enforcer
}

func compareJSON(t *testing.T, expected, actual map[string]interface{}) bool {
	t.Helper()
	
	expectedJSON, _ := json.Marshal(expected)
	actualJSON, _ := json.Marshal(actual)
	
	return string(expectedJSON) == string(actualJSON)
}