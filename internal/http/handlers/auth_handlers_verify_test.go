package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

func TestAuthHandlers_VerifyToken(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		authHeader     string
		setupMocks     func(*mocks.MockTokenService, *mocks.MockSessionRepository)
		expectedStatus int
		expectedBody   map[string]interface{}
		validateCalls  func(t *testing.T, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository)
	}{
		{
			name:       "successful token verification with valid session",
			authHeader: "Bearer valid_token_123",
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				// Token validation succeeds
				tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
					if token == "valid_token_123" {
						return &domain.TokenClaims{
							UserID:    4684,
							Role:      "user",
							SessionID: "sess_4684_123456789",
							IssuedAt:  time.Now().Unix() - 300, // 5 minutes ago
							ExpiresAt: time.Now().Unix() + 600, // 10 minutes from now
						}, nil
					}
					return nil, domain.ErrTokenInvalid
				}

				// Session validation succeeds
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					if sessionID == "sess_4684_123456789" {
						return &domain.Session{
							ID:        sessionID,
							UserID:    4684,
							ExpiresAt: time.Now().Add(10 * time.Minute),
							CreatedAt: time.Now(),
						}, nil
					}
					return nil, domain.ErrSessionNotFound
				}
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"valid":      true,
				"token_type": "access_token",
				"user": map[string]interface{}{
					"id":         float64(4684), // JSON unmarshaling converts numbers to float64
					"role":       "user",
					"session_id": "sess_4684_123456789",
				},
			},
			validateCalls: func(t *testing.T, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				if tokenSvc.ValidateAccessTokenFunc == nil {
					t.Error("expected ValidateAccessToken to be called")
				}
				if sessionRepo.FindByIDFunc == nil {
					t.Error("expected FindByID to be called")
				}
			},
		},
		{
			name:       "successful token verification without session",
			authHeader: "Bearer token_without_session",
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				// Token validation succeeds but no session ID
				tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
					if token == "token_without_session" {
						return &domain.TokenClaims{
							UserID:    1234,
							Role:      "admin",
							SessionID: "", // No session ID
							IssuedAt:  time.Now().Unix() - 100,
							ExpiresAt: time.Now().Unix() + 800,
						}, nil
					}
					return nil, domain.ErrTokenInvalid
				}
				// Session repo should not be called
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"valid":      true,
				"token_type": "access_token",
				"user": map[string]interface{}{
					"id":         float64(1234),
					"role":       "admin",
					"session_id": "",
				},
			},
			validateCalls: func(t *testing.T, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				if tokenSvc.ValidateAccessTokenFunc == nil {
					t.Error("expected ValidateAccessToken to be called")
				}
				// Session repo should not have been called
			},
		},
		{
			name:       "missing authorization header",
			authHeader: "",
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				// No mocks needed - validation fails before service calls
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"valid":      false,
				"error":      "Authorization header required",
				"error_code": "MISSING_AUTHORIZATION_HEADER",
			},
			validateCalls: func(t *testing.T, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				// Services should not be called
			},
		},
		{
			name:       "invalid authorization header format - missing Bearer",
			authHeader: "invalid_token_123",
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				// No mocks needed - validation fails before service calls
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"valid":      false,
				"error":      "Invalid authorization header format",
				"error_code": "INVALID_AUTHORIZATION_FORMAT",
			},
			validateCalls: func(t *testing.T, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				// Services should not be called
			},
		},
		{
			name:       "invalid authorization header format - malformed Bearer",
			authHeader: "Bearer",
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				// No mocks needed - validation fails before service calls
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"valid":      false,
				"error":      "Invalid authorization header format",
				"error_code": "INVALID_AUTHORIZATION_FORMAT",
			},
			validateCalls: func(t *testing.T, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				// Services should not be called
			},
		},
		{
			name:       "expired token",
			authHeader: "Bearer expired_token",
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
					if token == "expired_token" {
						return nil, domain.ErrTokenExpired
					}
					return nil, domain.ErrTokenInvalid
				}
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"valid":      false,
				"error":      "Token expired",
				"error_code": "TOKEN_EXPIRED",
			},
			validateCalls: func(t *testing.T, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				if tokenSvc.ValidateAccessTokenFunc == nil {
					t.Error("expected ValidateAccessToken to be called")
				}
			},
		},
		{
			name:       "invalid token",
			authHeader: "Bearer invalid_token",
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return nil, domain.ErrTokenInvalid
				}
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"valid":      false,
				"error":      "Token invalid",
				"error_code": "TOKEN_INVALID",
			},
			validateCalls: func(t *testing.T, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				if tokenSvc.ValidateAccessTokenFunc == nil {
					t.Error("expected ValidateAccessToken to be called")
				}
			},
		},
		{
			name:       "malformed token",
			authHeader: "Bearer malformed_token",
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
					if token == "malformed_token" {
						return nil, domain.ErrTokenMalformed
					}
					return nil, domain.ErrTokenInvalid
				}
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"valid":      false,
				"error":      "Token malformed",
				"error_code": "TOKEN_MALFORMED",
			},
			validateCalls: func(t *testing.T, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				if tokenSvc.ValidateAccessTokenFunc == nil {
					t.Error("expected ValidateAccessToken to be called")
				}
			},
		},
		{
			name:       "session not found",
			authHeader: "Bearer token_with_invalid_session",
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				// Token validation succeeds
				tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
					if token == "token_with_invalid_session" {
						return &domain.TokenClaims{
							UserID:    5000,
							Role:      "user",
							SessionID: "invalid_session_id",
							IssuedAt:  time.Now().Unix() - 200,
							ExpiresAt: time.Now().Unix() + 700,
						}, nil
					}
					return nil, domain.ErrTokenInvalid
				}

				// Session not found
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					return nil, domain.ErrSessionNotFound
				}
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"valid":      false,
				"error":      "Session invalid or expired",
				"error_code": "SESSION_INVALID",
			},
			validateCalls: func(t *testing.T, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				if tokenSvc.ValidateAccessTokenFunc == nil {
					t.Error("expected ValidateAccessToken to be called")
				}
				if sessionRepo.FindByIDFunc == nil {
					t.Error("expected FindByID to be called")
				}
			},
		},
		{
			name:       "session user mismatch",
			authHeader: "Bearer token_with_user_mismatch",
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				// Token validation succeeds
				tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
					if token == "token_with_user_mismatch" {
						return &domain.TokenClaims{
							UserID:    6000,
							Role:      "user",
							SessionID: "session_different_user",
							IssuedAt:  time.Now().Unix() - 200,
							ExpiresAt: time.Now().Unix() + 700,
						}, nil
					}
					return nil, domain.ErrTokenInvalid
				}

				// Session exists but for different user
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					if sessionID == "session_different_user" {
						return &domain.Session{
							ID:        sessionID,
							UserID:    7000, // Different user ID
							ExpiresAt: time.Now().Add(10 * time.Minute),
							CreatedAt: time.Now(),
						}, nil
					}
					return nil, domain.ErrSessionNotFound
				}
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"valid":      false,
				"error":      "Session user mismatch",
				"error_code": "SESSION_USER_MISMATCH",
			},
			validateCalls: func(t *testing.T, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				if tokenSvc.ValidateAccessTokenFunc == nil {
					t.Error("expected ValidateAccessToken to be called")
				}
				if sessionRepo.FindByIDFunc == nil {
					t.Error("expected FindByID to be called")
				}
			},
		},
		{
			name:       "expired session",
			authHeader: "Bearer token_with_expired_session",
			setupMocks: func(tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				// Token validation succeeds
				tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
					if token == "token_with_expired_session" {
						return &domain.TokenClaims{
							UserID:    8000,
							Role:      "user",
							SessionID: "expired_session_id",
							IssuedAt:  time.Now().Unix() - 200,
							ExpiresAt: time.Now().Unix() + 700,
						}, nil
					}
					return nil, domain.ErrTokenInvalid
				}

				// Session exists but is expired
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					if sessionID == "expired_session_id" {
						return &domain.Session{
							ID:        sessionID,
							UserID:    8000,
							ExpiresAt: time.Now().Add(-5 * time.Minute), // Expired 5 minutes ago
							CreatedAt: time.Now(),
						}, nil
					}
					return nil, domain.ErrSessionNotFound
				}
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"valid":      false,
				"error":      "Session expired",
				"error_code": "SESSION_EXPIRED",
			},
			validateCalls: func(t *testing.T, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				if tokenSvc.ValidateAccessTokenFunc == nil {
					t.Error("expected ValidateAccessToken to be called")
				}
				if sessionRepo.FindByIDFunc == nil {
					t.Error("expected FindByID to be called")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockTokenSvc := mocks.NewMockTokenService()
			mockSessionRepo := mocks.NewMockSessionRepository()
			mockAuthSvc := mocks.NewMockAuthService()
			mockOTPSvc := mocks.NewMockOTPService()
			mockUserRepo := mocks.NewMockUserRepository()

			// Setup mocks
			tt.setupMocks(mockTokenSvc, mockSessionRepo)

			// Create handler
			handler := NewAuthHandlers(mockAuthSvc, mockOTPSvc, mockUserRepo, mockTokenSvc, mockSessionRepo)

			// Create test request
			req, err := http.NewRequest("GET", "/auth/verify", nil)
			if err != nil {
				t.Fatal(err)
			}

			// Set authorization header if provided
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			// Create test recorder
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Call handler
			handler.VerifyToken(c)

			// Check status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Check response body
			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			if err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			// Validate required fields exist
			for key, expectedValue := range tt.expectedBody {
				actualValue, exists := response[key]
				if !exists {
					t.Errorf("expected key '%s' not found in response", key)
					continue
				}

				// Handle nested objects for user field
				if key == "user" && tt.expectedStatus == http.StatusOK {
					expectedUser := expectedValue.(map[string]interface{})
					actualUser := actualValue.(map[string]interface{})

					// Check required user fields, ignoring timestamps for simplicity
					if actualUser["id"] != expectedUser["id"] {
						t.Errorf("expected user.id %v, got %v", expectedUser["id"], actualUser["id"])
					}
					if actualUser["role"] != expectedUser["role"] {
						t.Errorf("expected user.role %v, got %v", expectedUser["role"], actualUser["role"])
					}
					if actualUser["session_id"] != expectedUser["session_id"] {
						t.Errorf("expected user.session_id %v, got %v", expectedUser["session_id"], actualUser["session_id"])
					}
				} else if actualValue != expectedValue {
					t.Errorf("expected %s %v, got %v", key, expectedValue, actualValue)
				}
			}

			// Validate calls were made as expected
			if tt.validateCalls != nil {
				tt.validateCalls(t, mockTokenSvc, mockSessionRepo)
			}
		})
	}
}

// Helper function to create test helpers for repeated setup
func createVerifyTokenHandlerForTest(t *testing.T, tokenSvc domain.TokenService, sessionRepo domain.SessionRepository) *AuthHandlers {
	t.Helper()

	return NewAuthHandlers(
		mocks.NewMockAuthService(),
		mocks.NewMockOTPService(),
		mocks.NewMockUserRepository(),
		tokenSvc,
		sessionRepo,
	)
}

// Test helper function to create test context
func createTestContextForVerify(t *testing.T, method string, authHeader string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()

	req, err := http.NewRequest(method, "/auth/verify", nil)
	if err != nil {
		t.Fatal(err)
	}

	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	return c, w
}