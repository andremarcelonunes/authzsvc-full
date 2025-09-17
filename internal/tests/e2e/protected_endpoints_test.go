package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/you/authzsvc/domain"
)

// TestProtectedEndpoints tests all protected endpoints requiring authentication
func TestProtectedEndpoints(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)

	helper.MustStart()
	helper.MustWaitForReady()

	// Create authenticated test users
	
	// Regular user
	userFactory := NewTestUserFactory(t, suite.DB)
	userOpts := DefaultTestUser()
	userOpts.PhoneVerified = true
	userOpts.Role = "user"
	regularUser := userFactory.CreateUserT(userOpts)
	
	// Admin user
	adminOpts := AdminTestUser()
	adminOpts.PhoneVerified = true
	adminUser := userFactory.CreateUserT(adminOpts)

	// Cleanup users
	defer func() {
		suite.DB.Delete(regularUser)
		suite.DB.Delete(adminUser)
	}()

	tests := []struct {
		name           string
		method         string
		path           string
		user           *domain.User
		password       string
		requestBody    map[string]interface{}
		expectedStatus int
		requiresAuth   bool
		requiresAdmin  bool
		validateFunc   func(t *testing.T, respBody map[string]interface{}, user *domain.User)
	}{
		{
			name:           "GET /auth/me returns current user profile",
			method:         "GET",
			path:           "/auth/me",
			user:           regularUser,
			password:       userOpts.Password,
			expectedStatus: http.StatusOK,
			requiresAuth:   true,
			requiresAdmin:  false,
			validateFunc: func(t *testing.T, respBody map[string]interface{}, user *domain.User) {
				assert.Equal(t, float64(user.ID), respBody["id"])
				assert.Equal(t, user.Email, respBody["email"])
				assert.Equal(t, user.Phone, respBody["phone"])
				assert.Equal(t, user.Role, respBody["role"])
				assert.Equal(t, user.IsActive, respBody["is_active"])
				assert.Equal(t, user.PhoneVerified, respBody["phone_verified"])
				assert.Contains(t, respBody, "created_at")
				assert.Contains(t, respBody, "updated_at")
			},
		},
		{
			name:           "POST /auth/logout invalidates session",
			method:         "POST",
			path:           "/auth/logout",
			user:           regularUser,
			password:       userOpts.Password,
			expectedStatus: http.StatusOK,
			requiresAuth:   true,
			requiresAdmin:  false,
			validateFunc: func(t *testing.T, respBody map[string]interface{}, user *domain.User) {
				assert.Contains(t, respBody["message"], "Logged out successfully")
			},
		},
		{
			name:           "POST /auth/refresh rotates access token",
			method:         "POST",
			path:           "/auth/refresh",
			user:           regularUser,
			password:       userOpts.Password,
			expectedStatus: http.StatusOK,
			requiresAuth:   false, // Uses refresh token, not access token
			requiresAdmin:  false,
			validateFunc: func(t *testing.T, respBody map[string]interface{}, user *domain.User) {
				assert.Contains(t, respBody, "access_token")
				assert.Contains(t, respBody, "token_type")
				assert.Contains(t, respBody, "expires_in")
				assert.Equal(t, "Bearer", respBody["token_type"])
				
				// New access token should be valid JWT
				accessToken := respBody["access_token"].(string)
				assert.True(t, strings.HasPrefix(accessToken, "eyJ"))
			},
		},
		{
			name:           "GET /admin/policies requires admin role",
			method:         "GET",
			path:           "/admin/policies",
			user:           adminUser,
			password:       adminOpts.Password,
			expectedStatus: http.StatusOK,
			requiresAuth:   true,
			requiresAdmin:  true,
		},
		{
			name:           "GET /admin/policies denies regular user",
			method:         "GET",
			path:           "/admin/policies",
			user:           regularUser,
			password:       userOpts.Password,
			expectedStatus: http.StatusForbidden,
			requiresAuth:   true,
			requiresAdmin:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Get authentication tokens if required
			var accessToken, refreshToken, sessionID string
			if tt.requiresAuth || tt.path == "/auth/refresh" {
				tokens := loginUser(t, helper, tt.user.Email, tt.password)
				
				// Safely extract tokens
				if accessTokenVal, ok := tokens["access_token"]; ok && accessTokenVal != nil {
					accessToken = accessTokenVal.(string)
				}
				if refreshTokenVal, ok := tokens["refresh_token"]; ok && refreshTokenVal != nil {
					refreshToken = refreshTokenVal.(string)
				}
				
				// Extract session ID from access token
				token, _ := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
					return []byte(suite.Config.JWTSecret), nil
				})
				claims := token.Claims.(jwt.MapClaims)
				sessionID = claims["session_id"].(string)
			}

			// Prepare request body
			var body []byte
			if tt.requestBody != nil {
				body, _ = json.Marshal(tt.requestBody)
			} else if tt.path == "/auth/refresh" {
				// Special case for refresh endpoint
				refreshBody := map[string]string{"refresh_token": refreshToken}
				body, _ = json.Marshal(refreshBody)
			}

			// Create request
			var req *http.Request
			if body != nil {
				req, _ = http.NewRequest(tt.method, helper.URL(tt.path), bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
			} else {
				req, _ = http.NewRequest(tt.method, helper.URL(tt.path), nil)
			}

			// Add authorization header if required
			if tt.requiresAuth && accessToken != "" {
				req.Header.Set("Authorization", "Bearer "+accessToken)
			}

			// Make request and measure performance
			start := time.Now()
			resp := helper.DoRequest(req)
			duration := time.Since(start)

			// Validate performance
			assert.Less(t, duration, 100*time.Millisecond, 
				"Protected endpoint %s should respond in < 100ms, took %v", tt.path, duration)

			// Validate response status
			assert.Equal(t, tt.expectedStatus, resp.StatusCode, 
				"Expected status %d for %s %s, got %d", 
				tt.expectedStatus, tt.method, tt.path, resp.StatusCode)

			// Parse response if successful
			if resp.StatusCode < 300 && tt.validateFunc != nil {
				// Special handling for admin policies endpoint which returns array
				if tt.path == "/admin/policies" {
					var policies [][]string
					err := json.NewDecoder(resp.Body).Decode(&policies)
					require.NoError(t, err)
					// Admin policies tests don't have validateFunc, so this won't be called
					// but we still parse to ensure valid JSON format
				} else {
					var respBody map[string]interface{}
					err := json.NewDecoder(resp.Body).Decode(&respBody)
					require.NoError(t, err)
					
					// Extract data from nested response structure for validation
					data, hasData := respBody["data"].(map[string]interface{})
					if hasData {
						tt.validateFunc(t, data, tt.user)
					} else {
						// Fallback for responses without data wrapper
						tt.validateFunc(t, respBody, tt.user)
					}
				}
			}
			resp.Body.Close()

			// Verify logout actually invalidates session
			if tt.path == "/auth/logout" && resp.StatusCode == http.StatusOK {
				ctx := context.Background()
				sessionKey := suite.GetRedisKey(fmt.Sprintf("session:%s", sessionID))
				
				// Session should be deleted from Redis
				exists, err := suite.Redis.Exists(ctx, sessionKey).Result()
				require.NoError(t, err)
				assert.Zero(t, exists, "Session should be deleted after logout")
			}
		})
	}

	server.ValidatePerformance(t)
}

// TestAuthenticationMiddleware tests JWT authentication middleware behavior
func TestAuthenticationMiddleware(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)

	helper.MustStart()
	helper.MustWaitForReady()

	// Create test user
	userFactory := NewTestUserFactory(t, suite.DB)
	opts := DefaultTestUser()
	opts.PhoneVerified = true
	user := userFactory.CreateUserT(opts)
	defer suite.DB.Delete(user)

	// Get valid token
	tokens := loginUser(t, helper, user.Email, opts.Password)
	validToken := tokens["access_token"].(string)

	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "valid token allows access",
			authHeader:     "Bearer " + validToken,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "missing authorization header denies access",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "authorization header required",
		},
		{
			name:           "invalid token format denies access",
			authHeader:     "InvalidFormat",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid authorization header format",
		},
		{
			name:           "malformed JWT denies access",
			authHeader:     "Bearer invalid.jwt.token",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid token",
		},
		{
			name:           "expired token denies access",
			authHeader:     "Bearer " + createExpiredToken(t, suite.Config.JWTSecret, user.ID),
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid token",
		},
		{
			name:           "token with invalid signature denies access",
			authHeader:     "Bearer " + createInvalidSignatureToken(t, user.ID),
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", helper.URL("/auth/me"), nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			start := time.Now()
			resp := helper.DoRequest(req)
			duration := time.Since(start)

			// Authentication should be fast
			assert.Less(t, duration, 50*time.Millisecond, 
				"Authentication middleware should be fast, took %v", duration)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			if tt.expectedStatus != http.StatusOK && tt.expectedError != "" {
				var respBody map[string]interface{}
				json.NewDecoder(resp.Body).Decode(&respBody)
				
				if errorMsg, ok := respBody["error"].(string); ok {
					assert.Contains(t, strings.ToLower(errorMsg), strings.ToLower(tt.expectedError))
				}
			}
			
			resp.Body.Close()
		})
	}
}

// TestAuthorizationMiddleware tests Casbin RBAC authorization middleware
func TestAuthorizationMiddleware(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)

	helper.MustStart()
	helper.MustWaitForReady()

	// Create users with different roles
	userFactory := NewTestUserFactory(t, suite.DB)
	
	// Regular user
	userOpts := DefaultTestUser()
	userOpts.PhoneVerified = true
	userOpts.Role = "user"
	regularUser := userFactory.CreateUserT(userOpts)
	
	// Admin user
	adminOpts := AdminTestUser()
	adminOpts.PhoneVerified = true
	adminUser := userFactory.CreateUserT(adminOpts)

	defer func() {
		suite.DB.Delete(regularUser)
		suite.DB.Delete(adminUser)
	}()

	authTests := []struct {
		name           string
		user           *domain.User
		password       string
		method         string
		path           string
		expectedStatus int
		description    string
	}{
		{
			name:           "admin can access admin endpoints",
			user:           adminUser,
			password:       adminOpts.Password,
			method:         "GET",
			path:           "/admin/policies",
			expectedStatus: http.StatusOK,
			description:    "Admin user should access admin-only endpoints",
		},
		{
			name:           "regular user cannot access admin endpoints",
			user:           regularUser,
			password:       userOpts.Password,
			method:         "GET",
			path:           "/admin/policies",
			expectedStatus: http.StatusForbidden,
			description:    "Regular user should be denied admin endpoints",
		},
		{
			name:           "regular user can access user endpoints",
			user:           regularUser,
			password:       userOpts.Password,
			method:         "GET",
			path:           "/auth/me",
			expectedStatus: http.StatusOK,
			description:    "Regular user should access user endpoints",
		},
		{
			name:           "admin can also access user endpoints",
			user:           adminUser,
			password:       adminOpts.Password,
			method:         "GET",
			path:           "/auth/me",
			expectedStatus: http.StatusOK,
			description:    "Admin should inherit user permissions",
		},
	}

	for _, tt := range authTests {
		t.Run(tt.name, func(t *testing.T) {
			// Login and get token
			tokens := loginUser(t, helper, tt.user.Email, tt.password)
			
			// Safely extract access token
			accessTokenVal, exists := tokens["access_token"]
			require.True(t, exists, "Response should contain access_token")
			require.NotNil(t, accessTokenVal, "access_token should not be nil")
			accessToken, ok := accessTokenVal.(string)
			require.True(t, ok, "access_token should be a string")

			// Make authorized request
			req, _ := http.NewRequest(tt.method, helper.URL(tt.path), nil)
			req.Header.Set("Authorization", "Bearer "+accessToken)

			start := time.Now()
			resp := helper.DoRequest(req)
			duration := time.Since(start)

			// Authorization should be fast
			assert.Less(t, duration, 100*time.Millisecond, 
				"Authorization should be fast, took %v", duration)

			assert.Equal(t, tt.expectedStatus, resp.StatusCode, tt.description)
			resp.Body.Close()
		})
	}
}

// TestTokenRefresh tests the token refresh mechanism
func TestTokenRefresh(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)

	helper.MustStart()
	helper.MustWaitForReady()

	// Create test user
	userFactory := NewTestUserFactory(t, suite.DB)
	opts := DefaultTestUser()
	opts.PhoneVerified = true
	user := userFactory.CreateUserT(opts)
	defer suite.DB.Delete(user)

	t.Run("valid refresh token generates new access token", func(t *testing.T) {
		// Initial login
		tokens := loginUser(t, helper, user.Email, opts.Password)
		originalAccessToken, ok := tokens["access_token"].(string)
		require.True(t, ok, "access_token should be present and be a string")
		refreshToken, ok := tokens["refresh_token"].(string)
		require.True(t, ok, "refresh_token should be present and be a string")

		// Small delay to ensure new token has different timestamp
		time.Sleep(100 * time.Millisecond)

		// Refresh token
		reqBody := map[string]string{"refresh_token": refreshToken}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", helper.URL("/auth/refresh"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		start := time.Now()
		resp := helper.DoRequest(req)
		duration := time.Since(start)

		// Refresh should be fast
		assert.Less(t, duration, 100*time.Millisecond, 
			"Token refresh should be fast, took %v", duration)

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var respBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&respBody)
		resp.Body.Close()

		// Extract data from nested response structure
		data, ok := respBody["data"].(map[string]interface{})
		require.True(t, ok, "Response should have data field with tokens")

		// Validate response
		assert.Contains(t, data, "access_token")
		assert.Contains(t, data, "token_type")
		assert.Contains(t, data, "expires_in")
		assert.Equal(t, "Bearer", data["token_type"])

		// New access token should be different
		newAccessToken := data["access_token"].(string)
		assert.NotEqual(t, originalAccessToken, newAccessToken, "New access token should be different")

		// New token should be valid
		req, _ = http.NewRequest("GET", helper.URL("/auth/me"), nil)
		req.Header.Set("Authorization", "Bearer "+newAccessToken)

		resp = helper.DoRequest(req)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "New access token should be valid")
		resp.Body.Close()
	})

	t.Run("invalid refresh token fails", func(t *testing.T) {
		reqBody := map[string]string{"refresh_token": "invalid.refresh.token"}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", helper.URL("/auth/refresh"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		resp := helper.DoRequest(req)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

		var respBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&respBody)
		resp.Body.Close()

		assert.Contains(t, respBody, "error")
	})

	t.Run("expired refresh token fails", func(t *testing.T) {
		// Create expired refresh token
		expiredToken := createExpiredRefreshToken(t, suite.Config.JWTSecret, user.ID)
		
		reqBody := map[string]string{"refresh_token": expiredToken}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", helper.URL("/auth/refresh"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		resp := helper.DoRequest(req)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})
}

// Helper functions

// loginUser performs login and returns tokens
func loginUser(t *testing.T, helper *ServerTestHelper, email, password string) map[string]interface{} {
	t.Helper()

	reqBody := map[string]string{
		"email":    email,
		"password": password,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", helper.URL("/auth/login"), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp := helper.DoRequest(req)
	
	// Debug failed login attempts
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("Login failed for %s with status %d: %s", email, resp.StatusCode, string(bodyBytes))
		require.Equal(t, http.StatusOK, resp.StatusCode, "Login should succeed")
	}

	var respBody map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&respBody)
	resp.Body.Close()

	// Handle nested response structure like {"data": {"access_token": "..."}}
	if data, ok := respBody["data"].(map[string]interface{}); ok {
		return data
	}

	// If no nested structure, return as-is
	return respBody
}

// createExpiredToken creates an expired JWT token for testing
func createExpiredToken(t *testing.T, secret string, userID uint) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    fmt.Sprintf("%d", userID),
		"email":      "test@example.com",
		"role":       "user",
		"session_id": "test_session",
		"exp":        time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		"iat":        time.Now().Add(-2 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)
	return tokenString
}

// createExpiredRefreshToken creates an expired refresh token for testing
func createExpiredRefreshToken(t *testing.T, secret string, userID uint) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    fmt.Sprintf("%d", userID),
		"session_id": "test_session",
		"type":       "refresh",
		"exp":        time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
		"iat":        time.Now().Add(-2 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString([]byte(secret))
	require.NoError(t, err)
	return tokenString
}

// createInvalidSignatureToken creates a token with invalid signature for testing
func createInvalidSignatureToken(t *testing.T, userID uint) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id":    fmt.Sprintf("%d", userID),
		"email":      "test@example.com",
		"role":       "user",
		"session_id": "test_session",
		"exp":        time.Now().Add(1 * time.Hour).Unix(),
		"iat":        time.Now().Unix(),
	})

	// Sign with wrong secret
	tokenString, err := token.SignedString([]byte("wrong_secret"))
	require.NoError(t, err)
	return tokenString
}