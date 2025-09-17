package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/you/authzsvc/domain"
)

// TestLoginFlow tests the complete user login flow E2E
func TestLoginFlow(t *testing.T) {
	// Get test suite and create test server
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)

	// Start server
	helper.MustStart()
	helper.MustWaitForReady()

	// Test data fixtures will be created per test as needed

	tests := []struct {
		name               string
		setupUser          func() (*domain.User, string) // Returns user and plain password
		email              string
		password           string
		expectedStatus     int
		expectTokens       bool
		expectSession      bool
		expectedError      string
		validateTokens     func(t *testing.T, accessToken, refreshToken string)
		validateSession    func(t *testing.T, user *domain.User, sessionID string)
	}{
		{
			name: "successful login creates tokens and session",
			setupUser: func() (*domain.User, string) {
				userFactory := NewTestUserFactory(t, suite.DB)
				opts := DefaultTestUser()
				opts.PhoneVerified = true // Ensure phone is verified
				user := userFactory.CreateUserT(opts)
				return user, opts.Password
			},
			expectedStatus: http.StatusOK,
			expectTokens:   true,
			expectSession:  true,
			validateTokens: func(t *testing.T, accessToken, refreshToken string) {
				t.Helper()
				
				// Validate access token structure
				assert.NotEmpty(t, accessToken, "Access token should not be empty")
				assert.True(t, strings.HasPrefix(accessToken, "eyJ"), "Access token should be JWT format")
				
				// Parse and validate JWT claims
				token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
					return []byte(suite.Config.JWTSecret), nil
				})
				require.NoError(t, err, "Access token should be valid JWT")
				
				claims, ok := token.Claims.(jwt.MapClaims)
				require.True(t, ok, "Token should have valid claims")
				
				// Validate required claims - based on actual JWT structure from documentation
				assert.Contains(t, claims, "user_id", "Token should contain user_id")
				assert.Contains(t, claims, "role", "Token should contain role")
				assert.Contains(t, claims, "exp", "Token should contain expiration")
				assert.Contains(t, claims, "iat", "Token should contain issued at")
				assert.Contains(t, claims, "session_id", "Token should contain session_id")
				assert.Contains(t, claims, "iss", "Token should contain issuer")
				assert.Contains(t, claims, "jti", "Token should contain JWT ID")
				
				// Validate token expiration
				exp := int64(claims["exp"].(float64))
				assert.Greater(t, exp, time.Now().Unix(), "Token should not be expired")
				
				// Validate refresh token
				assert.NotEmpty(t, refreshToken, "Refresh token should not be empty")
				assert.NotEqual(t, accessToken, refreshToken, "Refresh token should be different from access token")
			},
			validateSession: func(t *testing.T, user *domain.User, sessionID string) {
				t.Helper()
				
				// Verify session stored in Redis - check main namespace since app creates sessions
				ctx := context.Background()
				sessionKey := fmt.Sprintf("session:%s", sessionID)
				
				sessionData, err := suite.Redis.Get(ctx, sessionKey).Result()
				require.NoError(t, err, "Session should exist in Redis")
				
				// Parse session JSON data - based on actual session format from documentation
				var session map[string]interface{}
				err = json.Unmarshal([]byte(sessionData), &session)
				require.NoError(t, err, "Session data should be valid JSON")
				
				// Validate session content
				assert.Equal(t, float64(user.ID), session["UserID"], "Session should contain correct user ID")
				assert.Equal(t, sessionID, session["ID"], "Session should contain correct session ID")
				assert.Contains(t, session, "ExpiresAt", "Session should have expiration")
				assert.Contains(t, session, "CreatedAt", "Session should have creation time")
			},
		},
		{
			name: "login with unverified phone fails",
			setupUser: func() (*domain.User, string) {
				userFactory := NewTestUserFactory(t, suite.DB)
				opts := DefaultTestUser()
				opts.PhoneVerified = false // Phone not verified
				user := userFactory.CreateUserT(opts)
				return user, opts.Password
			},
			expectedStatus: http.StatusForbidden,
			expectTokens:   false,
			expectSession:  false,
			expectedError:  "Phone number not verified",
		},
		{
			name: "login with inactive user fails",
			setupUser: func() (*domain.User, string) {
				userFactory := NewTestUserFactory(t, suite.DB)
				opts := DefaultTestUser()
				opts.IsActive = false // User inactive
				opts.PhoneVerified = true
				user := userFactory.CreateUserT(opts)
				return user, opts.Password
			},
			expectedStatus: http.StatusForbidden,
			expectTokens:   false,
			expectSession:  false,
			expectedError:  "Account is inactive",
		},
		{
			name: "login with wrong password fails",
			setupUser: func() (*domain.User, string) {
				userFactory := NewTestUserFactory(t, suite.DB)
				opts := DefaultTestUser()
				opts.PhoneVerified = true
				user := userFactory.CreateUserT(opts)
				return user, "WrongPassword123!"
			},
			expectedStatus: http.StatusUnauthorized,
			expectTokens:   false,
			expectSession:  false,
			expectedError:  "Invalid credentials",
		},
		{
			name: "login with non-existent email fails",
			setupUser: func() (*domain.User, string) {
				return &domain.User{Email: "nonexistent@test.com"}, "password"
			},
			expectedStatus: http.StatusUnauthorized,
			expectTokens:   false,
			expectSession:  false,
			expectedError:  "Invalid credentials",
		},
		{
			name: "login with invalid email format fails",
			setupUser: func() (*domain.User, string) {
				return &domain.User{Email: "invalid-email"}, "password"
			},
			expectedStatus: http.StatusBadRequest,
			expectTokens:   false,
			expectSession:  false,
			expectedError:  "Error:Field validation for",
		},
		{
			name: "login with missing password fails",
			setupUser: func() (*domain.User, string) {
				return &domain.User{Email: generateTestEmail()}, ""
			},
			expectedStatus: http.StatusBadRequest,
			expectTokens:   false,
			expectSession:  false,
			expectedError:  "Error:Field validation for",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test user
			user, password := tt.setupUser()
			
			// Override email/password if provided in test case
			if tt.email != "" {
				user.Email = tt.email
			}
			if tt.password != "" {
				password = tt.password
			}

			// Create login request
			reqBody := map[string]string{
				"email":    user.Email,
				"password": password,
			}
			body, err := json.Marshal(reqBody)
			require.NoError(t, err)

			// Make login request
			req, err := http.NewRequest("POST", helper.URL("/auth/login"), bytes.NewBuffer(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")

			start := time.Now()
			resp := helper.DoRequest(req)
			duration := time.Since(start)

			// Validate performance: login should complete in < 100ms
			assert.Less(t, duration, 100*time.Millisecond, 
				"Login endpoint should respond in < 100ms, took %v", duration)

			// Validate response status
			assert.Equal(t, tt.expectedStatus, resp.StatusCode, 
				"Expected status %d, got %d", tt.expectedStatus, resp.StatusCode)

			// Parse response
			var respBody map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&respBody)
			require.NoError(t, err)
			resp.Body.Close()

			if tt.expectedStatus == http.StatusOK {
				// Extract data from nested response structure
				assert.Contains(t, respBody, "data", "Response should contain data field")
				data := respBody["data"].(map[string]interface{})
				
				// Successful login - check data fields
				assert.Contains(t, data, "access_token", "Response should contain access_token")
				assert.Contains(t, data, "refresh_token", "Response should contain refresh_token")
				assert.Contains(t, data, "token_type", "Response should contain token_type")
				assert.Contains(t, data, "expires_in", "Response should contain expires_in")
				assert.Contains(t, data, "user", "Response should contain user info")
				
				assert.Equal(t, "Bearer", data["token_type"], "Token type should be Bearer")
				
				// Validate user info
				userInfo := data["user"].(map[string]interface{})
				assert.Equal(t, float64(user.ID), userInfo["id"], "User ID should match")
				assert.Equal(t, user.Email, userInfo["email"], "Email should match")
				assert.Equal(t, user.Role, userInfo["role"], "Role should match")

				// Token validations
				if tt.validateTokens != nil {
					accessToken := data["access_token"].(string)
					refreshToken := data["refresh_token"].(string)
					tt.validateTokens(t, accessToken, refreshToken)

					// Extract session ID from access token for session validation
					token, _ := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
						return []byte(suite.Config.JWTSecret), nil
					})
					claims := token.Claims.(jwt.MapClaims)
					sessionID := claims["session_id"].(string)

					if tt.validateSession != nil {
						tt.validateSession(t, user, sessionID)
					}
				}
			} else {
				// Error cases
				assert.Contains(t, respBody, "error", "Error response should contain error field")
				if tt.expectedError != "" {
					errorStr, ok := respBody["error"].(string)
					require.True(t, ok, "Error should be string")
					assert.Contains(t, errorStr, tt.expectedError, 
						"Error message should contain: %s", tt.expectedError)
				}

				// Verify no tokens or sessions created
				assert.NotContains(t, respBody, "access_token", "No access token should be returned on error")
				assert.NotContains(t, respBody, "refresh_token", "No refresh token should be returned on error")
			}

			// Cleanup: Remove test user if it was created
			if user.ID != 0 {
				suite.DB.Delete(user)
			}
		})
	}

	// Validate overall server performance
	server.ValidatePerformance(t)
}

// TestLoginPerformance tests login performance under various conditions
func TestLoginPerformance(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)

	helper.MustStart()
	helper.MustWaitForReady()

	// Create a verified test user for performance testing
	userFactory := NewTestUserFactory(t, suite.DB)
	opts := DefaultTestUser()
	opts.PhoneVerified = true
	user := userFactory.CreateUserT(opts)
	defer suite.DB.Delete(user)

	t.Run("multiple logins for same user perform consistently", func(t *testing.T) {
		const numLogins = 10
		durations := make([]time.Duration, numLogins)

		reqBody := map[string]string{
			"email":    user.Email,
			"password": opts.Password,
		}
		body, _ := json.Marshal(reqBody)

		for i := 0; i < numLogins; i++ {
			req, _ := http.NewRequest("POST", helper.URL("/auth/login"), bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			start := time.Now()
			resp := helper.DoRequest(req)
			durations[i] = time.Since(start)

			assert.Equal(t, http.StatusOK, resp.StatusCode, "Login should succeed")
			resp.Body.Close()
		}

		// Calculate performance metrics
		var total time.Duration
		var max time.Duration
		for _, d := range durations {
			total += d
			if d > max {
				max = d
			}
		}
		avg := total / time.Duration(numLogins)

		// Performance assertions - align with CLAUDE.md standards (<100ms for auth endpoints)
		assert.Less(t, avg, 100*time.Millisecond, "Average login time should be < 100ms, got %v", avg)
		assert.Less(t, max, 150*time.Millisecond, "Max login time should be < 150ms, got %v", max)

		t.Logf("Login Performance: %d logins", numLogins)
		t.Logf("  Average: %v", avg)
		t.Logf("  Max: %v", max)
	})

	t.Run("concurrent logins perform within limits", func(t *testing.T) {
		// Create multiple users for concurrent testing
		const concurrentLogins = 5
		testUsers := make([]*domain.User, concurrentLogins)
		passwords := make([]string, concurrentLogins)

		for i := 0; i < concurrentLogins; i++ {
			opts := DefaultTestUser()
			opts.PhoneVerified = true
			testUsers[i] = userFactory.CreateUserT(opts)
			passwords[i] = opts.Password
		}

		// Cleanup users
		defer func() {
			for _, user := range testUsers {
				suite.DB.Delete(user)
			}
		}()

		results := make(chan time.Duration, concurrentLogins)
		errors := make(chan error, concurrentLogins)

		// Concurrent logins
		for i := 0; i < concurrentLogins; i++ {
			go func(index int) {
				reqBody := map[string]string{
					"email":    testUsers[index].Email,
					"password": passwords[index],
				}
				body, _ := json.Marshal(reqBody)

				req, _ := http.NewRequest("POST", helper.URL("/auth/login"), bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")

				start := time.Now()
				resp := helper.DoRequest(req)
				duration := time.Since(start)
				resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					errors <- fmt.Errorf("login %d failed with status %d", index, resp.StatusCode)
					return
				}

				results <- duration
			}(i)
		}

		// Collect results
		var durations []time.Duration
		var errorCount int

		for i := 0; i < concurrentLogins; i++ {
			select {
			case duration := <-results:
				durations = append(durations, duration)
			case err := <-errors:
				t.Logf("Concurrent login error: %v", err)
				errorCount++
			case <-time.After(5 * time.Second):
				t.Fatal("Concurrent login test timed out")
			}
		}

		// Validate performance
		assert.Zero(t, errorCount, "No login errors expected under normal load")
		
		var totalDuration time.Duration
		maxDuration := time.Duration(0)
		for _, d := range durations {
			totalDuration += d
			if d > maxDuration {
				maxDuration = d
			}
		}

		if len(durations) > 0 {
			avgDuration := totalDuration / time.Duration(len(durations))
			
			assert.Less(t, avgDuration, 100*time.Millisecond, 
				"Average concurrent login time should be < 100ms, got %v", avgDuration)
			assert.Less(t, maxDuration, 200*time.Millisecond, 
				"Max concurrent login time should be < 200ms, got %v", maxDuration)

			t.Logf("Concurrent Login Performance: %d logins", len(durations))
			t.Logf("  Average: %v", avgDuration)
			t.Logf("  Max: %v", maxDuration)
		}
	})

	server.ValidatePerformance(t)
}

// TestLoginDatabaseIntegration tests database interactions during login
func TestLoginDatabaseIntegration(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)

	helper.MustStart()
	helper.MustWaitForReady()

	t.Run("login queries database efficiently", func(t *testing.T) {
		// Create test user
		userFactory := NewTestUserFactory(t, suite.DB)
		opts := DefaultTestUser()
		opts.PhoneVerified = true
		user := userFactory.CreateUserT(opts)
		defer suite.DB.Delete(user)

		// Measure database query performance during login
		dbHelper := NewDatabaseTestHelper(t, suite)
		
		// Time a user lookup query directly
		queryDuration := dbHelper.MeasureQueryPerformanceT(
			"SELECT * FROM users WHERE email = $1 LIMIT 1", user.Email)
		
		// Database lookup should be fast
		assert.Less(t, queryDuration, 50*time.Millisecond, 
			"User lookup should be < 50ms, got %v", queryDuration)

		// Perform actual login and validate total time
		reqBody := map[string]string{
			"email":    user.Email,
			"password": opts.Password,
		}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", helper.URL("/auth/login"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		start := time.Now()
		resp := helper.DoRequest(req)
		totalDuration := time.Since(start)
		resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Less(t, totalDuration, 100*time.Millisecond, 
			"Complete login should be < 100ms, got %v", totalDuration)

		t.Logf("Database Performance:")
		t.Logf("  User lookup: %v", queryDuration)
		t.Logf("  Total login: %v", totalDuration)
	})

	t.Run("login handles database connection failures gracefully", func(t *testing.T) {
		// Note: This test would require database connection manipulation
		// For now, we test that the happy path works correctly
		t.Skip("Database failure simulation requires advanced test setup")
	})
}

// TestLoginRedisIntegration tests Redis session creation during login
func TestLoginRedisIntegration(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)

	helper.MustStart()
	helper.MustWaitForReady()

	t.Run("login creates session with correct Redis format", func(t *testing.T) {
		// Create verified test user
		userFactory := NewTestUserFactory(t, suite.DB)
		opts := DefaultTestUser()
		opts.PhoneVerified = true
		user := userFactory.CreateUserT(opts)
		defer suite.DB.Delete(user)

		// Perform login
		reqBody := map[string]string{
			"email":    user.Email,
			"password": opts.Password,
		}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", helper.URL("/auth/login"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		resp := helper.DoRequest(req)
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var respBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&respBody)
		resp.Body.Close()

		// Extract session ID from access token - access through data wrapper
		data := respBody["data"].(map[string]interface{})
		accessToken := data["access_token"].(string)
		token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
			return []byte(suite.Config.JWTSecret), nil
		})
		require.NoError(t, err)

		claims := token.Claims.(jwt.MapClaims)
		sessionID := claims["session_id"].(string)

		// Validate session in Redis
		ctx := context.Background()
		sessionKey := fmt.Sprintf("session:%s", sessionID)

		// Check session exists
		exists, err := suite.Redis.Exists(ctx, sessionKey).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(1), exists, "Session should exist in Redis")

		// Check session value - session is stored as JSON
		sessionData, err := suite.Redis.Get(ctx, sessionKey).Result()
		require.NoError(t, err, "Session should exist in Redis")
		
		var session map[string]interface{}
		err = json.Unmarshal([]byte(sessionData), &session)
		require.NoError(t, err, "Session data should be valid JSON")
		
		assert.Equal(t, float64(user.ID), session["UserID"], "Session should contain UserID")

		// Check TTL
		ttl, err := suite.Redis.TTL(ctx, sessionKey).Result()
		require.NoError(t, err)
		assert.Greater(t, ttl.Seconds(), 0.0, "Session should have positive TTL")
		
		// Should be close to configured refresh token TTL
		expectedTTL := suite.Config.RefreshTTL
		tolerance := 10 * time.Second
		assert.InDelta(t, expectedTTL.Seconds(), ttl.Seconds(), tolerance.Seconds(), 
			"Session TTL should be close to configured refresh TTL")

		// Cleanup session
		suite.Redis.Del(ctx, sessionKey)
	})

	t.Run("multiple logins create different sessions", func(t *testing.T) {
		// Create verified test user
		userFactory := NewTestUserFactory(t, suite.DB)
		opts := DefaultTestUser()
		opts.PhoneVerified = true
		user := userFactory.CreateUserT(opts)
		defer suite.DB.Delete(user)

		reqBody := map[string]string{
			"email":    user.Email,
			"password": opts.Password,
		}
		body, _ := json.Marshal(reqBody)

		sessionIDs := make([]string, 3)
		
		// Perform multiple logins
		for i := 0; i < 3; i++ {
			req, _ := http.NewRequest("POST", helper.URL("/auth/login"), bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")

			resp := helper.DoRequest(req)
			require.Equal(t, http.StatusOK, resp.StatusCode)

			var respBody map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&respBody)
			resp.Body.Close()

			// Extract session ID - access through data wrapper
			data := respBody["data"].(map[string]interface{})
			accessToken := data["access_token"].(string)
			token, _ := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
				return []byte(suite.Config.JWTSecret), nil
			})
			claims := token.Claims.(jwt.MapClaims)
			sessionIDs[i] = claims["session_id"].(string)
		}

		// Verify all session IDs are different
		for i := 0; i < len(sessionIDs); i++ {
			for j := i + 1; j < len(sessionIDs); j++ {
				assert.NotEqual(t, sessionIDs[i], sessionIDs[j], 
					"Each login should create a unique session")
			}
		}

		// Verify all sessions exist in Redis
		ctx := context.Background()
		for _, sessionID := range sessionIDs {
			sessionKey := fmt.Sprintf("session:%s", sessionID)
			exists, err := suite.Redis.Exists(ctx, sessionKey).Result()
			require.NoError(t, err)
			assert.Equal(t, int64(1), exists, "Each session should exist in Redis")
			
			// Cleanup
			suite.Redis.Del(ctx, sessionKey)
		}
	})
}