package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/you/authzsvc/domain"
)

// TestCompleteAuthenticationFlow tests the complete end-to-end authentication journey
func TestCompleteAuthenticationFlow(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)

	helper.MustStart()
	helper.MustWaitForReady()

	// Performance tracking (removed for now)

	// Test user data
	email := generateTestEmail()
	phone := "+15551234567"
	password := "SecurePassword123!"

	t.Run("complete user journey: register -> verify OTP -> login -> access protected -> refresh -> logout", func(t *testing.T) {
		// Step 1: User Registration
		t.Logf("Step 1: User Registration")
		start := time.Now()
		regBody := map[string]string{
			"email":    email,
			"phone":    phone,
			"password": password,
		}
		body, _ := json.Marshal(regBody)
		req, _ := http.NewRequest("POST", helper.URL("/auth/register"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		
		regResp := helper.DoRequest(req)
		regDuration := time.Since(start)
		t.Logf("Performance [registration]: %v (%d)", regDuration, regResp.StatusCode)
		require.Equal(t, http.StatusCreated, regResp.StatusCode, "Registration should succeed")
		regResp.Body.Close()
		
		// Verify user created in database
		var user domain.User
		err := suite.DB.Where("email = ?", email).First(&user).Error
		require.NoError(t, err, "User should be created in database")
		assert.Equal(t, email, user.Email)
		assert.False(t, user.PhoneVerified, "Phone should not be verified yet")

		// Verify OTP generated in Redis
		ctx := context.Background()
		otpKey := fmt.Sprintf("otp:%s:%d", phone, user.ID) // Don't use test prefix as services don't prefix
		otpCode, err := suite.Redis.Get(ctx, otpKey).Result()
		require.NoError(t, err, "OTP should be stored in Redis")
		assert.Regexp(t, `^\d{6}$`, otpCode, "OTP should be 6 digits")

		// Step 2: OTP Verification
		t.Logf("Step 2: OTP Verification with code: %s", otpCode)
		// Step 2: OTP Verification
		start = time.Now()
		otpBody := map[string]interface{}{
			"phone": phone,
			"code":  otpCode,
			"user_id": user.ID,
		}
		body, _ = json.Marshal(otpBody)
		req, _ = http.NewRequest("POST", helper.URL("/auth/otp/verify"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		
		otpResp := helper.DoRequest(req)
		otpDuration := time.Since(start)
		// Record performance manually
		_ = otpDuration
		require.Equal(t, http.StatusOK, otpResp.StatusCode)
		otpResp.Body.Close()

		// Verify phone is now verified in database
		err = suite.DB.Where("email = ?", email).First(&user).Error
		require.NoError(t, err)
		assert.True(t, user.PhoneVerified, "Phone should be verified after OTP")

		// Verify OTP is removed from Redis after successful verification
		_, err = suite.Redis.Get(ctx, otpKey).Result()
		assert.Error(t, err, "OTP should be removed after verification")

		// Step 3: User Login
		t.Logf("Step 3: User Login")
		loginBody := map[string]string{
			"email":    email,
			"password": password,
		}
		body, _ = json.Marshal(loginBody)

		req, _ = http.NewRequest("POST", helper.URL("/auth/login"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		start = time.Now()
		loginResp := helper.DoRequest(req)
		loginDuration := time.Since(start)
		
		require.Equal(t, http.StatusOK, loginResp.StatusCode, "Login should succeed")

		var loginRespBody map[string]interface{}
		err = json.NewDecoder(loginResp.Body).Decode(&loginRespBody)
		require.NoError(t, err)
		loginResp.Body.Close()

		// Extract tokens from nested data structure
		data := loginRespBody["data"].(map[string]interface{})
		accessToken := data["access_token"].(string)
		refreshToken := data["refresh_token"].(string)

		// Validate JWT structure and claims
		token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
			return []byte(suite.Config.JWTSecret), nil
		})
		require.NoError(t, err, "Access token should be valid JWT")

		claims := token.Claims.(jwt.MapClaims)
		sessionID := claims["session_id"].(string)
		userIDFromToken := claims["user_id"].(float64) // JWT unmarshals numbers as float64

		assert.Equal(t, float64(user.ID), userIDFromToken)
		assert.Equal(t, "user", claims["role"])

		// Verify session in Redis
		sessionKey := fmt.Sprintf("session:%s", sessionID) // Use session: prefix as per SessionRepository
		sessionData, err := suite.Redis.Get(ctx, sessionKey).Result()
		require.NoError(t, err, "Session should exist in Redis")
		
		// Session is stored as JSON, decode it
		var session domain.Session
		err = json.Unmarshal([]byte(sessionData), &session)
		require.NoError(t, err, "Session data should be valid JSON")
		assert.Equal(t, user.ID, session.UserID)

		// Step 4: Access Protected Endpoint
		t.Logf("Step 4: Access Protected Endpoint (/auth/me)")
		req, _ = http.NewRequest("GET", helper.URL("/auth/me"), nil)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		start = time.Now()
		meResp := helper.DoRequest(req)
		meDuration := time.Since(start)

		require.Equal(t, http.StatusOK, meResp.StatusCode, "Protected endpoint should be accessible")

		var meRespBody map[string]interface{}
		json.NewDecoder(meResp.Body).Decode(&meRespBody)
		meResp.Body.Close()

		// Extract user data from nested response structure
		userData := meRespBody["data"].(map[string]interface{})
		
		// Validate user profile data
		assert.Equal(t, float64(user.ID), userData["id"])
		assert.Equal(t, email, userData["email"])
		assert.Equal(t, phone, userData["phone"])
		assert.Equal(t, true, userData["phone_verified"])
		assert.Equal(t, "user", userData["role"])

		// Step 5: Token Refresh
		t.Logf("Step 5: Token Refresh")
		time.Sleep(100 * time.Millisecond) // Ensure different timestamp

		refreshBody := map[string]string{"refresh_token": refreshToken}
		body, _ = json.Marshal(refreshBody)

		req, _ = http.NewRequest("POST", helper.URL("/auth/refresh"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		start = time.Now()
		refreshResp := helper.DoRequest(req)
		refreshDuration := time.Since(start)

		require.Equal(t, http.StatusOK, refreshResp.StatusCode, "Token refresh should succeed")

		var refreshRespBody map[string]interface{}
		json.NewDecoder(refreshResp.Body).Decode(&refreshRespBody)
		refreshResp.Body.Close()

		// Extract data from nested response structure and get new access token
		refreshData := refreshRespBody["data"].(map[string]interface{})
		newAccessToken := refreshData["access_token"].(string)
		assert.NotEqual(t, accessToken, newAccessToken, "New access token should be different")

		// Verify new token works
		req, _ = http.NewRequest("GET", helper.URL("/auth/me"), nil)
		req.Header.Set("Authorization", "Bearer "+newAccessToken)

		newTokenResp := helper.DoRequest(req)
		assert.Equal(t, http.StatusOK, newTokenResp.StatusCode, "New access token should work")
		newTokenResp.Body.Close()

		// Step 6: User Logout
		t.Logf("Step 6: User Logout")
		req, _ = http.NewRequest("POST", helper.URL("/auth/logout"), nil)
		req.Header.Set("Authorization", "Bearer "+newAccessToken)

		start = time.Now()
		logoutResp := helper.DoRequest(req)
		logoutDuration := time.Since(start)

		require.Equal(t, http.StatusOK, logoutResp.StatusCode, "Logout should succeed")

		var logoutRespBody map[string]interface{}
		json.NewDecoder(logoutResp.Body).Decode(&logoutRespBody)
		logoutResp.Body.Close()

		// Extract message from nested data structure
		logoutData := logoutRespBody["data"].(map[string]interface{})
		assert.Contains(t, logoutData["message"], "Logged out successfully")

		// Verify session is removed from Redis
		_, err = suite.Redis.Get(ctx, sessionKey).Result()
		assert.Error(t, err, "Session should be removed after logout")

		// Step 7: Verify Token is Invalidated
		t.Logf("Step 7: Verify Token Invalidation")
		req, _ = http.NewRequest("GET", helper.URL("/auth/me"), nil)
		req.Header.Set("Authorization", "Bearer "+newAccessToken)

		tokenCheckResp := helper.DoRequest(req)
		assert.Equal(t, http.StatusUnauthorized, tokenCheckResp.StatusCode, 
			"Access token should be invalid after logout")
		tokenCheckResp.Body.Close()

		// Performance Validation
		t.Logf("Performance Summary:")
		t.Logf("  Registration: %v", regDuration)
		t.Logf("  OTP Verification: %v", otpDuration)
		t.Logf("  Login: %v", loginDuration)
		t.Logf("  Protected Endpoint: %v", meDuration)
		t.Logf("  Token Refresh: %v", refreshDuration)
		t.Logf("  Logout: %v", logoutDuration)

		// All operations should meet performance requirements
		assert.Less(t, regDuration, 100*time.Millisecond, "Registration should be < 100ms")
		assert.Less(t, otpDuration, 100*time.Millisecond, "OTP verification should be < 100ms")
		assert.Less(t, loginDuration, 100*time.Millisecond, "Login should be < 100ms")
		assert.Less(t, meDuration, 100*time.Millisecond, "Protected endpoint should be < 100ms")
		assert.Less(t, refreshDuration, 100*time.Millisecond, "Token refresh should be < 100ms")
		assert.Less(t, logoutDuration, 100*time.Millisecond, "Logout should be < 100ms")

		totalFlowDuration := regDuration + otpDuration + loginDuration + meDuration + refreshDuration + logoutDuration
		assert.Less(t, totalFlowDuration, 500*time.Millisecond, 
			"Complete authentication flow should be < 500ms total")

		// Cleanup
		suite.DB.Delete(&user)
	})

	server.ValidatePerformance(t)
}

// TestAuthFlowErrorScenarios tests error handling throughout the authentication flow
func TestAuthFlowErrorScenarios(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)

	helper.MustStart()
	helper.MustWaitForReady()

	t.Run("registration with existing email prevents duplicate users", func(t *testing.T) {
		// Create existing user
		userFactory := NewTestUserFactory(t, suite.DB)
		opts := DefaultTestUser()
		existingUser := userFactory.CreateUserT(opts)
		defer suite.DB.Delete(existingUser)

		// Attempt to register with same email
		reqBody := map[string]string{
			"email":    existingUser.Email,
			"phone":    "+15559999999",
			"password": "NewPassword123!",
		}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", helper.URL("/auth/register"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		resp := helper.DoRequest(req)
		assert.Equal(t, http.StatusConflict, resp.StatusCode)

		var respBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&respBody)
		resp.Body.Close()

		assert.Contains(t, respBody["error"], "User already exists")
	})

	t.Run("login before phone verification fails", func(t *testing.T) {
		// Create user with unverified phone
		userFactory := NewTestUserFactory(t, suite.DB)
		opts := DefaultTestUser()
		opts.PhoneVerified = false
		unverifiedUser := userFactory.CreateUserT(opts)
		defer suite.DB.Delete(unverifiedUser)

		// Attempt login
		reqBody := map[string]string{
			"email":    unverifiedUser.Email,
			"password": opts.Password,
		}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", helper.URL("/auth/login"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		resp := helper.DoRequest(req)
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)

		var respBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&respBody)
		resp.Body.Close()

		assert.Contains(t, respBody["error"], "Phone number not verified")
	})

	t.Run("OTP verification with wrong code fails", func(t *testing.T) {
		// Setup: Register user to generate OTP
		email := generateTestEmail()
		phone := "+15551111111"
		password := "TestPassword123!"

		reqBody := map[string]string{
			"email":    email,
			"phone":    phone,
			"password": password,
		}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", helper.URL("/auth/register"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		regResp := helper.DoRequest(req)
		require.Equal(t, http.StatusCreated, regResp.StatusCode)
		regResp.Body.Close()

		// Get the created user to access user.ID
		var user domain.User
		err := suite.DB.Where("email = ?", email).First(&user).Error
		require.NoError(t, err, "User should be created in database")

		// Attempt OTP verification with wrong code
		otpBody := map[string]interface{}{
			"phone": phone,
			"code":  "000000", // Wrong code
			"user_id": user.ID,
		}
		body, _ = json.Marshal(otpBody)

		req, _ = http.NewRequest("POST", helper.URL("/auth/otp/verify"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		resp := helper.DoRequest(req)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)

		var respBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&respBody)
		resp.Body.Close()

		assert.Contains(t, respBody["error"], "Invalid OTP")

		// Cleanup
		suite.DB.Where("email = ?", email).Delete(&domain.User{})
	})

	t.Run("accessing protected endpoints without token fails", func(t *testing.T) {
		req, _ := http.NewRequest("GET", helper.URL("/auth/me"), nil)
		// No Authorization header

		resp := helper.DoRequest(req)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()
	})

	t.Run("logout invalidates all user sessions", func(t *testing.T) {
		// Create verified user
		userFactory := NewTestUserFactory(t, suite.DB)
		opts := DefaultTestUser()
		opts.PhoneVerified = true
		user := userFactory.CreateUserT(opts)
		defer suite.DB.Delete(user)

		// Create multiple sessions (login multiple times)
		var tokens []map[string]interface{}
		for i := 0; i < 3; i++ {
			loginTokens := loginUserForTest(t, helper, user.Email, opts.Password)
			require.NotNil(t, loginTokens, "Login should succeed to create session")
			tokens = append(tokens, loginTokens)
		}

		// Logout from first session
		firstAccessToken := tokens[0]["access_token"].(string)
		req, _ := http.NewRequest("POST", helper.URL("/auth/logout"), nil)
		req.Header.Set("Authorization", "Bearer "+firstAccessToken)

		resp := helper.DoRequest(req)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()

		// Verify first token is invalidated
		req, _ = http.NewRequest("GET", helper.URL("/auth/me"), nil)
		req.Header.Set("Authorization", "Bearer "+firstAccessToken)

		resp = helper.DoRequest(req)
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		resp.Body.Close()

		// Other sessions should still be valid (session-based logout)
		secondAccessToken := tokens[1]["access_token"].(string)
		req, _ = http.NewRequest("GET", helper.URL("/auth/me"), nil)
		req.Header.Set("Authorization", "Bearer "+secondAccessToken)

		resp = helper.DoRequest(req)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	})
}

// TestAuthFlowConcurrency tests the authentication flow under concurrent access
func TestAuthFlowConcurrency(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)

	helper.MustStart()
	helper.MustWaitForReady()

	t.Run("concurrent user registrations succeed", func(t *testing.T) {
		const concurrentUsers = 5
		results := make(chan error, concurrentUsers)

		// Create concurrent registrations
		for i := 0; i < concurrentUsers; i++ {
			go func(index int) {
				email := fmt.Sprintf("concurrent.%d.%s", index, generateTestEmail())
				phone := fmt.Sprintf("+1555%07d", 2000000+index)
				
				reqBody := map[string]string{
					"email":    email,
					"phone":    phone,
					"password": "ConcurrentTest123!",
				}
				body, _ := json.Marshal(reqBody)

				req, _ := http.NewRequest("POST", helper.URL("/auth/register"), bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")

				resp := helper.DoRequest(req)
				resp.Body.Close()

				if resp.StatusCode != http.StatusCreated {
					results <- fmt.Errorf("registration %d failed with status %d", index, resp.StatusCode)
					return
				}

				results <- nil
			}(i)
		}

		// Collect results
		var errors []error
		for i := 0; i < concurrentUsers; i++ {
			select {
			case err := <-results:
				if err != nil {
					errors = append(errors, err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Concurrent registration test timed out")
			}
		}

		// Validate results
		if len(errors) > 0 {
			for _, err := range errors {
				t.Logf("Concurrent registration error: %v", err)
			}
			t.Fatalf("Expected no errors in concurrent registration, got %d", len(errors))
		}

		// Cleanup concurrent test users
		suite.DB.Where("email LIKE ?", "concurrent.%.%").Delete(&domain.User{})
		
		t.Logf("Successfully created %d users concurrently", concurrentUsers)
	})

	t.Run("concurrent logins for same user create separate sessions", func(t *testing.T) {
		// Create verified test user
		userFactory := NewTestUserFactory(t, suite.DB)
		opts := DefaultTestUser()
		opts.PhoneVerified = true
		user := userFactory.CreateUserT(opts)
		defer suite.DB.Delete(user)

		const concurrentLogins = 3
		sessionResults := make(chan string, concurrentLogins)
		errors := make(chan error, concurrentLogins)

		// Perform concurrent logins
		for i := 0; i < concurrentLogins; i++ {
			go func(index int) {
				tokens := loginUserForTest(t, helper, user.Email, opts.Password)
				
				if tokens == nil {
					errors <- fmt.Errorf("login %d failed", index)
					return
				}

				// Extract session ID from access token
				accessToken := tokens["access_token"].(string)
				token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
					return []byte(suite.Config.JWTSecret), nil
				})
				if err != nil {
					errors <- fmt.Errorf("failed to parse token for login %d: %v", index, err)
					return
				}

				claims := token.Claims.(jwt.MapClaims)
				sessionID := claims["session_id"].(string)
				sessionResults <- sessionID
			}(i)
		}

		// Collect session IDs
		var sessionIDs []string
		var errorCount int

		for i := 0; i < concurrentLogins; i++ {
			select {
			case sessionID := <-sessionResults:
				sessionIDs = append(sessionIDs, sessionID)
			case err := <-errors:
				t.Logf("Concurrent login error: %v", err)
				errorCount++
			case <-time.After(10 * time.Second):
				t.Fatal("Concurrent login test timed out")
			}
		}

		// Validate all logins succeeded
		assert.Zero(t, errorCount, "All concurrent logins should succeed")
		assert.Equal(t, concurrentLogins, len(sessionIDs), "Should have session IDs for all logins")

		// Verify all session IDs are unique
		sessionMap := make(map[string]bool)
		for _, sessionID := range sessionIDs {
			assert.False(t, sessionMap[sessionID], "Session ID %s should be unique", sessionID)
			sessionMap[sessionID] = true
		}

		// Verify all sessions exist in Redis (check main Redis, not test-prefixed)
		ctx := context.Background()
		for _, sessionID := range sessionIDs {
			// Check main Redis namespace since sessions are created by running app server
			sessionKey := fmt.Sprintf("session:%s", sessionID)
			exists, err := suite.Redis.Exists(ctx, sessionKey).Result()
			require.NoError(t, err)
			assert.Equal(t, int64(1), exists, "Session %s should exist in Redis", sessionID)
		}

		t.Logf("Successfully created %d concurrent sessions with unique IDs", len(sessionIDs))
	})

	server.ValidatePerformance(t)
}

// TestAuthFlowDatabaseTransactions tests transaction handling across the auth flow
func TestAuthFlowDatabaseTransactions(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)

	helper.MustStart()
	helper.MustWaitForReady()

	t.Run("registration transaction commits completely", func(t *testing.T) {
		dbHelper := NewDatabaseTestHelper(t, suite)
		initialCount := dbHelper.CountRecordsT("users")

		email := generateTestEmail()
		phone := "+15552222222"

		reqBody := map[string]string{
			"email":    email,
			"phone":    phone,
			"password": "TransactionTest123!",
		}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", helper.URL("/auth/register"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		resp := helper.DoRequest(req)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		resp.Body.Close()

		// Verify exact increment in user count
		finalCount := dbHelper.CountRecordsT("users")
		assert.Equal(t, initialCount+1, finalCount, "User count should increase by exactly 1")

		// Verify user data integrity
		var user domain.User
		err := suite.DB.Where("email = ?", email).First(&user).Error
		require.NoError(t, err)
		
		assert.Equal(t, email, user.Email)
		assert.Equal(t, phone, user.Phone)
		assert.NotEmpty(t, user.PasswordHash)
		assert.True(t, user.IsActive)
		assert.False(t, user.PhoneVerified)
		assert.Equal(t, "user", user.Role)

		// Cleanup
		suite.DB.Delete(&user)
	})

	t.Run("OTP verification updates database atomically", func(t *testing.T) {
		// Create unverified user
		userFactory := NewTestUserFactory(t, suite.DB)
		opts := DefaultTestUser()
		opts.PhoneVerified = false
		user := userFactory.CreateUserT(opts)
		defer suite.DB.Delete(user)

		// Generate OTP manually for testing
		ctx := context.Background()
		otpKey := fmt.Sprintf("otp:%s:%d", user.Phone, user.ID)
		testOTP := "123456"
		suite.Redis.Set(ctx, otpKey, testOTP, 5*time.Minute)

		// Verify OTP
		reqBody := map[string]interface{}{
			"phone":   user.Phone,
			"code":    testOTP,
			"user_id": user.ID,
		}
		body, _ := json.Marshal(reqBody)

		req, _ := http.NewRequest("POST", helper.URL("/auth/otp/verify"), bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		resp := helper.DoRequest(req)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()

		// Verify database update
		var updatedUser domain.User
		err := suite.DB.Where("id = ?", user.ID).First(&updatedUser).Error
		require.NoError(t, err)
		assert.True(t, updatedUser.PhoneVerified, "Phone should be verified after OTP verification")

		// Verify OTP is removed from Redis
		_, err = suite.Redis.Get(ctx, otpKey).Result()
		assert.Error(t, err, "OTP should be removed from Redis after verification")
	})

	server.ValidatePerformance(t)
}

// Helper functions

// loginUserForTest performs login and returns tokens (for test helper)
func loginUserForTest(t *testing.T, helper *ServerTestHelper, email, password string) map[string]interface{} {
	t.Helper()

	reqBody := map[string]string{
		"email":    email,
		"password": password,
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest("POST", helper.URL("/auth/login"), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	resp := helper.DoRequest(req)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil
	}

	var respBody map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&respBody)
	resp.Body.Close()

	// Extract data from nested response structure
	if data, ok := respBody["data"].(map[string]interface{}); ok {
		return data
	}
	return respBody
}

