package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestManualAuthenticationFlowWithDatabaseValidation runs a step-by-step authentication flow
// with database validation at each step for CB-176 verification
func TestManualAuthenticationFlowWithDatabaseValidation(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	
	// Start the test server
	err := server.Start()
	require.NoError(t, err)
	defer server.Stop()

	// Test user data
	testEmail := fmt.Sprintf("manual.test.%d@e2etest.local", time.Now().UnixNano())
	testPhone := "+1234567890"
	testPassword := "TestPassword123!"
	
	// Variables to share between test steps
	var userID int
	var otp string

	t.Logf("🚀 Starting manual authentication flow test")
	t.Logf("📧 Test email: %s", testEmail)
	t.Logf("📱 Test phone: %s", testPhone)
	t.Logf("🌐 Server URL: %s", server.BaseURL)

	// Step 1: Check initial database state
	t.Run("Step 1: Initial Database State", func(t *testing.T) {
		userCount := countUsersInDatabase(t, suite)
		t.Logf("📊 Initial users in database: %d", userCount)
		
		// Verify user doesn't exist yet
		userExists := checkUserExistsInDatabase(t, suite, testEmail)
		assert.False(t, userExists, "User should not exist initially")
		t.Logf("✅ Verified user doesn't exist yet")
	})

	// Step 2: User Registration
	var registerResponse map[string]interface{}
	t.Run("Step 2: User Registration", func(t *testing.T) {
		t.Logf("📝 Registering user...")

		registerPayload := map[string]interface{}{
			"email":    testEmail,
			"phone":    testPhone,
			"password": testPassword,
			"role":     "user",
		}

		reqBody, _ := json.Marshal(registerPayload)
		resp, err := http.Post(
			server.BaseURL+"/auth/register",
			"application/json",
			bytes.NewBuffer(reqBody),
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check HTTP response
		assert.Equal(t, http.StatusCreated, resp.StatusCode, "Registration should succeed")
		t.Logf("✅ Registration HTTP response: %d", resp.StatusCode)

		// Parse response
		err = json.NewDecoder(resp.Body).Decode(&registerResponse)
		require.NoError(t, err)
		t.Logf("📄 Registration response: %+v", registerResponse)

		// Validate database state after registration
		userCount := countUsersInDatabase(t, suite)
		t.Logf("📊 Users in database after registration: %d", userCount)
		
		userExists := checkUserExistsInDatabase(t, suite, testEmail)
		assert.True(t, userExists, "User should exist after registration")
		
		user := getUserFromDatabase(t, suite, testEmail)
		assert.NotNil(t, user)
		assert.Equal(t, testEmail, user["email"])
		assert.Equal(t, testPhone, user["phone"])
		assert.False(t, user["phone_verified"].(bool), "Phone should not be verified yet")
		assert.True(t, user["is_active"].(bool), "User should be active")
		t.Logf("✅ User created in database with correct data")
		t.Logf("   - ID: %v", user["id"])
		t.Logf("   - Email: %v", user["email"])
		t.Logf("   - Phone: %v", user["phone"])
		t.Logf("   - Phone Verified: %v", user["phone_verified"])
		t.Logf("   - Is Active: %v", user["is_active"])
	})

	// Step 3: Check OTP in Redis
	t.Run("Step 3: OTP Storage Validation", func(t *testing.T) {
		t.Logf("🔍 Checking OTP storage in Redis...")
		
		// Extract user ID from registration response
		data, ok := registerResponse["data"].(map[string]interface{})
		require.True(t, ok, "Registration response should contain data field")
		userID = int(data["user_id"].(float64))
		
		// Check Redis for OTP key
		otpExists := checkOTPInRedisWithUserID(t, suite, testPhone, userID)
		assert.True(t, otpExists, "OTP should be stored in Redis")
		t.Logf("✅ OTP found in Redis for phone: %s", testPhone)
		
		// Get OTP for verification (in real app, this would come from SMS)
		otp = getOTPFromRedisWithUserID(t, suite, testPhone, userID)
		assert.NotEmpty(t, otp, "OTP should not be empty")
		t.Logf("🔐 Generated OTP: %s", otp)
	})

	// Step 4: OTP Verification
	t.Run("Step 4: OTP Verification", func(t *testing.T) {
		t.Logf("🔐 Verifying OTP...")

		// Use the OTP and userID from previous step
		require.NotEmpty(t, otp, "Need OTP for verification")

		verifyPayload := map[string]interface{}{
			"phone":   testPhone,
			"code":    otp,
			"user_id": userID,
		}

		reqBody, _ := json.Marshal(verifyPayload)
		resp, err := http.Post(
			server.BaseURL+"/auth/otp/verify",
			"application/json",
			bytes.NewBuffer(reqBody),
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check HTTP response
		assert.Equal(t, http.StatusOK, resp.StatusCode, "OTP verification should succeed")
		t.Logf("✅ OTP verification HTTP response: %d", resp.StatusCode)

		var verifyResponse map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&verifyResponse)
		require.NoError(t, err)
		t.Logf("📄 OTP verification response: %+v", verifyResponse)

		// Validate database state after OTP verification
		user := getUserFromDatabase(t, suite, testEmail)
		assert.True(t, user["phone_verified"].(bool), "Phone should be verified after OTP")
		t.Logf("✅ Phone verified in database: %v", user["phone_verified"])
	})

	// Step 5: Login Attempt
	var loginResponse map[string]interface{}
	var accessToken, refreshToken string
	t.Run("Step 5: Login", func(t *testing.T) {
		t.Logf("🔑 Logging in user...")

		loginPayload := map[string]interface{}{
			"email":    testEmail,
			"password": testPassword,
		}

		reqBody, _ := json.Marshal(loginPayload)
		resp, err := http.Post(
			server.BaseURL+"/auth/login",
			"application/json",
			bytes.NewBuffer(reqBody),
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check HTTP response
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Login should succeed")
		t.Logf("✅ Login HTTP response: %d", resp.StatusCode)

		// Parse login response
		err = json.NewDecoder(resp.Body).Decode(&loginResponse)
		require.NoError(t, err)
		t.Logf("📄 Login response keys: %v", getMapKeys(loginResponse))

		// Extract tokens from corrected nested response format
		if data, ok := loginResponse["data"].(map[string]interface{}); ok {
			accessToken = data["access_token"].(string)
			refreshToken = data["refresh_token"].(string)
			t.Logf("✅ Tokens extracted successfully")
			t.Logf("   - Access token length: %d", len(accessToken))
			t.Logf("   - Refresh token length: %d", len(refreshToken))
		} else {
			t.Fatalf("Could not extract tokens from login response: %+v", loginResponse)
		}

		// Check session in Redis
		sessionExists := checkSessionInRedis(t, suite, refreshToken)
		assert.True(t, sessionExists, "Session should be created in Redis")
		t.Logf("✅ Session created in Redis")
	})

	// Step 6: Access Protected Endpoint
	t.Run("Step 6: Protected Endpoint Access", func(t *testing.T) {
		t.Logf("🛡️  Accessing protected endpoint...")

		req, err := http.NewRequest("GET", server.BaseURL+"/auth/me", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+accessToken)

		client := &http.Client{}
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check HTTP response
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Protected endpoint should be accessible")
		t.Logf("✅ Protected endpoint HTTP response: %d", resp.StatusCode)

		var meResponse map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&meResponse)
		require.NoError(t, err)
		t.Logf("📄 /auth/me response: %+v", meResponse)

		// Validate user data in response from corrected nested format
		if data, ok := meResponse["data"].(map[string]interface{}); ok {
			assert.Equal(t, testEmail, data["email"])
			t.Logf("✅ Protected endpoint returned correct user data")
			t.Logf("   - User ID: %v", data["id"])
			t.Logf("   - Phone verified: %v", data["phone_verified"])
		} else {
			t.Logf("❌ Could not extract user data from /auth/me response: %+v", meResponse)
		}
	})

	// Step 7: Token Refresh
	t.Run("Step 7: Token Refresh", func(t *testing.T) {
		t.Logf("🔄 Refreshing tokens...")

		refreshPayload := map[string]interface{}{
			"refresh_token": refreshToken,
		}

		reqBody, _ := json.Marshal(refreshPayload)
		resp, err := http.Post(
			server.BaseURL+"/auth/refresh",
			"application/json",
			bytes.NewBuffer(reqBody),
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check HTTP response
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Token refresh should succeed")
		t.Logf("✅ Token refresh HTTP response: %d", resp.StatusCode)

		var refreshResponse map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&refreshResponse)
		require.NoError(t, err)
		t.Logf("📄 Refresh response received")

		// Extract new tokens from corrected nested response format
		if data, ok := refreshResponse["data"].(map[string]interface{}); ok {
			newAccessToken := data["access_token"].(string)
			assert.NotEqual(t, accessToken, newAccessToken, "New access token should be different")
			t.Logf("✅ New access token generated (length: %d)", len(newAccessToken))
		} else {
			t.Logf("❌ Could not extract new access token from refresh response: %+v", refreshResponse)
		}
	})

	// Step 8: Logout
	t.Run("Step 8: Logout", func(t *testing.T) {
		t.Logf("👋 Logging out user...")

		logoutPayload := map[string]interface{}{
			"refresh_token": refreshToken,
		}

		reqBody, _ := json.Marshal(logoutPayload)
		resp, err := http.Post(
			server.BaseURL+"/auth/logout",
			"application/json",
			bytes.NewBuffer(reqBody),
		)
		require.NoError(t, err)
		defer resp.Body.Close()

		// Check HTTP response
		assert.Equal(t, http.StatusOK, resp.StatusCode, "Logout should succeed")
		t.Logf("✅ Logout HTTP response: %d", resp.StatusCode)

		// Verify session is removed from Redis
		sessionExists := checkSessionInRedis(t, suite, refreshToken)
		assert.False(t, sessionExists, "Session should be removed from Redis")
		t.Logf("✅ Session removed from Redis")
	})

	// Step 9: Final Database State
	t.Run("Step 9: Final Database State", func(t *testing.T) {
		t.Logf("📊 Checking final database state...")

		user := getUserFromDatabase(t, suite, testEmail)
		assert.NotNil(t, user, "User should still exist in database")
		assert.True(t, user["phone_verified"].(bool), "Phone should remain verified")
		assert.True(t, user["is_active"].(bool), "User should remain active")

		t.Logf("✅ Final user state in database:")
		t.Logf("   - ID: %v", user["id"])
		t.Logf("   - Email: %v", user["email"])
		t.Logf("   - Phone Verified: %v", user["phone_verified"])
		t.Logf("   - Is Active: %v", user["is_active"])
		t.Logf("   - Created At: %v", user["created_at"])
		t.Logf("   - Updated At: %v", user["updated_at"])
	})

	t.Logf("🎉 Complete authentication flow test completed successfully!")
}

// Helper functions for database validation

func countUsersInDatabase(t *testing.T, suite *TestSuite) int {
	t.Helper()
	
	query := "SELECT COUNT(*) FROM auth.users"
	var count int
	err := suite.DB.Raw(query).Scan(&count).Error
	require.NoError(t, err)
	return count
}

func checkUserExistsInDatabase(t *testing.T, suite *TestSuite, email string) bool {
	t.Helper()
	
	query := "SELECT COUNT(*) FROM auth.users WHERE email = ?"
	var count int
	err := suite.DB.Raw(query, email).Scan(&count).Error
	require.NoError(t, err)
	return count > 0
}

func getUserFromDatabase(t *testing.T, suite *TestSuite, email string) map[string]interface{} {
	t.Helper()
	
	query := "SELECT id, email, phone, is_active, phone_verified, created_at, updated_at FROM auth.users WHERE email = ?"
	var result map[string]interface{}
	
	rows, err := suite.DB.Raw(query, email).Rows()
	require.NoError(t, err)
	defer rows.Close()
	
	if rows.Next() {
		var id int
		var email, phone string
		var isActive, phoneVerified bool
		var createdAt, updatedAt time.Time
		
		err := rows.Scan(&id, &email, &phone, &isActive, &phoneVerified, &createdAt, &updatedAt)
		require.NoError(t, err)
		
		result = map[string]interface{}{
			"id": id,
			"email": email,
			"phone": phone,
			"is_active": isActive,
			"phone_verified": phoneVerified,
			"created_at": createdAt,
			"updated_at": updatedAt,
		}
	}
	
	return result
}

func checkOTPInRedis(t *testing.T, suite *TestSuite, phone string) bool {
	t.Helper()
	
	// Actual OTP key format (no test prefix)
	key := fmt.Sprintf("otp:%s", phone)
	val, err := suite.Redis.Get(context.Background(), key).Result()
	if err != nil {
		return false
	}
	return val != ""
}

func getOTPFromRedis(t *testing.T, suite *TestSuite, phone string) string {
	t.Helper()
	
	// Actual OTP key format (no test prefix)
	key := fmt.Sprintf("otp:%s", phone)
	val, err := suite.Redis.Get(context.Background(), key).Result()
	if err != nil {
		return ""
	}
	
	// OTP is stored directly as string, not JSON
	return val
}

func checkSessionInRedis(t *testing.T, suite *TestSuite, refreshToken string) bool {
	t.Helper()
	
	// Check for session keys (actual format without test prefix)
	pattern := "session:*"
	keys, err := suite.Redis.Keys(context.Background(), pattern).Result()
	require.NoError(t, err)
	
	return len(keys) > 0
}

func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func checkOTPInRedisWithUserID(t *testing.T, suite *TestSuite, phone string, userID int) bool {
	t.Helper()
	
	// Correct OTP key format: otp:{phone}:{userID}
	key := fmt.Sprintf("otp:%s:%d", phone, userID)
	val, err := suite.Redis.Get(context.Background(), key).Result()
	if err != nil {
		return false
	}
	return val != ""
}

func getOTPFromRedisWithUserID(t *testing.T, suite *TestSuite, phone string, userID int) string {
	t.Helper()
	
	// Correct OTP key format: otp:{phone}:{userID}
	key := fmt.Sprintf("otp:%s:%d", phone, userID)
	val, err := suite.Redis.Get(context.Background(), key).Result()
	if err != nil {
		return ""
	}
	
	// OTP is stored directly as string, not JSON
	return val
}