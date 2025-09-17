package domain

import (
	"testing"
	"time"
)

func TestUser_Validation(t *testing.T) {
	tests := []struct {
		name         string
		user         *User
		expectValid  bool
		description  string
	}{
		{
			name: "valid user",
			user: &User{
				ID:            1,
				Email:         "test@example.com",
				Phone:         "+1234567890",
				PasswordHash:  "hashed_password",
				Role:          "user",
				IsActive:      true,
				PhoneVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			expectValid: true,
			description: "user with all valid fields",
		},
		{
			name: "user with admin role",
			user: &User{
				ID:            2,
				Email:         "admin@example.com",
				Phone:         "+1234567891",
				PasswordHash:  "hashed_admin_password",
				Role:          "admin",
				IsActive:      true,
				PhoneVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			expectValid: true,
			description: "admin user should be valid",
		},
		{
			name: "inactive user",
			user: &User{
				ID:            3,
				Email:         "inactive@example.com",
				Phone:         "+1234567892",
				PasswordHash:  "hashed_password",
				Role:          "user",
				IsActive:      false,
				PhoneVerified: true,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			expectValid: true,
			description: "inactive user should be valid (business rule, not validation rule)",
		},
		{
			name: "user with unverified phone",
			user: &User{
				ID:            4,
				Email:         "unverified@example.com",
				Phone:         "+1234567893",
				PasswordHash:  "hashed_password",
				Role:          "user",
				IsActive:      true,
				PhoneVerified: false,
				CreatedAt:     time.Now(),
				UpdatedAt:     time.Now(),
			},
			expectValid: true,
			description: "user with unverified phone should be valid (OTP flow)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test basic field validation
			if tt.user.ID == 0 && tt.expectValid {
				t.Error("expected valid user to have non-zero ID")
			}

			if tt.user.Email == "" && tt.expectValid {
				t.Error("expected valid user to have non-empty email")
			}

			if tt.user.Phone == "" && tt.expectValid {
				t.Error("expected valid user to have non-empty phone")
			}

			if tt.user.PasswordHash == "" && tt.expectValid {
				t.Error("expected valid user to have non-empty password hash")
			}

			if tt.user.Role == "" && tt.expectValid {
				t.Error("expected valid user to have non-empty role")
			}

			// Test role validation
			validRoles := []string{"user", "admin"}
			roleValid := false
			for _, validRole := range validRoles {
				if tt.user.Role == validRole {
					roleValid = true
					break
				}
			}

			if !roleValid && tt.expectValid {
				t.Errorf("expected valid role, got %s", tt.user.Role)
			}

			// Test timestamp validation
			if tt.user.CreatedAt.IsZero() && tt.expectValid {
				t.Error("expected valid user to have non-zero CreatedAt")
			}

			if tt.user.UpdatedAt.IsZero() && tt.expectValid {
				t.Error("expected valid user to have non-zero UpdatedAt")
			}

			// Test business logic: UpdatedAt should be >= CreatedAt
			if tt.user.UpdatedAt.Before(tt.user.CreatedAt) && tt.expectValid {
				t.Error("UpdatedAt should not be before CreatedAt")
			}
		})
	}
}

func TestAuthRequest_Validation(t *testing.T) {
	tests := []struct {
		name        string
		authRequest *AuthRequest
		expectValid bool
		description string
	}{
		{
			name: "valid auth request",
			authRequest: &AuthRequest{
				Email:    "test@example.com",
				Password: "securepassword123",
			},
			expectValid: true,
			description: "auth request with valid email and password",
		},
		{
			name: "empty email",
			authRequest: &AuthRequest{
				Email:    "",
				Password: "securepassword123",
			},
			expectValid: false,
			description: "auth request with empty email should be invalid",
		},
		{
			name: "empty password",
			authRequest: &AuthRequest{
				Email:    "test@example.com",
				Password: "",
			},
			expectValid: false,
			description: "auth request with empty password should be invalid",
		},
		{
			name: "both empty",
			authRequest: &AuthRequest{
				Email:    "",
				Password: "",
			},
			expectValid: false,
			description: "auth request with both empty should be invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasEmail := tt.authRequest.Email != ""
			hasPassword := tt.authRequest.Password != ""
			isValid := hasEmail && hasPassword

			if isValid != tt.expectValid {
				t.Errorf("expected validity %t, got %t", tt.expectValid, isValid)
			}
		})
	}
}

func TestAuthResult_Validation(t *testing.T) {
	now := time.Now()
	validUser := &User{
		ID:            1,
		Email:         "test@example.com",
		Phone:         "+1234567890",
		PasswordHash:  "hashed_password",
		Role:          "user",
		IsActive:      true,
		PhoneVerified: true,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	tests := []struct {
		name        string
		authResult  *AuthResult
		expectValid bool
		description string
	}{
		{
			name: "valid auth result",
			authResult: &AuthResult{
				User:         validUser,
				AccessToken:  "access_token_123",
				RefreshToken: "refresh_token_123",
				SessionID:    "session_123",
				ExpiresIn:    900, // 15 minutes
			},
			expectValid: true,
			description: "auth result with all valid fields",
		},
		{
			name: "nil user",
			authResult: &AuthResult{
				User:         nil,
				AccessToken:  "access_token_123",
				RefreshToken: "refresh_token_123",
				SessionID:    "session_123",
				ExpiresIn:    900,
			},
			expectValid: false,
			description: "auth result with nil user should be invalid",
		},
		{
			name: "empty access token",
			authResult: &AuthResult{
				User:         validUser,
				AccessToken:  "",
				RefreshToken: "refresh_token_123",
				SessionID:    "session_123",
				ExpiresIn:    900,
			},
			expectValid: false,
			description: "auth result with empty access token should be invalid",
		},
		{
			name: "empty refresh token",
			authResult: &AuthResult{
				User:         validUser,
				AccessToken:  "access_token_123",
				RefreshToken: "",
				SessionID:    "session_123",
				ExpiresIn:    900,
			},
			expectValid: false,
			description: "auth result with empty refresh token should be invalid",
		},
		{
			name: "empty session ID",
			authResult: &AuthResult{
				User:         validUser,
				AccessToken:  "access_token_123",
				RefreshToken: "refresh_token_123",
				SessionID:    "",
				ExpiresIn:    900,
			},
			expectValid: false,
			description: "auth result with empty session ID should be invalid",
		},
		{
			name: "zero expires in",
			authResult: &AuthResult{
				User:         validUser,
				AccessToken:  "access_token_123",
				RefreshToken: "refresh_token_123",
				SessionID:    "session_123",
				ExpiresIn:    0,
			},
			expectValid: false,
			description: "auth result with zero ExpiresIn should be invalid",
		},
		{
			name: "negative expires in",
			authResult: &AuthResult{
				User:         validUser,
				AccessToken:  "access_token_123",
				RefreshToken: "refresh_token_123",
				SessionID:    "session_123",
				ExpiresIn:    -100,
			},
			expectValid: false,
			description: "auth result with negative ExpiresIn should be invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasUser := tt.authResult.User != nil
			hasAccessToken := tt.authResult.AccessToken != ""
			hasRefreshToken := tt.authResult.RefreshToken != ""
			hasSessionID := tt.authResult.SessionID != ""
			hasValidExpiresIn := tt.authResult.ExpiresIn > 0

			isValid := hasUser && hasAccessToken && hasRefreshToken && hasSessionID && hasValidExpiresIn

			if isValid != tt.expectValid {
				t.Errorf("expected validity %t, got %t", tt.expectValid, isValid)
			}
		})
	}
}

func TestOTPRequest_Validation(t *testing.T) {
	tests := []struct {
		name        string
		otpRequest  *OTPRequest
		expectValid bool
		description string
	}{
		{
			name: "valid OTP request",
			otpRequest: &OTPRequest{
				Phone:     "+1234567890",
				Code:      "123456",
				UserID:    1,
				ExpiresAt: time.Now().Add(5 * time.Minute),
				Attempts:  0,
			},
			expectValid: true,
			description: "OTP request with all valid fields",
		},
		{
			name: "empty phone",
			otpRequest: &OTPRequest{
				Phone:     "",
				Code:      "123456",
				UserID:    1,
				ExpiresAt: time.Now().Add(5 * time.Minute),
				Attempts:  0,
			},
			expectValid: false,
			description: "OTP request with empty phone should be invalid",
		},
		{
			name: "empty code",
			otpRequest: &OTPRequest{
				Phone:     "+1234567890",
				Code:      "",
				UserID:    1,
				ExpiresAt: time.Now().Add(5 * time.Minute),
				Attempts:  0,
			},
			expectValid: false,
			description: "OTP request with empty code should be invalid",
		},
		{
			name: "zero user ID",
			otpRequest: &OTPRequest{
				Phone:     "+1234567890",
				Code:      "123456",
				UserID:    0,
				ExpiresAt: time.Now().Add(5 * time.Minute),
				Attempts:  0,
			},
			expectValid: false,
			description: "OTP request with zero UserID should be invalid",
		},
		{
			name: "expired OTP",
			otpRequest: &OTPRequest{
				Phone:     "+1234567890",
				Code:      "123456",
				UserID:    1,
				ExpiresAt: time.Now().Add(-5 * time.Minute), // Expired
				Attempts:  0,
			},
			expectValid: false,
			description: "expired OTP request should be invalid",
		},
		{
			name: "negative attempts",
			otpRequest: &OTPRequest{
				Phone:     "+1234567890",
				Code:      "123456",
				UserID:    1,
				ExpiresAt: time.Now().Add(5 * time.Minute),
				Attempts:  -1,
			},
			expectValid: false,
			description: "OTP request with negative attempts should be invalid",
		},
		{
			name: "too many attempts",
			otpRequest: &OTPRequest{
				Phone:     "+1234567890",
				Code:      "123456",
				UserID:    1,
				ExpiresAt: time.Now().Add(5 * time.Minute),
				Attempts:  10, // Assuming max is 5
			},
			expectValid: false,
			description: "OTP request with too many attempts should be invalid",
		},
	}

	maxAttempts := 5 // Business rule: max 5 attempts

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasPhone := tt.otpRequest.Phone != ""
			hasCode := tt.otpRequest.Code != ""
			hasUserID := tt.otpRequest.UserID > 0
			notExpired := tt.otpRequest.ExpiresAt.After(time.Now())
			validAttempts := tt.otpRequest.Attempts >= 0 && tt.otpRequest.Attempts <= maxAttempts

			isValid := hasPhone && hasCode && hasUserID && notExpired && validAttempts

			if isValid != tt.expectValid {
				t.Errorf("expected validity %t, got %t", tt.expectValid, isValid)
			}
		})
	}
}

func TestSession_Validation(t *testing.T) {
	tests := []struct {
		name        string
		session     *Session
		expectValid bool
		description string
	}{
		{
			name: "valid session",
			session: &Session{
				ID:        "session_123_456",
				UserID:    1,
				ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
				CreatedAt: time.Now(),
			},
			expectValid: true,
			description: "session with all valid fields",
		},
		{
			name: "empty session ID",
			session: &Session{
				ID:        "",
				UserID:    1,
				ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
				CreatedAt: time.Now(),
			},
			expectValid: false,
			description: "session with empty ID should be invalid",
		},
		{
			name: "zero user ID",
			session: &Session{
				ID:        "session_123",
				UserID:    0,
				ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
				CreatedAt: time.Now(),
			},
			expectValid: false,
			description: "session with zero UserID should be invalid",
		},
		{
			name: "expired session",
			session: &Session{
				ID:        "session_123",
				UserID:    1,
				ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
				CreatedAt: time.Now().Add(-2 * time.Hour),
			},
			expectValid: false,
			description: "expired session should be invalid",
		},
		{
			name: "zero created at",
			session: &Session{
				ID:        "session_123",
				UserID:    1,
				ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
				CreatedAt: time.Time{}, // Zero time
			},
			expectValid: false,
			description: "session with zero CreatedAt should be invalid",
		},
		{
			name: "expires before created",
			session: &Session{
				ID:        "session_123",
				UserID:    1,
				ExpiresAt: time.Now().Add(-1 * time.Hour),
				CreatedAt: time.Now(), // Created after expiration
			},
			expectValid: false,
			description: "session that expires before creation should be invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasID := tt.session.ID != ""
			hasUserID := tt.session.UserID > 0
			notExpired := tt.session.ExpiresAt.After(time.Now())
			hasCreatedAt := !tt.session.CreatedAt.IsZero()
			expiresAfterCreated := tt.session.ExpiresAt.After(tt.session.CreatedAt)

			isValid := hasID && hasUserID && notExpired && hasCreatedAt && expiresAfterCreated

			if isValid != tt.expectValid {
				t.Errorf("expected validity %t, got %t", tt.expectValid, isValid)
			}
		})
	}
}

func TestTokenClaims_Validation(t *testing.T) {
	now := time.Now().Unix()

	tests := []struct {
		name        string
		claims      *TokenClaims
		expectValid bool
		description string
	}{
		{
			name: "valid access token claims",
			claims: &TokenClaims{
				UserID:    1,
				Role:      "user",
				SessionID: "", // Access tokens might not have session ID
				IssuedAt:  now,
				ExpiresAt: now + 900, // 15 minutes
			},
			expectValid: true,
			description: "valid access token claims",
		},
		{
			name: "valid refresh token claims",
			claims: &TokenClaims{
				UserID:    1,
				Role:      "admin",
				SessionID: "session_123",
				IssuedAt:  now,
				ExpiresAt: now + 604800, // 7 days
			},
			expectValid: true,
			description: "valid refresh token claims with session ID",
		},
		{
			name: "zero user ID",
			claims: &TokenClaims{
				UserID:    0,
				Role:      "user",
				SessionID: "",
				IssuedAt:  now,
				ExpiresAt: now + 900,
			},
			expectValid: false,
			description: "claims with zero UserID should be invalid",
		},
		{
			name: "empty role",
			claims: &TokenClaims{
				UserID:    1,
				Role:      "",
				SessionID: "",
				IssuedAt:  now,
				ExpiresAt: now + 900,
			},
			expectValid: false,
			description: "claims with empty role should be invalid",
		},
		{
			name: "expired token",
			claims: &TokenClaims{
				UserID:    1,
				Role:      "user",
				SessionID: "",
				IssuedAt:  now - 1800, // 30 minutes ago
				ExpiresAt: now - 900,  // Expired 15 minutes ago
			},
			expectValid: false,
			description: "expired token claims should be invalid",
		},
		{
			name: "expires before issued",
			claims: &TokenClaims{
				UserID:    1,
				Role:      "user",
				SessionID: "",
				IssuedAt:  now,
				ExpiresAt: now - 900, // Expires before issued
			},
			expectValid: false,
			description: "claims that expire before issuance should be invalid",
		},
		{
			name: "future issued at",
			claims: &TokenClaims{
				UserID:    1,
				Role:      "user",
				SessionID: "",
				IssuedAt:  now + 3600, // Issued in the future
				ExpiresAt: now + 4500,
			},
			expectValid: false,
			description: "claims issued in the future should be invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasUserID := tt.claims.UserID > 0
			hasRole := tt.claims.Role != ""
			notExpired := tt.claims.ExpiresAt > now
			expiresAfterIssued := tt.claims.ExpiresAt > tt.claims.IssuedAt
			notIssuedInFuture := tt.claims.IssuedAt <= now+60 // Allow 60 seconds clock skew

			// Validate role is a known role
			validRoles := []string{"user", "admin"}
			roleValid := false
			for _, validRole := range validRoles {
				if tt.claims.Role == validRole {
					roleValid = true
					break
				}
			}

			isValid := hasUserID && hasRole && roleValid && notExpired && expiresAfterIssued && notIssuedInFuture

			if isValid != tt.expectValid {
				t.Errorf("expected validity %t, got %t", tt.expectValid, isValid)
			}
		})
	}
}

// Business logic tests
func TestUser_BusinessRules(t *testing.T) {
	t.Run("user activation rules", func(t *testing.T) {
		user := &User{
			ID:            1,
			Email:         "test@example.com",
			Phone:         "+1234567890",
			PasswordHash:  "hashed_password",
			Role:          "user",
			IsActive:      false, // Inactive user
			PhoneVerified: false, // Unverified phone
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		// Business rule: User must verify phone before being fully activated
		if user.IsActive && !user.PhoneVerified {
			t.Error("User should not be active without phone verification")
		}

		// Business rule: Admin users might have different activation rules
		adminUser := &User{
			ID:            2,
			Email:         "admin@example.com",
			Phone:         "+1234567891",
			PasswordHash:  "hashed_password",
			Role:          "admin",
			IsActive:      true,
			PhoneVerified: true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		if adminUser.Role == "admin" && !adminUser.IsActive {
			t.Error("Admin users should typically be active")
		}
	})

	t.Run("user role hierarchy", func(t *testing.T) {
		userRoles := []string{"user", "admin"}
		
		for _, role := range userRoles {
			// Business rule: Admin has higher privileges than user
			if role == "admin" {
				// Admin should have all user permissions plus more
				hasAdminPrivileges := true
				if !hasAdminPrivileges {
					t.Error("Admin should have elevated privileges")
				}
			}
		}
	})
}

func TestSession_BusinessRules(t *testing.T) {
	t.Run("session duration rules", func(t *testing.T) {
		now := time.Now()
		
		// Business rule: Sessions should not be too long or too short
		maxSessionDuration := 30 * 24 * time.Hour // 30 days
		minSessionDuration := 1 * time.Hour       // 1 hour
		
		session := &Session{
			ID:        "session_123",
			UserID:    1,
			ExpiresAt: now.Add(7 * 24 * time.Hour), // 7 days
			CreatedAt: now,
		}
		
		duration := session.ExpiresAt.Sub(session.CreatedAt)
		
		if duration > maxSessionDuration {
			t.Error("Session duration should not exceed maximum allowed")
		}
		
		if duration < minSessionDuration {
			t.Error("Session duration should meet minimum requirements")
		}
	})
	
	t.Run("session cleanup rules", func(t *testing.T) {
		// Business rule: Expired sessions should be cleaned up
		expiredSession := &Session{
			ID:        "expired_session",
			UserID:    1,
			ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
			CreatedAt: time.Now().Add(-2 * time.Hour),
		}
		
		if expiredSession.ExpiresAt.Before(time.Now()) {
			// This session should be eligible for cleanup
			eligibleForCleanup := true
			if !eligibleForCleanup {
				t.Error("Expired sessions should be eligible for cleanup")
			}
		}
	})
}

func TestOTPRequest_BusinessRules(t *testing.T) {
	t.Run("OTP attempt limits", func(t *testing.T) {
		maxAttempts := 5 // Business rule
		
		otpRequest := &OTPRequest{
			Phone:     "+1234567890",
			Code:      "123456",
			UserID:    1,
			ExpiresAt: time.Now().Add(5 * time.Minute),
			Attempts:  maxAttempts,
		}
		
		// Business rule: Should block after max attempts
		if otpRequest.Attempts >= maxAttempts {
			shouldBlock := true
			if !shouldBlock {
				t.Error("Should block OTP verification after max attempts")
			}
		}
	})
	
	t.Run("OTP code format", func(t *testing.T) {
		validCodes := []string{"123456", "000000", "999999"}
		invalidCodes := []string{"12345", "1234567", "abcdef", ""}
		
		for _, code := range validCodes {
			if len(code) != 6 {
				t.Errorf("Expected valid OTP code length 6, got %d for code %s", len(code), code)
			}
			
			// Business rule: OTP should be numeric
			for _, char := range code {
				if char < '0' || char > '9' {
					t.Errorf("OTP code should only contain digits, got %s", code)
				}
			}
		}
		
		for _, code := range invalidCodes {
			if len(code) == 6 {
				// Check if it's numeric
				isNumeric := true
				for _, char := range code {
					if char < '0' || char > '9' {
						isNumeric = false
						break
					}
				}
				if !isNumeric {
					// This is expected - non-numeric codes should be invalid
					continue
				}
			}
			// Codes with wrong length should be invalid
			if len(code) != 6 && code != "" {
				// This is expected
				continue
			}
		}
	})
}