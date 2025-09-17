package domain

import (
	"errors"
	"testing"
)

func TestAuthenticationErrors(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		expectedMsg   string
		description   string
	}{
		{
			name:        "ErrUserNotFound",
			err:         ErrUserNotFound,
			expectedMsg: "user not found",
			description: "should indicate user lookup failure",
		},
		{
			name:        "ErrInvalidCredentials",
			err:         ErrInvalidCredentials,
			expectedMsg: "invalid credentials",
			description: "should indicate authentication failure",
		},
		{
			name:        "ErrUserAlreadyExists",
			err:         ErrUserAlreadyExists,
			expectedMsg: "user already exists",
			description: "should indicate duplicate user registration",
		},
		{
			name:        "ErrUserInactive",
			err:         ErrUserInactive,
			expectedMsg: "user account is inactive",
			description: "should indicate account is disabled",
		},
		{
			name:        "ErrPhoneNotVerified",
			err:         ErrPhoneNotVerified,
			expectedMsg: "phone number not verified",
			description: "should indicate phone verification required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("error should not be nil")
			}

			if tt.err.Error() != tt.expectedMsg {
				t.Errorf("expected error message %q, got %q", tt.expectedMsg, tt.err.Error())
			}

			// Test error identity
			if !errors.Is(tt.err, tt.err) {
				t.Error("error should be equal to itself")
			}

			// Test that these are different errors
			for _, other := range tests {
				if other.name != tt.name && errors.Is(tt.err, other.err) {
					t.Errorf("error %s should not be equal to %s", tt.name, other.name)
				}
			}
		})
	}
}

func TestOTPErrors(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		expectedMsg   string
		description   string
	}{
		{
			name:        "ErrOTPExpired",
			err:         ErrOTPExpired,
			expectedMsg: "otp has expired",
			description: "should indicate OTP time limit exceeded",
		},
		{
			name:        "ErrOTPInvalid",
			err:         ErrOTPInvalid,
			expectedMsg: "invalid otp code",
			description: "should indicate wrong OTP code",
		},
		{
			name:        "ErrOTPMaxAttempts",
			err:         ErrOTPMaxAttempts,
			expectedMsg: "maximum otp attempts exceeded",
			description: "should indicate too many failed attempts",
		},
		{
			name:        "ErrOTPNotFound",
			err:         ErrOTPNotFound,
			expectedMsg: "otp not found",
			description: "should indicate no OTP exists for phone",
		},
		{
			name:        "ErrOTPResendLimit",
			err:         ErrOTPResendLimit,
			expectedMsg: "otp resend limit exceeded",
			description: "should indicate resend throttling",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("error should not be nil")
			}

			if tt.err.Error() != tt.expectedMsg {
				t.Errorf("expected error message %q, got %q", tt.expectedMsg, tt.err.Error())
			}

			// Test error identity
			if !errors.Is(tt.err, tt.err) {
				t.Error("error should be equal to itself")
			}

			// Test that these are different errors
			for _, other := range tests {
				if other.name != tt.name && errors.Is(tt.err, other.err) {
					t.Errorf("error %s should not be equal to %s", tt.name, other.name)
				}
			}
		})
	}
}

func TestTokenErrors(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		expectedMsg   string
		description   string
	}{
		{
			name:        "ErrTokenInvalid",
			err:         ErrTokenInvalid,
			expectedMsg: "invalid token",
			description: "should indicate token validation failure",
		},
		{
			name:        "ErrTokenExpired",
			err:         ErrTokenExpired,
			expectedMsg: "token has expired",
			description: "should indicate token time limit exceeded",
		},
		{
			name:        "ErrTokenMalformed",
			err:         ErrTokenMalformed,
			expectedMsg: "malformed token",
			description: "should indicate token structure issues",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("error should not be nil")
			}

			if tt.err.Error() != tt.expectedMsg {
				t.Errorf("expected error message %q, got %q", tt.expectedMsg, tt.err.Error())
			}

			// Test error identity
			if !errors.Is(tt.err, tt.err) {
				t.Error("error should be equal to itself")
			}

			// Test that these are different errors
			for _, other := range tests {
				if other.name != tt.name && errors.Is(tt.err, other.err) {
					t.Errorf("error %s should not be equal to %s", tt.name, other.name)
				}
			}
		})
	}
}

func TestSessionErrors(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		expectedMsg   string
		description   string
	}{
		{
			name:        "ErrSessionNotFound",
			err:         ErrSessionNotFound,
			expectedMsg: "session not found",
			description: "should indicate session lookup failure",
		},
		{
			name:        "ErrSessionExpired",
			err:         ErrSessionExpired,
			expectedMsg: "session has expired",
			description: "should indicate session time limit exceeded",
		},
		{
			name:        "ErrSessionRevoked",
			err:         ErrSessionRevoked,
			expectedMsg: "session has been revoked",
			description: "should indicate session was manually terminated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("error should not be nil")
			}

			if tt.err.Error() != tt.expectedMsg {
				t.Errorf("expected error message %q, got %q", tt.expectedMsg, tt.err.Error())
			}

			// Test error identity
			if !errors.Is(tt.err, tt.err) {
				t.Error("error should be equal to itself")
			}

			// Test that these are different errors
			for _, other := range tests {
				if other.name != tt.name && errors.Is(tt.err, other.err) {
					t.Errorf("error %s should not be equal to %s", tt.name, other.name)
				}
			}
		})
	}
}

func TestAuthorizationErrors(t *testing.T) {
	tests := []struct {
		name          string
		err           error
		expectedMsg   string
		description   string
	}{
		{
			name:        "ErrUnauthorized",
			err:         ErrUnauthorized,
			expectedMsg: "unauthorized access",
			description: "should indicate access denied",
		},
		{
			name:        "ErrInsufficientRole",
			err:         ErrInsufficientRole,
			expectedMsg: "insufficient role permissions",
			description: "should indicate role-based access denial",
		},
		{
			name:        "ErrResourceNotFound",
			err:         ErrResourceNotFound,
			expectedMsg: "resource not found",
			description: "should indicate requested resource doesn't exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("error should not be nil")
			}

			if tt.err.Error() != tt.expectedMsg {
				t.Errorf("expected error message %q, got %q", tt.expectedMsg, tt.err.Error())
			}

			// Test error identity
			if !errors.Is(tt.err, tt.err) {
				t.Error("error should be equal to itself")
			}

			// Test that these are different errors
			for _, other := range tests {
				if other.name != tt.name && errors.Is(tt.err, other.err) {
					t.Errorf("error %s should not be equal to %s", tt.name, other.name)
				}
			}
		})
	}
}

// Test error categorization and handling
func TestErrorCategories(t *testing.T) {
	t.Run("authentication error category", func(t *testing.T) {
		authErrors := []error{
			ErrUserNotFound,
			ErrInvalidCredentials,
			ErrUserAlreadyExists,
			ErrUserInactive,
			ErrPhoneNotVerified,
		}

		for _, err := range authErrors {
			// Test that these are all authentication-related errors
			if err == nil {
				t.Error("authentication error should not be nil")
			}

			// These errors should be user-facing but not reveal sensitive information
			msg := err.Error()
			if msg == "" {
				t.Error("authentication error should have a message")
			}

			// Should not contain sensitive information like "password"
			if contains(msg, "password") || contains(msg, "hash") {
				t.Errorf("authentication error message should not contain sensitive info: %s", msg)
			}
		}
	})

	t.Run("OTP error category", func(t *testing.T) {
		otpErrors := []error{
			ErrOTPExpired,
			ErrOTPInvalid,
			ErrOTPMaxAttempts,
			ErrOTPNotFound,
			ErrOTPResendLimit,
		}

		for _, err := range otpErrors {
			// All OTP errors should be related to verification process
			if err == nil {
				t.Error("OTP error should not be nil")
			}

			// These errors should guide the user on next steps
			msg := err.Error()
			if msg == "" {
				t.Error("OTP error should have a message")
			}

			// Should mention OTP in the message (except for ErrOTPResendLimit)
			if err != ErrOTPResendLimit && !contains(msg, "otp") {
				t.Errorf("OTP error should mention otp in message: %s", msg)
			}
		}
	})

	t.Run("token error category", func(t *testing.T) {
		tokenErrors := []error{
			ErrTokenInvalid,
			ErrTokenExpired,
			ErrTokenMalformed,
		}

		for _, err := range tokenErrors {
			// All token errors should be related to JWT validation
			if err == nil {
				t.Error("token error should not be nil")
			}

			// These errors should mention token
			msg := err.Error()
			if !contains(msg, "token") {
				t.Errorf("token error should mention token in message: %s", msg)
			}
		}
	})

	t.Run("session error category", func(t *testing.T) {
		sessionErrors := []error{
			ErrSessionNotFound,
			ErrSessionExpired,
			ErrSessionRevoked,
		}

		for _, err := range sessionErrors {
			// All session errors should be related to session management
			if err == nil {
				t.Error("session error should not be nil")
			}

			// These errors should mention session
			msg := err.Error()
			if !contains(msg, "session") {
				t.Errorf("session error should mention session in message: %s", msg)
			}
		}
	})

	t.Run("authorization error category", func(t *testing.T) {
		authzErrors := []error{
			ErrUnauthorized,
			ErrInsufficientRole,
			ErrResourceNotFound,
		}

		for _, err := range authzErrors {
			// All authorization errors should be related to access control
			if err == nil {
				t.Error("authorization error should not be nil")
			}

			// These errors should not reveal too much about system internals
			msg := err.Error()
			if msg == "" {
				t.Error("authorization error should have a message")
			}

			// Should not reveal internal structure details
			if contains(msg, "database") || contains(msg, "internal") {
				t.Errorf("authorization error should not reveal internal details: %s", msg)
			}
		}
	})
}

// Test error wrapping and unwrapping
func TestErrorWrapping(t *testing.T) {
	t.Run("error wrapping with context", func(t *testing.T) {
		baseErr := ErrUserNotFound
		wrappedErr := errors.New("database connection failed: " + baseErr.Error())

		// Test that wrapped error contains original message
		if !contains(wrappedErr.Error(), baseErr.Error()) {
			t.Error("wrapped error should contain original error message")
		}
	})

	t.Run("error comparison with errors.Is", func(t *testing.T) {
		// Test that errors.Is works correctly with our domain errors
		testCases := []struct {
			err    error
			target error
			should bool
		}{
			{ErrUserNotFound, ErrUserNotFound, true},
			{ErrUserNotFound, ErrInvalidCredentials, false},
			{ErrOTPExpired, ErrOTPExpired, true},
			{ErrOTPExpired, ErrOTPInvalid, false},
		}

		for _, tc := range testCases {
			if errors.Is(tc.err, tc.target) != tc.should {
				t.Errorf("errors.Is(%v, %v) should be %t", tc.err, tc.target, tc.should)
			}
		}
	})
}

// Test error handling best practices
func TestErrorHandlingBestPractices(t *testing.T) {
	t.Run("all errors have non-empty messages", func(t *testing.T) {
		allErrors := []error{
			// Authentication errors
			ErrUserNotFound,
			ErrInvalidCredentials,
			ErrUserAlreadyExists,
			ErrUserInactive,
			ErrPhoneNotVerified,
			// OTP errors
			ErrOTPExpired,
			ErrOTPInvalid,
			ErrOTPMaxAttempts,
			ErrOTPNotFound,
			ErrOTPResendLimit,
			// Token errors
			ErrTokenInvalid,
			ErrTokenExpired,
			ErrTokenMalformed,
			// Session errors
			ErrSessionNotFound,
			ErrSessionExpired,
			ErrSessionRevoked,
			// Authorization errors
			ErrUnauthorized,
			ErrInsufficientRole,
			ErrResourceNotFound,
		}

		for _, err := range allErrors {
			if err == nil {
				t.Error("domain error should not be nil")
				continue
			}

			msg := err.Error()
			if msg == "" {
				t.Errorf("domain error should have non-empty message: %v", err)
			}

			// Should not start with capital letter (Go convention)
			if len(msg) > 0 && msg[0] >= 'A' && msg[0] <= 'Z' {
				t.Errorf("error message should start with lowercase letter: %s", msg)
			}

			// Should not end with punctuation
			if len(msg) > 0 && (msg[len(msg)-1] == '.' || msg[len(msg)-1] == '!') {
				t.Errorf("error message should not end with punctuation: %s", msg)
			}
		}
	})

	t.Run("errors are distinct", func(t *testing.T) {
		allErrors := []error{
			ErrUserNotFound, ErrInvalidCredentials, ErrUserAlreadyExists, ErrUserInactive, ErrPhoneNotVerified,
			ErrOTPExpired, ErrOTPInvalid, ErrOTPMaxAttempts, ErrOTPNotFound, ErrOTPResendLimit,
			ErrTokenInvalid, ErrTokenExpired, ErrTokenMalformed,
			ErrSessionNotFound, ErrSessionExpired, ErrSessionRevoked,
			ErrUnauthorized, ErrInsufficientRole, ErrResourceNotFound,
		}

		// Check that all errors are distinct
		seen := make(map[string]bool)
		for _, err := range allErrors {
			if err == nil {
				continue
			}

			msg := err.Error()
			if seen[msg] {
				t.Errorf("duplicate error message found: %s", msg)
			}
			seen[msg] = true
		}

		// Should have at least 15 unique errors
		if len(seen) < 15 {
			t.Errorf("expected at least 15 unique error messages, got %d", len(seen))
		}
	})
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && 
		(s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || 
		 containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}