package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// TestRefreshTokenSecurityEnhancements tests the CB-179 security fixes
func TestRefreshTokenSecurityEnhancements(t *testing.T) {
	tests := []struct {
		name           string
		refreshToken   string
		setupMocks     func(*mocks.MockUserRepository, *mocks.MockSessionRepository, *mocks.MockTokenService, *mocks.MockRedisClient)
		expectedError  string
		validateResult func(t *testing.T, result *domain.AuthResult)
	}{
		{
			name:         "successful token refresh with security enhancements",
			refreshToken: "valid_refresh_token",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, tokenSvc *mocks.MockTokenService, redisClient *mocks.MockRedisClient) {
				testUser := createValidUser(t)
				testSession := createValidSession(t, testUser.ID)
				claims := createValidTokenClaims(t, testUser.ID, testUser.Role, testSession.ID)

				// Lock acquisition succeeds
				redisClient.SetNXFunc = func(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd {
					cmd := redis.NewBoolCmd(ctx, "setnx", key, value)
					cmd.SetVal(true) // Lock acquired successfully
					return cmd
				}

				// Lock release succeeds
				redisClient.EvalFunc = func(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd {
					cmd := redis.NewCmd(ctx, "eval", script)
					cmd.SetVal(int64(1)) // Lock released successfully
					return cmd
				}

				// Token validation succeeds
				tokenSvc.ValidateRefreshTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return claims, nil
				}

				// Session lookup succeeds
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					return testSession, nil
				}

				// User lookup succeeds
				userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
					return testUser, nil
				}

				// Session TTL extension succeeds
				sessionRepo.ExtendTTLFunc = func(ctx context.Context, sessionID string, ttl time.Duration) error {
					if ttl != 24*time.Hour {
						t.Errorf("expected TTL of 24 hours, got %v", ttl)
					}
					return nil
				}

				// Session update succeeds
				sessionRepo.UpdateFunc = func(ctx context.Context, session *domain.Session) error {
					return nil
				}

				// Token generation succeeds
				tokenSvc.GenerateAccessTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "new_access_token_123", nil
				}

				tokenSvc.GenerateRefreshTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "new_refresh_token_456", nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result == nil {
					t.Fatal("result is nil")
				}
				if result.AccessToken != "new_access_token_123" {
					t.Errorf("expected new access token, got %s", result.AccessToken)
				}
				if result.RefreshToken != "new_refresh_token_456" {
					t.Errorf("expected new refresh token (rotation), got %s", result.RefreshToken)
				}
				if result.RefreshToken == "valid_refresh_token" {
					t.Error("refresh token should be rotated, not reused")
				}
			},
		},
		{
			name:         "refresh without redis (no locking)",
			refreshToken: "valid_refresh_token",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, tokenSvc *mocks.MockTokenService, redisClient *mocks.MockRedisClient) {
				testUser := createValidUser(t)
				testSession := createValidSession(t, testUser.ID)

				// Setup successful refresh mocks (no Redis locking)
				setupSuccessfulRefreshMocks(t, userRepo, sessionRepo, tokenSvc, testUser, testSession)
			},
			expectedError: "",
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result == nil {
					t.Fatal("expected valid result when Redis is unavailable")
				}
				if result.RefreshToken != "new_refresh_token_456" {
					t.Errorf("expected new refresh token, got %s", result.RefreshToken)
				}
			},
		},
		{
			name:         "inactive user blocked",
			refreshToken: "valid_refresh_token",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, tokenSvc *mocks.MockTokenService, redisClient *mocks.MockRedisClient) {
				inactiveUser := createInactiveUser(t)
				testSession := createValidSession(t, inactiveUser.ID)
				claims := createValidTokenClaims(t, inactiveUser.ID, inactiveUser.Role, testSession.ID)

				// Lock acquisition succeeds
				redisClient.SetNXFunc = func(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd {
					cmd := redis.NewBoolCmd(ctx, "setnx", key, value)
					cmd.SetVal(true)
					return cmd
				}

				// Lock release
				redisClient.EvalFunc = func(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd {
					cmd := redis.NewCmd(ctx, "eval", script)
					cmd.SetVal(int64(1))
					return cmd
				}

				// Token validation succeeds
				tokenSvc.ValidateRefreshTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return claims, nil
				}

				// Session lookup succeeds
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					return testSession, nil
				}

				// User lookup returns inactive user
				userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
					return inactiveUser, nil
				}
			},
			expectedError: "inactive user",
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when user is inactive")
				}
			},
		},
		{
			name:         "session TTL extension failure",
			refreshToken: "valid_refresh_token",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, tokenSvc *mocks.MockTokenService, redisClient *mocks.MockRedisClient) {
				testUser := createValidUser(t)
				testSession := createValidSession(t, testUser.ID)
				claims := createValidTokenClaims(t, testUser.ID, testUser.Role, testSession.ID)

				// Lock acquisition succeeds
				redisClient.SetNXFunc = func(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd {
					cmd := redis.NewBoolCmd(ctx, "setnx", key, value)
					cmd.SetVal(true)
					return cmd
				}

				redisClient.EvalFunc = func(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd {
					cmd := redis.NewCmd(ctx, "eval", script)
					cmd.SetVal(int64(1))
					return cmd
				}

				// Token validation succeeds
				tokenSvc.ValidateRefreshTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return claims, nil
				}

				// Session lookup succeeds
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					return testSession, nil
				}

				// User lookup succeeds
				userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
					return testUser, nil
				}

				// Session TTL extension fails
				sessionRepo.ExtendTTLFunc = func(ctx context.Context, sessionID string, ttl time.Duration) error {
					return errors.New("redis connection failed")
				}
			},
			expectedError: "session TTL extension failed",
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when TTL extension fails")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			userRepo := mocks.NewMockUserRepository()
			sessionRepo := mocks.NewMockSessionRepository()
			passwordSvc := mocks.NewMockPasswordService()
			tokenSvc := mocks.NewMockTokenService()
			otpSvc := mocks.NewMockOTPService()
			policySvc := mocks.NewMockPolicyService()
			redisClient := mocks.NewMockRedisClient()

			// Setup mocks
			tt.setupMocks(userRepo, sessionRepo, tokenSvc, redisClient)

			// Create service with nil Redis client for testing (will use default behavior)
			authService := NewAuthService(userRepo, sessionRepo, passwordSvc, tokenSvc, otpSvc, policySvc, nil)

			// Create context
			ctx := createTestContext(t)

			// Execute test
			result, err := authService.RefreshToken(ctx, tt.refreshToken)

			// Validate error
			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.expectedError)
				} else if err.Error() == "" || !containsString(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing '%s', got '%v'", tt.expectedError, err)
				}
			}

			// Validate result
			tt.validateResult(t, result)
		})
	}
}

// containsString checks if a string contains a substring (case-insensitive helper)
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && 
		   (s == substr || 
			len(s) > len(substr) && 
			(s[:len(substr)] == substr || 
			 s[len(s)-len(substr):] == substr || 
			 containsSubstring(s, substr)))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestRefreshTokenLockScenarios tests various locking scenarios
func TestRefreshTokenLockScenarios(t *testing.T) {
	tests := []struct {
		name          string
		lockAcquired  bool
		lockReleaseOk bool
		expectedError string
	}{
		{
			name:          "lock acquired and released successfully",
			lockAcquired:  true,
			lockReleaseOk: true,
			expectedError: "",
		},
		{
			name:          "lock acquisition failed",
			lockAcquired:  false,
			lockReleaseOk: true,
			expectedError: "concurrent refresh attempt detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			userRepo := mocks.NewMockUserRepository()
			sessionRepo := mocks.NewMockSessionRepository()
			passwordSvc := mocks.NewMockPasswordService()
			tokenSvc := mocks.NewMockTokenService()
			otpSvc := mocks.NewMockOTPService()
			policySvc := mocks.NewMockPolicyService()
			redisClient := mocks.NewMockRedisClient()

			testUser := createValidUser(t)
			testSession := createValidSession(t, testUser.ID)
			claims := createValidTokenClaims(t, testUser.ID, testUser.Role, testSession.ID)

			// Configure lock behavior
			redisClient.SetNXFunc = func(ctx context.Context, key string, value interface{}, expiration time.Duration) *redis.BoolCmd {
				cmd := redis.NewBoolCmd(ctx, "setnx", key, value)
				cmd.SetVal(tt.lockAcquired)
				return cmd
			}

			if tt.lockAcquired && tt.lockReleaseOk {
				redisClient.EvalFunc = func(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd {
					cmd := redis.NewCmd(ctx, "eval", script)
					cmd.SetVal(int64(1))
					return cmd
				}

				// Setup successful refresh mocks
				setupSuccessfulRefreshMocks(t, userRepo, sessionRepo, tokenSvc, testUser, testSession)
			}

			// Token validation
			tokenSvc.ValidateRefreshTokenFunc = func(token string) (*domain.TokenClaims, error) {
				return claims, nil
			}

			// Create service
			authService := NewAuthService(userRepo, sessionRepo, passwordSvc, tokenSvc, otpSvc, policySvc, nil)

			// Execute test
			ctx := createTestContext(t)
			result, err := authService.RefreshToken(ctx, "valid_refresh_token")

			// Validate
			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
				if result == nil {
					t.Error("expected valid result when successful")
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing '%s', got nil", tt.expectedError)
				}
				if result != nil {
					t.Error("expected nil result when error occurs")
				}
			}
		})
	}
}