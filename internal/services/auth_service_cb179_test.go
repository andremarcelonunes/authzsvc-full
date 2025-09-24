package services

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// TestRefreshTokenSecurityEnhancements tests the CB-179 security fixes
func TestRefreshTokenSecurityEnhancements(t *testing.T) {
	// Start miniredis server for testing
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	// Create real Redis client that connects to miniredis
	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	tests := []struct {
		name           string
		refreshToken   string
		setupMocks     func(*mocks.MockUserRepository, *mocks.MockSessionRepository, *mocks.MockTokenService)
		setupRedis     func() // Setup Redis state before test
		expectedError  string
		validateResult func(t *testing.T, result *domain.AuthResult)
		validateRedis  func() // Validate Redis state after test
	}{
		{
			name:         "successful token refresh with security enhancements",
			refreshToken: fmt.Sprintf("valid_refresh_token_%d", time.Now().UnixNano()),
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, tokenSvc *mocks.MockTokenService) {
				testUser := createValidUser(t)
				testSession := createValidSession(t, testUser.ID)
				claims := createValidTokenClaims(t, testUser.ID, testUser.Role, testSession.ID)

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
			setupRedis: func() {
				// Redis starts clean - no tokens blacklisted
				mr.FlushAll()
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
			},
			validateRedis: func() {
				// Verify the old token was blacklisted (check if it exists in Redis)
				ctx := context.Background()
				// The token should be blacklisted with a hash key
				keys, _ := redisClient.Keys(ctx, "blacklist:refresh:*").Result()
				if len(keys) != 1 {
					t.Errorf("expected 1 blacklisted token, found %d", len(keys))
				}
			},
		},
		{
			name:         "token reuse prevented (blacklisted token)",
			refreshToken: "already_used_token",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, tokenSvc *mocks.MockTokenService) {
				testUser := createValidUser(t)
				testSession := createValidSession(t, testUser.ID)
				claims := createValidTokenClaims(t, testUser.ID, testUser.Role, testSession.ID)

				// Token validation succeeds (token is valid JWT)
				tokenSvc.ValidateRefreshTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return claims, nil
				}
			},
			setupRedis: func() {
				// Blacklist this token before the test (simulate it was already used)
				ctx := context.Background()
				tokenHash := fmt.Sprintf("blacklist:refresh:%x", sha256.Sum256([]byte("already_used_token")))
				redisClient.Set(ctx, tokenHash, "revoked", 1*time.Hour)
			},
			expectedError: "refresh token already used (blacklisted)",
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected nil result when token is blacklisted")
				}
			},
			validateRedis: func() {
				// Token should still be blacklisted
				ctx := context.Background()
				tokenHash := fmt.Sprintf("blacklist:refresh:%x", sha256.Sum256([]byte("already_used_token")))
				exists := redisClient.Exists(ctx, tokenHash).Val()
				if exists == 0 {
					t.Error("token should remain blacklisted")
				}
			},
		},
		{
			name:         "inactive user blocked", 
			refreshToken: fmt.Sprintf("valid_refresh_token_3_%d", time.Now().UnixNano()),
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, tokenSvc *mocks.MockTokenService) {
				inactiveUser := createInactiveUser(t)
				testSession := createValidSession(t, inactiveUser.ID)
				claims := createValidTokenClaims(t, inactiveUser.ID, inactiveUser.Role, testSession.ID)

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
			setupRedis: func() {
				// Redis starts clean
				mr.FlushAll()
			},
			expectedError: "inactive user",
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when user is inactive")
				}
			},
			validateRedis: func() {
				// No tokens should be blacklisted since operation failed early
				ctx := context.Background()
				keys, _ := redisClient.Keys(ctx, "blacklist:refresh:*").Result()
				if len(keys) != 0 {
					t.Errorf("expected no blacklisted tokens for failed operation, found %d", len(keys))
				}
			},
		},
		{
			name:         "session TTL extension failure",
			refreshToken: fmt.Sprintf("valid_refresh_token_4_%d", time.Now().UnixNano()),
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, tokenSvc *mocks.MockTokenService) {
				testUser := createValidUser(t)
				testSession := createValidSession(t, testUser.ID)
				claims := createValidTokenClaims(t, testUser.ID, testUser.Role, testSession.ID)

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
			setupRedis: func() {
				// Redis starts clean
				mr.FlushAll()
			},
			expectedError: "session TTL extension failed",
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when TTL extension fails")
				}
			},
			validateRedis: func() {
				// No tokens should be blacklisted since operation failed
				ctx := context.Background()
				keys, _ := redisClient.Keys(ctx, "blacklist:refresh:*").Result()
				if len(keys) != 0 {
					t.Errorf("expected no blacklisted tokens for failed operation, found %d", len(keys))
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

			// Setup mocks
			tt.setupMocks(userRepo, sessionRepo, tokenSvc)
			
			// Setup Redis state
			if tt.setupRedis != nil {
				tt.setupRedis()
			}
			
			// Create service with real Redis client (miniredis)
			authService := NewAuthService(userRepo, sessionRepo, passwordSvc, tokenSvc, otpSvc, policySvc, redisClient, nil, nil)

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
			
			// Validate Redis state
			if tt.validateRedis != nil {
				tt.validateRedis()
			}
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
	// Start miniredis server for testing
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	// Create real Redis client that connects to miniredis
	redisClient := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	tests := []struct {
		name          string
		simulateLockTaken bool // Simulate lock already taken
		expectedError string
	}{
		{
			name:          "lock acquired and released successfully",
			simulateLockTaken: false,
			expectedError: "",
		},
		{
			name:          "lock acquisition failed - concurrent refresh",
			simulateLockTaken: true,
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

			testUser := createValidUser(t)
			testSession := createValidSession(t, testUser.ID)
			claims := createValidTokenClaims(t, testUser.ID, testUser.Role, testSession.ID)
			
			// Clean Redis before test
			mr.FlushAll()

			// Simulate lock already taken if needed
			if tt.simulateLockTaken {
				ctx := context.Background()
				lockKey := fmt.Sprintf("refresh_lock:%s", testSession.ID)
				redisClient.SetNX(ctx, lockKey, "locked", 30*time.Second)
			}

			// Token validation succeeds
			tokenSvc.ValidateRefreshTokenFunc = func(token string) (*domain.TokenClaims, error) {
				return claims, nil
			}
			
			// Setup other necessary mocks
			userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
				return testUser, nil
			}
			
			sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
				return testSession, nil
			}
			
			sessionRepo.ExtendTTLFunc = func(ctx context.Context, sessionID string, ttl time.Duration) error {
				return nil
			}
			
			sessionRepo.UpdateFunc = func(ctx context.Context, session *domain.Session) error {
				return nil
			}
			
			tokenSvc.GenerateAccessTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
				return "new_access_token", nil
			}
			
			tokenSvc.GenerateRefreshTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
				return "new_refresh_token", nil
			}

			// Create service with real Redis client
			authService := NewAuthService(userRepo, sessionRepo, passwordSvc, tokenSvc, otpSvc, policySvc, redisClient, nil, nil)

			// Execute test
			ctx := createTestContext(t)
			result, err := authService.RefreshToken(ctx, fmt.Sprintf("valid_refresh_token_%d", time.Now().UnixNano()))

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
				} else if !containsString(err.Error(), tt.expectedError) {
					t.Errorf("expected error containing '%s', got '%v'", tt.expectedError, err)
				}
				if result != nil {
					t.Error("expected nil result when error occurs")
				}
			}
		})
	}
}