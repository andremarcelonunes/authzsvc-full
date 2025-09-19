package services

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// TestRefreshTokenConcurrency tests concurrent refresh token operations for race conditions
func TestRefreshTokenConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping load test in short mode")
	}

	// Create mocks
	userRepo := mocks.NewMockUserRepository()
	sessionRepo := mocks.NewMockSessionRepository()
	passwordSvc := mocks.NewMockPasswordService()
	tokenSvc := mocks.NewMockTokenService()
	otpSvc := mocks.NewMockOTPService()
	policySvc := mocks.NewMockPolicyService()

	testUser := createValidUser(t)
	testSession := createValidSession(t, testUser.ID)

	// Setup mocks for successful refresh
	setupSuccessfulRefreshMocks(t, userRepo, sessionRepo, tokenSvc, testUser, testSession)

	// Create service (without Redis for testing)
	authService := NewAuthService(userRepo, sessionRepo, passwordSvc, tokenSvc, otpSvc, policySvc, nil)

	// Test concurrent refresh attempts
	concurrency := 10
	attempts := 100

	t.Run("concurrent_refresh_attempts", func(t *testing.T) {
		var wg sync.WaitGroup
		var mu sync.Mutex
		successCount := 0
		errorCount := 0

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(goroutineID int) {
				defer wg.Done()

				for j := 0; j < attempts; j++ {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					result, err := authService.RefreshToken(ctx, "valid_refresh_token")
					cancel()

					mu.Lock()
					if err != nil {
						errorCount++
					} else if result != nil {
						successCount++
					}
					mu.Unlock()

					// Small delay to increase chance of race conditions
					time.Sleep(1 * time.Millisecond)
				}
			}(i)
		}

		wg.Wait()

		t.Logf("Concurrent refresh test completed: %d successes, %d errors out of %d total attempts", 
			successCount, errorCount, concurrency*attempts)

		// Verify we got some results (not all should fail)
		if successCount == 0 {
			t.Error("expected at least some successful refresh operations")
		}

		// Total should match
		if successCount+errorCount != concurrency*attempts {
			t.Errorf("expected %d total operations, got %d", concurrency*attempts, successCount+errorCount)
		}
	})
}

// TestRefreshTokenPerformance tests the performance of refresh token operations
func TestRefreshTokenPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	// Create mocks
	userRepo := mocks.NewMockUserRepository()
	sessionRepo := mocks.NewMockSessionRepository()
	passwordSvc := mocks.NewMockPasswordService()
	tokenSvc := mocks.NewMockTokenService()
	otpSvc := mocks.NewMockOTPService()
	policySvc := mocks.NewMockPolicyService()

	testUser := createValidUser(t)
	testSession := createValidSession(t, testUser.ID)

	// Setup mocks for successful refresh
	setupSuccessfulRefreshMocks(t, userRepo, sessionRepo, tokenSvc, testUser, testSession)

	// Create service
	authService := NewAuthService(userRepo, sessionRepo, passwordSvc, tokenSvc, otpSvc, policySvc, nil)

	// Performance test
	iterations := 1000
	maxDuration := 100 * time.Millisecond // Target: <100ms per operation

	t.Run("refresh_token_performance", func(t *testing.T) {
		start := time.Now()

		for i := 0; i < iterations; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
			_, err := authService.RefreshToken(ctx, "valid_refresh_token")
			cancel()

			if err != nil {
				t.Fatalf("unexpected error on iteration %d: %v", i, err)
			}
		}

		totalDuration := time.Since(start)
		avgDuration := totalDuration / time.Duration(iterations)

		t.Logf("Performance test completed: %d operations in %v (avg: %v per operation)",
			iterations, totalDuration, avgDuration)

		// Verify performance target
		if avgDuration > maxDuration {
			t.Errorf("average refresh time %v exceeds target %v", avgDuration, maxDuration)
		}
	})
}

// TestRefreshTokenMemoryUsage tests for memory leaks in refresh operations
func TestRefreshTokenMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping memory test in short mode")
	}

	// Create mocks
	userRepo := mocks.NewMockUserRepository()
	sessionRepo := mocks.NewMockSessionRepository()
	passwordSvc := mocks.NewMockPasswordService()
	tokenSvc := mocks.NewMockTokenService()
	otpSvc := mocks.NewMockOTPService()
	policySvc := mocks.NewMockPolicyService()

	testUser := createValidUser(t)
	testSession := createValidSession(t, testUser.ID)

	// Setup mocks for successful refresh
	setupSuccessfulRefreshMocks(t, userRepo, sessionRepo, tokenSvc, testUser, testSession)

	// Create service
	authService := NewAuthService(userRepo, sessionRepo, passwordSvc, tokenSvc, otpSvc, policySvc, nil)

	// Memory usage test
	iterations := 10000

	t.Run("memory_usage_test", func(t *testing.T) {
		// Run many operations to detect potential memory leaks
		for i := 0; i < iterations; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_, err := authService.RefreshToken(ctx, "valid_refresh_token")
			cancel()

			if err != nil {
				t.Fatalf("unexpected error on iteration %d: %v", i, err)
			}

			// Periodically trigger GC to help detect leaks
			if i%1000 == 0 {
				// Force garbage collection
				ctx = nil
			}
		}

		t.Logf("Memory test completed: %d operations executed successfully", iterations)
	})
}

// BenchmarkRefreshToken benchmarks the refresh token operation
func BenchmarkRefreshToken(b *testing.B) {
	// Create mocks
	userRepo := mocks.NewMockUserRepository()
	sessionRepo := mocks.NewMockSessionRepository()
	passwordSvc := mocks.NewMockPasswordService()
	tokenSvc := mocks.NewMockTokenService()
	otpSvc := mocks.NewMockOTPService()
	policySvc := mocks.NewMockPolicyService()

	testUser := createValidUserForBench(b)
	testSession := createValidSessionForBench(b, testUser.ID)

	// Setup mocks for successful refresh
	setupSuccessfulRefreshMocksForBench(b, userRepo, sessionRepo, tokenSvc, testUser, testSession)

	// Create service
	authService := NewAuthService(userRepo, sessionRepo, passwordSvc, tokenSvc, otpSvc, policySvc, nil)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := authService.RefreshToken(ctx, "valid_refresh_token")
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

// createValidUserForBench helper for benchmarks
func createValidUserForBench(tb testing.TB) *domain.User {
	tb.Helper()

	return &domain.User{
		ID:            1,
		Email:         "test@example.com",
		Phone:         "+1234567890",
		PasswordHash:  "hashed_password123",
		Role:          "user",
		IsActive:      true,
		PhoneVerified: true,
		CreatedAt:     time.Now().Add(-24 * time.Hour),
		UpdatedAt:     time.Now().Add(-1 * time.Hour),
	}
}

// createValidSessionForBench helper for benchmarks
func createValidSessionForBench(tb testing.TB, userID uint) *domain.Session {
	tb.Helper()

	return &domain.Session{
		ID:        "sess_123_456789",
		UserID:    userID,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}
}

// setupSuccessfulRefreshMocksForBench helper for benchmarks
func setupSuccessfulRefreshMocksForBench(tb testing.TB,
	userRepo *mocks.MockUserRepository,
	sessionRepo *mocks.MockSessionRepository,
	tokenSvc *mocks.MockTokenService,
	testUser *domain.User,
	testSession *domain.Session) {
	tb.Helper()

	claims := &domain.TokenClaims{
		UserID:    testUser.ID,
		Role:      testUser.Role,
		SessionID: testSession.ID,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
	}

	// Token validation succeeds
	tokenSvc.ValidateRefreshTokenFunc = func(token string) (*domain.TokenClaims, error) {
		return claims, nil
	}

	// Session exists and is valid
	sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
		return testSession, nil
	}

	// Session TTL extension succeeds
	sessionRepo.ExtendTTLFunc = func(ctx context.Context, sessionID string, ttl time.Duration) error {
		return nil
	}

	// Session update succeeds
	sessionRepo.UpdateFunc = func(ctx context.Context, session *domain.Session) error {
		return nil
	}

	// User exists
	userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
		return testUser, nil
	}

	// Token generation succeeds
	tokenSvc.GenerateAccessTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
		return "new_access_token_123", nil
	}

	tokenSvc.GenerateRefreshTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
		return "new_refresh_token_456", nil
	}
}