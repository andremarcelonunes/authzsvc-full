package services

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// createAuthServiceForTest creates an AuthService with mock dependencies for testing
func createAuthServiceForTest(t *testing.T, 
	userRepo domain.UserRepository,
	sessionRepo domain.SessionRepository,
	passwordSvc domain.PasswordService,
	tokenSvc domain.TokenService,
	otpSvc domain.OTPService,
	policySvc domain.PolicyService,
	redisClient *redis.Client) domain.AuthService {
	t.Helper()

	// Use provided mocks or create defaults
	if userRepo == nil {
		userRepo = mocks.NewMockUserRepository()
	}
	if sessionRepo == nil {
		sessionRepo = mocks.NewMockSessionRepository()
	}
	if passwordSvc == nil {
		passwordSvc = mocks.NewMockPasswordService()
	}
	if tokenSvc == nil {
		tokenSvc = mocks.NewMockTokenService()
	}
	if otpSvc == nil {
		otpSvc = mocks.NewMockOTPService()
	}
	if policySvc == nil {
		policySvc = mocks.NewMockPolicyService()
	}
	// Leave redisClient as nil for tests that don't need Redis
	// This allows graceful degradation in blacklist functionality

	return NewAuthService(userRepo, sessionRepo, passwordSvc, tokenSvc, otpSvc, policySvc, redisClient)
}

// createValidUser creates a valid user entity for testing
func createValidUser(t *testing.T) *domain.User {
	t.Helper()

	return &domain.User{
		ID:            1,
		Email:         "test@example.com",
		Phone:         "+1234567890",
		PasswordHash:  "hashed_password123",
		Role:          "user",
		IsActive:      true,
		PhoneVerified: true,
		CreatedAt:     time.Now().Add(-24 * time.Hour), // Created yesterday
		UpdatedAt:     time.Now().Add(-1 * time.Hour),  // Updated 1 hour ago
	}
}

// createInactiveUser creates an inactive user entity for testing
func createInactiveUser(t *testing.T) *domain.User {
	t.Helper()

	user := createValidUser(t)
	user.IsActive = false
	return user
}

// createAdminUser creates an admin user entity for testing
func createAdminUser(t *testing.T) *domain.User {
	t.Helper()

	user := createValidUser(t)
	user.ID = 2
	user.Email = "admin@example.com"
	user.Role = "admin"
	return user
}

// createValidSession creates a valid session entity for testing
func createValidSession(t *testing.T, userID uint) *domain.Session {
	t.Helper()

	return &domain.Session{
		ID:        "sess_123_456789",
		UserID:    userID,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // Expires in 7 days
		CreatedAt: time.Now(),
	}
}

// createExpiredSession creates an expired session entity for testing
func createExpiredSession(t *testing.T, userID uint) *domain.Session {
	t.Helper()

	return &domain.Session{
		ID:        "sess_expired_123",
		UserID:    userID,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired 1 hour ago
		CreatedAt: time.Now().Add(-2 * time.Hour), // Created 2 hours ago
	}
}

// createValidTokenClaims creates valid token claims for testing
func createValidTokenClaims(t *testing.T, userID uint, role string, sessionID string) *domain.TokenClaims {
	t.Helper()

	now := time.Now().Unix()
	return &domain.TokenClaims{
		UserID:    userID,
		Role:      role,
		SessionID: sessionID,
		IssuedAt:  now,
		ExpiresAt: now + 900, // 15 minutes
	}
}

// createExpiredTokenClaims creates expired token claims for testing
func createExpiredTokenClaims(t *testing.T, userID uint, role string, sessionID string) *domain.TokenClaims {
	t.Helper()

	now := time.Now().Unix()
	return &domain.TokenClaims{
		UserID:    userID,
		Role:      role,
		SessionID: sessionID,
		IssuedAt:  now - 1800, // Issued 30 minutes ago
		ExpiresAt: now - 900,  // Expired 15 minutes ago
	}
}

// createOTPRequest creates a valid OTP request for testing
func createOTPRequest(t *testing.T, phone string, userID uint) *domain.OTPRequest {
	t.Helper()

	return &domain.OTPRequest{
		Phone:     phone,
		Code:      "123456",
		UserID:    userID,
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Attempts:  0,
	}
}

// assertAuthResult validates the structure and content of an AuthResult
func assertAuthResult(t *testing.T, result *domain.AuthResult, expectedUser *domain.User) {
	t.Helper()

	if result == nil {
		t.Fatal("AuthResult is nil")
	}

	if result.User == nil {
		t.Fatal("AuthResult.User is nil")
	}

	if result.User.ID != expectedUser.ID {
		t.Errorf("expected user ID %d, got %d", expectedUser.ID, result.User.ID)
	}

	if result.User.Email != expectedUser.Email {
		t.Errorf("expected user email %s, got %s", expectedUser.Email, result.User.Email)
	}

	if result.AccessToken == "" {
		t.Error("AccessToken is empty")
	}

	if result.RefreshToken == "" {
		t.Error("RefreshToken is empty")
	}

	if result.SessionID == "" {
		t.Error("SessionID is empty")
	}

	if result.ExpiresIn <= 0 {
		t.Errorf("expected positive ExpiresIn, got %d", result.ExpiresIn)
	}
}

// createTestContext creates a context for testing with timeout
func createTestContext(t *testing.T) context.Context {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// setupSuccessfulRegisterMocks configures mocks for a successful user registration
func setupSuccessfulRegisterMocks(t *testing.T, 
	userRepo *mocks.MockUserRepository,
	passwordSvc *mocks.MockPasswordService,
	otpSvc *mocks.MockOTPService) {
	t.Helper()

	// User doesn't exist yet
	userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
		return nil, domain.ErrUserNotFound
	}

	// Password hashing succeeds
	passwordSvc.HashFunc = func(password string) (string, error) {
		return "hashed_" + password, nil
	}

	// User creation succeeds
	userRepo.CreateFunc = func(ctx context.Context, user *domain.User) error {
		user.ID = 1 // Simulate database assignment
		return nil
	}

	// OTP generation succeeds
	otpSvc.GenerateFunc = func(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) {
		return createOTPRequest(t, phone, userID), nil
	}
}

// setupSuccessfulLoginMocks configures mocks for a successful user login
func setupSuccessfulLoginMocks(t *testing.T,
	userRepo *mocks.MockUserRepository,
	sessionRepo *mocks.MockSessionRepository,
	passwordSvc *mocks.MockPasswordService,
	tokenSvc *mocks.MockTokenService,
	testUser *domain.User) {
	t.Helper()

	// User exists and is found
	userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
		if email == testUser.Email {
			return testUser, nil
		}
		return nil, domain.ErrUserNotFound
	}

	// Password verification succeeds
	passwordSvc.VerifyFunc = func(hashedPassword, password string) bool {
		return hashedPassword == "hashed_password123" && password == "password123"
	}

	// Session creation succeeds
	sessionRepo.CreateFunc = func(ctx context.Context, session *domain.Session) error {
		return nil
	}

	// Token generation succeeds
	tokenSvc.GenerateAccessTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
		return "access_token_123", nil
	}

	tokenSvc.GenerateRefreshTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
		return "refresh_token_123", nil
	}
}

// setupSuccessfulRefreshMocks configures mocks for a successful token refresh
func setupSuccessfulRefreshMocks(t *testing.T,
	userRepo *mocks.MockUserRepository,
	sessionRepo *mocks.MockSessionRepository,
	tokenSvc *mocks.MockTokenService,
	testUser *domain.User,
	testSession *domain.Session) {
	t.Helper()

	claims := createValidTokenClaims(t, testUser.ID, testUser.Role, testSession.ID)

	// Refresh token validation succeeds
	tokenSvc.ValidateRefreshTokenFunc = func(token string) (*domain.TokenClaims, error) {
		if token == "valid_refresh_token" {
			return claims, nil
		}
		return nil, domain.ErrTokenInvalid
	}

	// Session exists and is valid
	sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
		if sessionID == testSession.ID {
			return testSession, nil
		}
		return nil, domain.ErrSessionNotFound
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
		if id == testUser.ID {
			return testUser, nil
		}
		return nil, domain.ErrUserNotFound
	}

	// New access token generation succeeds
	tokenSvc.GenerateAccessTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
		return "new_access_token_123", nil
	}

	// New refresh token generation succeeds (for token rotation)
	tokenSvc.GenerateRefreshTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
		return "new_refresh_token_456", nil
	}
}