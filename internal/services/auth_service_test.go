package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

func TestAuthServiceImpl_Register(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		phone         string
		password      string
		setupMocks    func(*mocks.MockUserRepository, *mocks.MockPasswordService, *mocks.MockOTPService)
		expectedError error
		validateUser  func(t *testing.T, user *domain.User)
	}{
		{
			name:     "successful registration",
			email:    "newuser@example.com",
			phone:    "+1234567890",
			password: "securepassword123",
			setupMocks: func(userRepo *mocks.MockUserRepository, passwordSvc *mocks.MockPasswordService, otpSvc *mocks.MockOTPService) {
				setupSuccessfulRegisterMocks(t, userRepo, passwordSvc, otpSvc)
			},
			expectedError: nil,
			validateUser: func(t *testing.T, user *domain.User) {
				if user == nil {
					t.Fatal("user is nil")
				}
				if user.Email != "newuser@example.com" {
					t.Errorf("expected email %s, got %s", "newuser@example.com", user.Email)
				}
				if user.Phone != "+1234567890" {
					t.Errorf("expected phone %s, got %s", "+1234567890", user.Phone)
				}
				if user.Role != "user" {
					t.Errorf("expected role %s, got %s", "user", user.Role)
				}
				if !user.IsActive {
					t.Error("expected user to be active")
				}
				if user.PasswordHash != "hashed_securepassword123" {
					t.Errorf("expected password hash %s, got %s", "hashed_securepassword123", user.PasswordHash)
				}
			},
		},
		{
			name:     "user already exists",
			email:    "existing@example.com",
			phone:    "+1234567890",
			password: "password123",
			setupMocks: func(userRepo *mocks.MockUserRepository, passwordSvc *mocks.MockPasswordService, otpSvc *mocks.MockOTPService) {
				// User already exists
				userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return createValidUser(t), nil
				}
			},
			expectedError: domain.ErrUserAlreadyExists,
			validateUser: func(t *testing.T, user *domain.User) {
				if user != nil {
					t.Error("expected user to be nil when already exists")
				}
			},
		},
		{
			name:     "password hashing fails",
			email:    "newuser@example.com",
			phone:    "+1234567890",
			password: "password123",
			setupMocks: func(userRepo *mocks.MockUserRepository, passwordSvc *mocks.MockPasswordService, otpSvc *mocks.MockOTPService) {
				// User doesn't exist
				userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return nil, domain.ErrUserNotFound
				}
				// Password hashing fails
				passwordSvc.HashFunc = func(password string) (string, error) {
					return "", errors.New("hashing failed")
				}
			},
			expectedError: fmt.Errorf("failed to hash password: %w", errors.New("hashing failed")),
			validateUser: func(t *testing.T, user *domain.User) {
				if user != nil {
					t.Error("expected user to be nil when password hashing fails")
				}
			},
		},
		{
			name:     "user creation fails",
			email:    "newuser@example.com",
			phone:    "+1234567890",
			password: "password123",
			setupMocks: func(userRepo *mocks.MockUserRepository, passwordSvc *mocks.MockPasswordService, otpSvc *mocks.MockOTPService) {
				// User doesn't exist
				userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return nil, domain.ErrUserNotFound
				}
				// Password hashing succeeds
				passwordSvc.HashFunc = func(password string) (string, error) {
					return "hashed_" + password, nil
				}
				// User creation fails
				userRepo.CreateFunc = func(ctx context.Context, user *domain.User) error {
					return errors.New("database error")
				}
			},
			expectedError: fmt.Errorf("failed to create user: %w", errors.New("database error")),
			validateUser: func(t *testing.T, user *domain.User) {
				if user != nil {
					t.Error("expected user to be nil when creation fails")
				}
			},
		},
		{
			name:     "OTP generation fails",
			email:    "newuser@example.com",
			phone:    "+1234567890",
			password: "password123",
			setupMocks: func(userRepo *mocks.MockUserRepository, passwordSvc *mocks.MockPasswordService, otpSvc *mocks.MockOTPService) {
				// User doesn't exist
				userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return nil, domain.ErrUserNotFound
				}
				// Password hashing succeeds
				passwordSvc.HashFunc = func(password string) (string, error) {
					return "hashed_" + password, nil
				}
				// User creation succeeds
				userRepo.CreateFunc = func(ctx context.Context, user *domain.User) error {
					user.ID = 1
					return nil
				}
				// OTP generation fails
				otpSvc.GenerateFunc = func(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) {
					return nil, errors.New("SMS service unavailable")
				}
			},
			expectedError: fmt.Errorf("failed to send OTP: %w", errors.New("SMS service unavailable")),
			validateUser: func(t *testing.T, user *domain.User) {
				if user != nil {
					t.Error("expected user to be nil when OTP generation fails")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			userRepo := mocks.NewMockUserRepository()
			passwordSvc := mocks.NewMockPasswordService()
			otpSvc := mocks.NewMockOTPService()

			// Setup test-specific mock behavior
			tt.setupMocks(userRepo, passwordSvc, otpSvc)

			// Create service
			authService := createAuthServiceForTest(t, userRepo, nil, passwordSvc, nil, otpSvc, nil, nil)

			// Create context
			ctx := createTestContext(t)

			// Execute test
			user, err := authService.Register(ctx, tt.email, tt.phone, tt.password, "user")

			// Validate error
			if tt.expectedError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.expectedError)
				}
				// For enhanced error messages, check if the expected error is contained in the actual error
				expectedMsg := tt.expectedError.Error()
				actualMsg := err.Error()
				if !strings.Contains(actualMsg, expectedMsg) {
					t.Errorf("expected error containing '%s', got '%s'", expectedMsg, actualMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Validate user
			tt.validateUser(t, user)
		})
	}
}

func TestAuthServiceImpl_Login(t *testing.T) {
	tests := []struct {
		name           string
		email          string
		password       string
		setupMocks     func(*mocks.MockUserRepository, *mocks.MockSessionRepository, *mocks.MockPasswordService, *mocks.MockTokenService)
		expectedError  error
		validateResult func(t *testing.T, result *domain.AuthResult)
	}{
		{
			name:     "successful login",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, passwordSvc *mocks.MockPasswordService, tokenSvc *mocks.MockTokenService) {
				testUser := createValidUser(t)
				setupSuccessfulLoginMocks(t, userRepo, sessionRepo, passwordSvc, tokenSvc, testUser)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				testUser := createValidUser(t)
				assertAuthResult(t, result, testUser)
			},
		},
		{
			name:     "user not found",
			email:    "nonexistent@example.com",
			password: "password123",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, passwordSvc *mocks.MockPasswordService, tokenSvc *mocks.MockTokenService) {
				userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return nil, domain.ErrUserNotFound
				}
			},
			expectedError: domain.ErrInvalidCredentials,
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when user not found")
				}
			},
		},
		{
			name:     "user inactive",
			email:    "inactive@example.com",
			password: "password123",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, passwordSvc *mocks.MockPasswordService, tokenSvc *mocks.MockTokenService) {
				inactiveUser := createInactiveUser(t)
				userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return inactiveUser, nil
				}
			},
			expectedError: domain.ErrUserInactive,
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when user inactive")
				}
			},
		},
		{
			name:     "invalid password",
			email:    "test@example.com",
			password: "wrongpassword",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, passwordSvc *mocks.MockPasswordService, tokenSvc *mocks.MockTokenService) {
				testUser := createValidUser(t)
				userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return testUser, nil
				}
				passwordSvc.VerifyFunc = func(hashedPassword, password string) bool {
					return false // Password verification fails
				}
			},
			expectedError: domain.ErrInvalidCredentials,
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when password invalid")
				}
			},
		},
		{
			name:     "session creation fails",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, passwordSvc *mocks.MockPasswordService, tokenSvc *mocks.MockTokenService) {
				testUser := createValidUser(t)
				userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return testUser, nil
				}
				passwordSvc.VerifyFunc = func(hashedPassword, password string) bool {
					return true
				}
				sessionRepo.CreateFunc = func(ctx context.Context, session *domain.Session) error {
					return errors.New("session creation failed")
				}
			},
			expectedError: fmt.Errorf("failed to create session: %w", errors.New("session creation failed")),
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when session creation fails")
				}
			},
		},
		{
			name:     "access token generation fails",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, passwordSvc *mocks.MockPasswordService, tokenSvc *mocks.MockTokenService) {
				testUser := createValidUser(t)
				userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return testUser, nil
				}
				passwordSvc.VerifyFunc = func(hashedPassword, password string) bool {
					return true
				}
				sessionRepo.CreateFunc = func(ctx context.Context, session *domain.Session) error {
					return nil
				}
				tokenSvc.GenerateAccessTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "", errors.New("token generation failed")
				}
			},
			expectedError: fmt.Errorf("failed to generate access token: %w", errors.New("token generation failed")),
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when access token generation fails")
				}
			},
		},
		{
			name:     "refresh token generation fails",
			email:    "test@example.com",
			password: "password123",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, passwordSvc *mocks.MockPasswordService, tokenSvc *mocks.MockTokenService) {
				testUser := createValidUser(t)
				userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return testUser, nil
				}
				passwordSvc.VerifyFunc = func(hashedPassword, password string) bool {
					return true
				}
				sessionRepo.CreateFunc = func(ctx context.Context, session *domain.Session) error {
					return nil
				}
				tokenSvc.GenerateAccessTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "access_token_123", nil
				}
				tokenSvc.GenerateRefreshTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "", errors.New("refresh token generation failed")
				}
			},
			expectedError: fmt.Errorf("failed to generate refresh token: %w", errors.New("refresh token generation failed")),
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when refresh token generation fails")
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

			// Setup test-specific mock behavior
			tt.setupMocks(userRepo, sessionRepo, passwordSvc, tokenSvc)

			// Create service
			authService := createAuthServiceForTest(t, userRepo, sessionRepo, passwordSvc, tokenSvc, nil, nil, nil)

			// Create context
			ctx := createTestContext(t)

			// Execute test
			result, err := authService.Login(ctx, tt.email, tt.password)

			// Validate error
			if tt.expectedError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.expectedError)
				}
				// For enhanced error messages, check if the expected error is contained in the actual error
				expectedMsg := tt.expectedError.Error()
				actualMsg := err.Error()
				if !strings.Contains(actualMsg, expectedMsg) {
					t.Errorf("expected error containing '%s', got '%s'", expectedMsg, actualMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Validate result
			tt.validateResult(t, result)
		})
	}
}

func TestAuthServiceImpl_RefreshToken(t *testing.T) {
	tests := []struct {
		name           string
		refreshToken   string
		setupMocks     func(*mocks.MockUserRepository, *mocks.MockSessionRepository, *mocks.MockTokenService)
		expectedError  error
		validateResult func(t *testing.T, result *domain.AuthResult)
	}{
		{
			name:         "successful token refresh",
			refreshToken: "valid_refresh_token",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, tokenSvc *mocks.MockTokenService) {
				testUser := createValidUser(t)
				testSession := createValidSession(t, testUser.ID)
				setupSuccessfulRefreshMocks(t, userRepo, sessionRepo, tokenSvc, testUser, testSession)
			},
			expectedError: nil,
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				testUser := createValidUser(t)
				assertAuthResult(t, result, testUser)
				if result.AccessToken != "new_access_token_123" {
					t.Errorf("expected new access token, got %s", result.AccessToken)
				}
				if result.RefreshToken != "new_refresh_token_456" {
					t.Errorf("expected new refresh token 'new_refresh_token_456', got %s", result.RefreshToken)
				}
			},
		},
		{
			name:         "invalid refresh token",
			refreshToken: "invalid_token",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, tokenSvc *mocks.MockTokenService) {
				tokenSvc.ValidateRefreshTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return nil, domain.ErrTokenInvalid
				}
			},
			expectedError: fmt.Errorf("token validation failed: invalid token"),
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when token invalid")
				}
			},
		},
		{
			name:         "session not found",
			refreshToken: "valid_refresh_token",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, tokenSvc *mocks.MockTokenService) {
				testUser := createValidUser(t)
				claims := createValidTokenClaims(t, testUser.ID, testUser.Role, "nonexistent_session")
				
				tokenSvc.ValidateRefreshTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return claims, nil
				}
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					return nil, domain.ErrSessionNotFound
				}
			},
			expectedError: fmt.Errorf("session lookup failed for session nonexistent_session: session not found"),
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when session not found")
				}
			},
		},
		{
			name:         "session expired",
			refreshToken: "valid_refresh_token",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, tokenSvc *mocks.MockTokenService) {
				testUser := createValidUser(t)
				expiredSession := createExpiredSession(t, testUser.ID)
				claims := createValidTokenClaims(t, testUser.ID, testUser.Role, expiredSession.ID)
				
				tokenSvc.ValidateRefreshTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return claims, nil
				}
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					return expiredSession, nil
				}
			},
			expectedError: errors.New("session has expired"),
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when session expired")
				}
			},
		},
		{
			name:         "user not found",
			refreshToken: "valid_refresh_token",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, tokenSvc *mocks.MockTokenService) {
				testSession := createValidSession(t, 999) // Non-existent user ID
				claims := createValidTokenClaims(t, 999, "user", testSession.ID)
				
				tokenSvc.ValidateRefreshTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return claims, nil
				}
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					return testSession, nil
				}
				userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
					return nil, domain.ErrUserNotFound
				}
			},
			expectedError: fmt.Errorf("user lookup failed for user ID 999 in session sess_123_456789: user not found"),
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when user not found")
				}
			},
		},
		{
			name:         "new access token generation fails",
			refreshToken: "valid_refresh_token",
			setupMocks: func(userRepo *mocks.MockUserRepository, sessionRepo *mocks.MockSessionRepository, tokenSvc *mocks.MockTokenService) {
				testUser := createValidUser(t)
				testSession := createValidSession(t, testUser.ID)
				claims := createValidTokenClaims(t, testUser.ID, testUser.Role, testSession.ID)
				
				tokenSvc.ValidateRefreshTokenFunc = func(token string) (*domain.TokenClaims, error) {
					return claims, nil
				}
				sessionRepo.FindByIDFunc = func(ctx context.Context, sessionID string) (*domain.Session, error) {
					return testSession, nil
				}
				userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
					return testUser, nil
				}
				tokenSvc.GenerateAccessTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "", errors.New("token generation failed")
				}
			},
			expectedError: fmt.Errorf("access token generation failed for user 1 (session sess_123_456789): token generation failed"),
			validateResult: func(t *testing.T, result *domain.AuthResult) {
				if result != nil {
					t.Error("expected result to be nil when access token generation fails")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			userRepo := mocks.NewMockUserRepository()
			sessionRepo := mocks.NewMockSessionRepository()
			tokenSvc := mocks.NewMockTokenService()

			// Setup test-specific mock behavior
			tt.setupMocks(userRepo, sessionRepo, tokenSvc)

			// Create service
			authService := createAuthServiceForTest(t, userRepo, sessionRepo, nil, tokenSvc, nil, nil, nil)

			// Create context
			ctx := createTestContext(t)

			// Execute test
			result, err := authService.RefreshToken(ctx, tt.refreshToken)

			// Validate error
			if tt.expectedError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.expectedError)
				}
				// For enhanced error messages, check if the expected error is contained in the actual error
				expectedMsg := tt.expectedError.Error()
				actualMsg := err.Error()
				if !strings.Contains(actualMsg, expectedMsg) {
					t.Errorf("expected error containing '%s', got '%s'", expectedMsg, actualMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Validate result
			tt.validateResult(t, result)
		})
	}
}

func TestAuthServiceImpl_Logout(t *testing.T) {
	tests := []struct {
		name          string
		sessionID     string
		setupMocks    func(*mocks.MockSessionRepository)
		expectedError error
	}{
		{
			name:      "successful logout",
			sessionID: "valid_session_123",
			setupMocks: func(sessionRepo *mocks.MockSessionRepository) {
				sessionRepo.DeleteFunc = func(ctx context.Context, sessionID string) error {
					return nil
				}
			},
			expectedError: nil,
		},
		{
			name:      "session deletion fails",
			sessionID: "valid_session_123",
			setupMocks: func(sessionRepo *mocks.MockSessionRepository) {
				sessionRepo.DeleteFunc = func(ctx context.Context, sessionID string) error {
					return errors.New("database error")
				}
			},
			expectedError: errors.New("database error"),
		},
		{
			name:      "empty session ID",
			sessionID: "",
			setupMocks: func(sessionRepo *mocks.MockSessionRepository) {
				sessionRepo.DeleteFunc = func(ctx context.Context, sessionID string) error {
					if sessionID == "" {
						return domain.ErrSessionNotFound
					}
					return nil
				}
			},
			expectedError: domain.ErrSessionNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			sessionRepo := mocks.NewMockSessionRepository()

			// Setup test-specific mock behavior
			tt.setupMocks(sessionRepo)

			// Create service
			authService := createAuthServiceForTest(t, nil, sessionRepo, nil, nil, nil, nil, nil)

			// Create context
			ctx := createTestContext(t)

			// Execute test
			err := authService.Logout(ctx, tt.sessionID)

			// Validate error
			if tt.expectedError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.expectedError)
				}
				// For enhanced error messages, check if the expected error is contained in the actual error
				expectedMsg := tt.expectedError.Error()
				actualMsg := err.Error()
				if !strings.Contains(actualMsg, expectedMsg) {
					t.Errorf("expected error containing '%s', got '%s'", expectedMsg, actualMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}
		})
	}
}

func TestAuthServiceImpl_GetUserProfile(t *testing.T) {
	tests := []struct {
		name         string
		userID       uint
		setupMocks   func(*mocks.MockUserRepository)
		expectedUser *domain.User
		expectedError error
	}{
		{
			name:   "successful profile retrieval",
			userID: 1,
			setupMocks: func(userRepo *mocks.MockUserRepository) {
				testUser := createValidUser(t)
				userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
					if id == 1 {
						return testUser, nil
					}
					return nil, domain.ErrUserNotFound
				}
			},
			expectedUser:  createValidUser(t),
			expectedError: nil,
		},
		{
			name:   "user not found",
			userID: 999,
			setupMocks: func(userRepo *mocks.MockUserRepository) {
				userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
					return nil, domain.ErrUserNotFound
				}
			},
			expectedUser:  nil,
			expectedError: domain.ErrUserNotFound,
		},
		{
			name:   "database error",
			userID: 1,
			setupMocks: func(userRepo *mocks.MockUserRepository) {
				userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
					return nil, errors.New("database connection failed")
				}
			},
			expectedUser:  nil,
			expectedError: errors.New("database connection failed"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			userRepo := mocks.NewMockUserRepository()

			// Setup test-specific mock behavior
			tt.setupMocks(userRepo)

			// Create service
			authService := createAuthServiceForTest(t, userRepo, nil, nil, nil, nil, nil, nil)

			// Create context
			ctx := createTestContext(t)

			// Execute test
			user, err := authService.GetUserProfile(ctx, tt.userID)

			// Validate error
			if tt.expectedError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.expectedError)
				}
				// For enhanced error messages, check if the expected error is contained in the actual error
				expectedMsg := tt.expectedError.Error()
				actualMsg := err.Error()
				if !strings.Contains(actualMsg, expectedMsg) {
					t.Errorf("expected error containing '%s', got '%s'", expectedMsg, actualMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Validate user
			if tt.expectedUser != nil {
				if user == nil {
					t.Fatal("expected user, got nil")
				}
				if user.ID != tt.expectedUser.ID {
					t.Errorf("expected user ID %d, got %d", tt.expectedUser.ID, user.ID)
				}
				if user.Email != tt.expectedUser.Email {
					t.Errorf("expected user email %s, got %s", tt.expectedUser.Email, user.Email)
				}
			} else {
				if user != nil {
					t.Errorf("expected nil user, got %+v", user)
				}
			}
		})
	}
}

// Integration-style test to verify the complete auth flow
func TestAuthServiceImpl_CompleteAuthFlow(t *testing.T) {
	// Create mocks
	userRepo := mocks.NewMockUserRepository()
	sessionRepo := mocks.NewMockSessionRepository()
	passwordSvc := mocks.NewMockPasswordService()
	tokenSvc := mocks.NewMockTokenService()
	otpSvc := mocks.NewMockOTPService()

	// Create service
	authService := createAuthServiceForTest(t, userRepo, sessionRepo, passwordSvc, tokenSvc, otpSvc, nil, nil)

	// Test data
	email := "integration@test.com"
	phone := "+1234567890"
	password := "securepassword123"
	hashedPassword := "hashed_securepassword123"

	ctx := createTestContext(t)

	var registeredUser *domain.User

	// Step 1: Register user
	// User doesn't exist yet
	userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
		if registeredUser != nil && email == registeredUser.Email {
			return registeredUser, nil
		}
		return nil, domain.ErrUserNotFound
	}

	// Password hashing succeeds
	passwordSvc.HashFunc = func(password string) (string, error) {
		return hashedPassword, nil
	}

	// User creation succeeds
	userRepo.CreateFunc = func(ctx context.Context, user *domain.User) error {
		user.ID = 1 // Simulate database assignment
		registeredUser = user
		return nil
	}

	// OTP generation succeeds
	otpSvc.GenerateFunc = func(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) {
		return createOTPRequest(t, phone, userID), nil
	}

	user, err := authService.Register(ctx, email, phone, password, "user")
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	if user == nil {
		t.Fatal("user is nil after registration")
	}

	// Step 2: Login user
	// Mark phone as verified (simulating OTP verification)
	registeredUser.PhoneVerified = true
	
	// Password verification succeeds with consistent hash
	passwordSvc.VerifyFunc = func(hashedPwd, pwd string) bool {
		return hashedPwd == hashedPassword && pwd == password
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

	authResult, err := authService.Login(ctx, email, password)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	assertAuthResult(t, authResult, user)

	// Step 3: Refresh token
	testSession := &domain.Session{
		ID:        authResult.SessionID,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}

	claims := createValidTokenClaims(t, user.ID, user.Role, testSession.ID)

	// Refresh token validation succeeds
	tokenSvc.ValidateRefreshTokenFunc = func(token string) (*domain.TokenClaims, error) {
		if token == "refresh_token_123" {
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

	// User exists
	userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
		if id == user.ID {
			return user, nil
		}
		return nil, domain.ErrUserNotFound
	}

	// New access token generation succeeds
	tokenSvc.GenerateAccessTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
		return "new_access_token_123", nil
	}

	refreshResult, err := authService.RefreshToken(ctx, authResult.RefreshToken)
	if err != nil {
		t.Fatalf("token refresh failed: %v", err)
	}
	assertAuthResult(t, refreshResult, user)

	// Step 4: Get user profile
	profile, err := authService.GetUserProfile(ctx, user.ID)
	if err != nil {
		t.Fatalf("get profile failed: %v", err)
	}
	if profile.ID != user.ID {
		t.Errorf("expected profile ID %d, got %d", user.ID, profile.ID)
	}

	// Step 5: Logout
	sessionRepo.DeleteFunc = func(ctx context.Context, sessionID string) error {
		return nil
	}
	err = authService.Logout(ctx, authResult.SessionID)
	if err != nil {
		t.Fatalf("logout failed: %v", err)
	}
}