package mocks_test

import (
	"context"
	"testing"
	"time"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// Example demonstrating how to use mocks in table-driven tests
// This file serves as documentation for the mock system
func TestMockUsageExample(t *testing.T) {
	t.Helper()

	// Example: Testing a hypothetical AuthService.Login method
	tests := []struct {
		name           string
		email          string
		password       string
		setupMocks     func(*mocks.MockUserRepository, *mocks.MockPasswordService, *mocks.MockTokenService, *mocks.MockSessionRepository)
		expectedResult *domain.AuthResult
		expectedError  string
	}{
		{
			name:     "successful login",
			email:    "user@example.com",
			password: "validpassword",
			setupMocks: func(userRepo *mocks.MockUserRepository, pwdSvc *mocks.MockPasswordService, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				// Configure user repository to return a valid user
				userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return &domain.User{
						ID:            1,
						Email:         email,
						PasswordHash:  "hashed_validpassword",
						Role:          "user",
						IsActive:      true,
						PhoneVerified: true,
					}, nil
				}
				
				// Configure password service to verify successfully
				pwdSvc.VerifyFunc = func(hashedPassword, password string) bool {
					return hashedPassword == "hashed_validpassword" && password == "validpassword"
				}
				
				// Configure token service to generate tokens
				tokenSvc.GenerateAccessTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "mock_access_token", nil
				}
				tokenSvc.GenerateRefreshTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "mock_refresh_token", nil
				}
				
				// Configure session repository to create session successfully
				sessionRepo.CreateFunc = func(ctx context.Context, session *domain.Session) error {
					return nil
				}
			},
			expectedResult: &domain.AuthResult{
				User: &domain.User{
					ID:            1,
					Email:         "user@example.com",
					Role:          "user",
					IsActive:      true,
					PhoneVerified: true,
				},
				AccessToken:  "mock_access_token",
				RefreshToken: "mock_refresh_token",
				SessionID:    "mock_session_id",
				ExpiresIn:    900,
			},
			expectedError: "",
		},
		{
			name:     "user not found",
			email:    "nonexistent@example.com",
			password: "anypassword",
			setupMocks: func(userRepo *mocks.MockUserRepository, pwdSvc *mocks.MockPasswordService, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				// Configure user repository to return not found error
				userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return nil, domain.ErrUserNotFound
				}
			},
			expectedResult: nil,
			expectedError:  "user not found",
		},
		{
			name:     "invalid password",
			email:    "user@example.com",
			password: "wrongpassword",
			setupMocks: func(userRepo *mocks.MockUserRepository, pwdSvc *mocks.MockPasswordService, tokenSvc *mocks.MockTokenService, sessionRepo *mocks.MockSessionRepository) {
				// Configure user repository to return a valid user
				userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return &domain.User{
						ID:           1,
						Email:        email,
						PasswordHash: "hashed_validpassword",
						Role:         "user",
						IsActive:     true,
					}, nil
				}
				
				// Configure password service to reject invalid password
				pwdSvc.VerifyFunc = func(hashedPassword, password string) bool {
					return false // Invalid password
				}
			},
			expectedResult: nil,
			expectedError:  "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh mocks for each test
			userRepo := mocks.NewMockUserRepository()
			pwdSvc := mocks.NewMockPasswordService()
			tokenSvc := mocks.NewMockTokenService()
			sessionRepo := mocks.NewMockSessionRepository()
			
			// Setup mocks according to test case
			if tt.setupMocks != nil {
				tt.setupMocks(userRepo, pwdSvc, tokenSvc, sessionRepo)
			}
			
			// Here you would create your service under test and call the method
			// service := NewAuthService(userRepo, pwdSvc, tokenSvc, sessionRepo)
			// result, err := service.Login(context.Background(), tt.email, tt.password)
			
			// Example assertions (replace with actual testing framework)
			_ = userRepo    // Use the mocks to prevent unused variable errors
			_ = pwdSvc      // in this documentation example
			_ = tokenSvc    
			_ = sessionRepo
			
			// In real tests, you would assert:
			// if tt.expectedError != "" {
			//     assert.Error(t, err)
			//     assert.Contains(t, err.Error(), tt.expectedError)
			//     assert.Nil(t, result)
			// } else {
			//     assert.NoError(t, err)
			//     assert.Equal(t, tt.expectedResult.AccessToken, result.AccessToken)
			//     assert.Equal(t, tt.expectedResult.User.Email, result.User.Email)
			// }
		})
	}
}

// Example: Testing OTP Service with mocks
func TestOTPServiceExample(t *testing.T) {
	t.Helper()

	tests := []struct {
		name          string
		phone         string
		setupMocks    func(*mocks.MockOTPService)
		expectedValid bool
		expectedError string
	}{
		{
			name:  "valid OTP verification",
			phone: "+1234567890",
			setupMocks: func(otpSvc *mocks.MockOTPService) {
				otpSvc.VerifyFunc = func(ctx context.Context, phone, code string, userID uint) (bool, error) {
					return code == "123456", nil
				}
			},
			expectedValid: true,
			expectedError: "",
		},
		{
			name:  "invalid OTP code",
			phone: "+1234567890",
			setupMocks: func(otpSvc *mocks.MockOTPService) {
				otpSvc.VerifyFunc = func(ctx context.Context, phone, code string, userID uint) (bool, error) {
					return false, nil
				}
			},
			expectedValid: false,
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			otpSvc := mocks.NewMockOTPService()
			
			if tt.setupMocks != nil {
				tt.setupMocks(otpSvc)
			}
			
			// Example usage
			valid, err := otpSvc.Verify(context.Background(), tt.phone, "123456", 1)
			
			// In real tests, you would assert the results
			_ = valid
			_ = err
		})
	}
}

// Helper function example following CLAUDE.md standards
func createTestUser(t *testing.T) *domain.User {
	t.Helper()
	
	return &domain.User{
		ID:            1,
		Email:         "test@example.com",
		Phone:         "+1234567890",
		PasswordHash:  "hashed_password",
		Role:          "user",
		IsActive:      true,
		PhoneVerified: true,
		CreatedAt:     time.Now().Add(-24 * time.Hour),
		UpdatedAt:     time.Now(),
	}
}

// Helper function for creating auth service dependencies
func createAuthServiceMocks(t *testing.T) (*mocks.MockUserRepository, *mocks.MockPasswordService, *mocks.MockTokenService, *mocks.MockSessionRepository) {
	t.Helper()
	
	return mocks.NewMockUserRepository(),
		mocks.NewMockPasswordService(),
		mocks.NewMockTokenService(),
		mocks.NewMockSessionRepository()
}