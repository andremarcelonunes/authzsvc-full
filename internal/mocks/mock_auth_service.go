package mocks

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
)

// MockAuthService implements domain.AuthService interface for testing
type MockAuthService struct {
	RegisterFunc       func(ctx context.Context, email, phone, password, role string) (*domain.User, error)
	LoginFunc          func(ctx context.Context, email, password string) (*domain.AuthResult, error)
	RefreshTokenFunc   func(ctx context.Context, refreshToken string) (*domain.AuthResult, error)
	LogoutFunc         func(ctx context.Context, sessionID string) error
	GetUserProfileFunc func(ctx context.Context, userID uint) (*domain.User, error)
}

// NewMockAuthService creates a new MockAuthService with default behaviors
func NewMockAuthService() *MockAuthService {
	return &MockAuthService{}
}

// Register registers a new user
func (m *MockAuthService) Register(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
	if m.RegisterFunc != nil {
		return m.RegisterFunc(ctx, email, phone, password, role)
	}
	// Default behavior: return a mock user
	return &domain.User{
		ID:            1,
		Email:         email,
		Phone:         phone,
		PasswordHash:  "hashed_" + password,
		Role:          role,
		IsActive:      true,
		PhoneVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}, nil
}

// Login authenticates a user and returns auth result
func (m *MockAuthService) Login(ctx context.Context, email, password string) (*domain.AuthResult, error) {
	if m.LoginFunc != nil {
		return m.LoginFunc(ctx, email, password)
	}
	// Default behavior: return successful auth result
	return &domain.AuthResult{
		User: &domain.User{
			ID:            1,
			Email:         email,
			Role:          "user",
			IsActive:      true,
			PhoneVerified: true,
		},
		AccessToken:  "mock_access_token",
		RefreshToken: "mock_refresh_token",
		SessionID:    "mock_session_id",
		ExpiresIn:    900, // 15 minutes
	}, nil
}

// RefreshToken refreshes an access token using a refresh token
func (m *MockAuthService) RefreshToken(ctx context.Context, refreshToken string) (*domain.AuthResult, error) {
	if m.RefreshTokenFunc != nil {
		return m.RefreshTokenFunc(ctx, refreshToken)
	}
	// Default behavior: return new auth result
	return &domain.AuthResult{
		User: &domain.User{
			ID:            1,
			Email:         "test@example.com",
			Role:          "user",
			IsActive:      true,
			PhoneVerified: true,
		},
		AccessToken:  "new_mock_access_token",
		RefreshToken: "new_mock_refresh_token",
		SessionID:    "mock_session_id",
		ExpiresIn:    900, // 15 minutes
	}, nil
}

// Logout logs out a user by terminating their session
func (m *MockAuthService) Logout(ctx context.Context, sessionID string) error {
	if m.LogoutFunc != nil {
		return m.LogoutFunc(ctx, sessionID)
	}
	// Default behavior: success
	return nil
}

// GetUserProfile retrieves user profile information
func (m *MockAuthService) GetUserProfile(ctx context.Context, userID uint) (*domain.User, error) {
	if m.GetUserProfileFunc != nil {
		return m.GetUserProfileFunc(ctx, userID)
	}
	// Default behavior: return mock user profile
	return &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		Phone:         "+1234567890",
		Role:          "user",
		IsActive:      true,
		PhoneVerified: true,
		CreatedAt:     time.Now().Add(-24 * time.Hour),
		UpdatedAt:     time.Now(),
	}, nil
}

// Compile-time interface compliance verification
var _ domain.AuthService = (*MockAuthService)(nil)