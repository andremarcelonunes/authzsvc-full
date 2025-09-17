package mocks

import (
	"fmt"
	"time"

	"github.com/you/authzsvc/domain"
)

// MockTokenService implements domain.TokenService interface for testing
type MockTokenService struct {
	GenerateAccessTokenFunc  func(userID uint, role string, sessionID string) (string, error)
	GenerateRefreshTokenFunc func(userID uint, role string, sessionID string) (string, error)
	ValidateAccessTokenFunc  func(token string) (*domain.TokenClaims, error)
	ValidateRefreshTokenFunc func(token string) (*domain.TokenClaims, error)
}

// NewMockTokenService creates a new MockTokenService with default behaviors
func NewMockTokenService() *MockTokenService {
	return &MockTokenService{}
}

// GenerateAccessToken generates an access token for the user
func (m *MockTokenService) GenerateAccessToken(userID uint, role string, sessionID string) (string, error) {
	if m.GenerateAccessTokenFunc != nil {
		return m.GenerateAccessTokenFunc(userID, role, sessionID)
	}
	// Default behavior: return a mock access token
	return fmt.Sprintf("access_token_user_%d_%s_%s", userID, role, sessionID), nil
}

// GenerateRefreshToken generates a refresh token for the user
func (m *MockTokenService) GenerateRefreshToken(userID uint, role string, sessionID string) (string, error) {
	if m.GenerateRefreshTokenFunc != nil {
		return m.GenerateRefreshTokenFunc(userID, role, sessionID)
	}
	// Default behavior: return a mock refresh token
	return fmt.Sprintf("refresh_token_user_%d_%s_%s", userID, role, sessionID), nil
}

// ValidateAccessToken validates an access token and returns claims
func (m *MockTokenService) ValidateAccessToken(token string) (*domain.TokenClaims, error) {
	if m.ValidateAccessTokenFunc != nil {
		return m.ValidateAccessTokenFunc(token)
	}
	// Default behavior: return valid claims for properly formatted mock tokens
	if token == "" {
		return nil, domain.ErrTokenInvalid
	}
	
	now := time.Now().Unix()
	return &domain.TokenClaims{
		UserID:    1,
		Role:      "user",
		SessionID: "",
		IssuedAt:  now,
		ExpiresAt: now + 900, // 15 minutes
	}, nil
}

// ValidateRefreshToken validates a refresh token and returns claims
func (m *MockTokenService) ValidateRefreshToken(token string) (*domain.TokenClaims, error) {
	if m.ValidateRefreshTokenFunc != nil {
		return m.ValidateRefreshTokenFunc(token)
	}
	// Default behavior: return valid claims for properly formatted mock tokens
	if token == "" {
		return nil, domain.ErrTokenInvalid
	}
	
	now := time.Now().Unix()
	return &domain.TokenClaims{
		UserID:    1,
		Role:      "user",
		SessionID: "mock_session_id",
		IssuedAt:  now,
		ExpiresAt: now + 604800, // 7 days
	}, nil
}

// Compile-time interface compliance verification
var _ domain.TokenService = (*MockTokenService)(nil)