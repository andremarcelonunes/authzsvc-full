package mocks

import (
	"context"

	"github.com/you/authzsvc/domain"
)

// MockAuthenticationStrategy implements domain.AuthenticationStrategy for testing
type MockAuthenticationStrategy struct {
	AuthenticateFunc       func(ctx context.Context, identifier, password string) (*domain.User, error)
	SupportsIdentifierFunc func(ctx context.Context, identifier string) bool
	GetIdentifierTypeFunc  func() domain.IdentifierType
	ValidateCredentialsFunc func(ctx context.Context, identifier, password string) error
	
	// Configuration for default behaviors
	SupportedIdentifierType domain.IdentifierType
	DefaultUser            *domain.User
	ShouldFailAuth         bool
	AuthError              error
}

// NewMockAuthenticationStrategy creates a new mock authentication strategy
func NewMockAuthenticationStrategy(identifierType domain.IdentifierType) *MockAuthenticationStrategy {
	return &MockAuthenticationStrategy{
		SupportedIdentifierType: identifierType,
		DefaultUser: &domain.User{
			ID:            1,
			Email:         "test@example.com",
			Phone:         "+1234567890",
			PasswordHash:  "hashedpassword",
			Role:          "user",
			IsActive:      true,
			PhoneVerified: true,
		},
	}
}

// NewMockEmailAuthenticationStrategy creates a mock email authentication strategy
func NewMockEmailAuthenticationStrategy() *MockAuthenticationStrategy {
	return NewMockAuthenticationStrategy(domain.IdentifierTypeEmail)
}

// NewMockPhoneAuthenticationStrategy creates a mock phone authentication strategy
func NewMockPhoneAuthenticationStrategy() *MockAuthenticationStrategy {
	return NewMockAuthenticationStrategy(domain.IdentifierTypePhone)
}

// Authenticate implements domain.AuthenticationStrategy
func (m *MockAuthenticationStrategy) Authenticate(ctx context.Context, identifier, password string) (*domain.User, error) {
	if m.AuthenticateFunc != nil {
		return m.AuthenticateFunc(ctx, identifier, password)
	}
	
	// Default behavior
	if m.ShouldFailAuth {
		if m.AuthError != nil {
			return nil, m.AuthError
		}
		return nil, domain.ErrInvalidCredentials
	}
	
	if identifier == "" || password == "" {
		return nil, domain.ErrInvalidCredentials
	}
	
	return m.DefaultUser, nil
}

// SupportsIdentifier implements domain.AuthenticationStrategy
func (m *MockAuthenticationStrategy) SupportsIdentifier(ctx context.Context, identifier string) bool {
	if m.SupportsIdentifierFunc != nil {
		return m.SupportsIdentifierFunc(ctx, identifier)
	}
	
	// Default behavior based on supported type
	if identifier == "" {
		return false
	}
	
	switch m.SupportedIdentifierType {
	case domain.IdentifierTypeEmail:
		// Simple check for @
		for _, char := range identifier {
			if char == '@' {
				return true
			}
		}
		return false
	case domain.IdentifierTypePhone:
		// Check if it looks like a phone (starts with + or all digits)
		if identifier[0] == '+' {
			return true
		}
		// Check if all characters are digits
		for _, char := range identifier {
			if char < '0' || char > '9' {
				return false
			}
		}
		return len(identifier) >= 10
	default:
		return false
	}
}

// GetIdentifierType implements domain.AuthenticationStrategy
func (m *MockAuthenticationStrategy) GetIdentifierType() domain.IdentifierType {
	if m.GetIdentifierTypeFunc != nil {
		return m.GetIdentifierTypeFunc()
	}
	
	return m.SupportedIdentifierType
}

// ValidateCredentials implements domain.AuthenticationStrategy
func (m *MockAuthenticationStrategy) ValidateCredentials(ctx context.Context, identifier, password string) error {
	if m.ValidateCredentialsFunc != nil {
		return m.ValidateCredentialsFunc(ctx, identifier, password)
	}
	
	// Default behavior: basic validation
	if identifier == "" {
		return domain.ErrInvalidIdentifier
	}
	
	if password == "" {
		return domain.ErrFieldRequired
	}
	
	if len(password) < 8 {
		return domain.ErrFieldTooShort
	}
	
	return nil
}

// ConfigureForSuccess configures the mock to return successful authentication
func (m *MockAuthenticationStrategy) ConfigureForSuccess(user *domain.User) {
	m.ShouldFailAuth = false
	if user != nil {
		m.DefaultUser = user
	}
}

// ConfigureForFailure configures the mock to return authentication failures
func (m *MockAuthenticationStrategy) ConfigureForFailure(err error) {
	m.ShouldFailAuth = true
	m.AuthError = err
}