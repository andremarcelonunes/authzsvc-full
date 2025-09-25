package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/you/authzsvc/domain"
)

// EmailAuthStrategy implements authentication using email addresses
type EmailAuthStrategy struct {
	userRepository      domain.UserRepository
	passwordService     domain.PasswordService
	identifierResolver  domain.IdentifierResolutionService
}

// NewEmailAuthStrategy creates a new email authentication strategy
func NewEmailAuthStrategy(
	userRepository domain.UserRepository,
	passwordService domain.PasswordService,
	identifierResolver domain.IdentifierResolutionService,
) domain.AuthenticationStrategy {
	return &EmailAuthStrategy{
		userRepository:     userRepository,
		passwordService:    passwordService,
		identifierResolver: identifierResolver,
	}
}

// Authenticate performs authentication using email and password
func (s *EmailAuthStrategy) Authenticate(ctx context.Context, identifier, password string) (*domain.User, error) {
	// Validate credentials format first
	if err := s.ValidateCredentials(ctx, identifier, password); err != nil {
		return nil, fmt.Errorf("credential validation failed: %w", err)
	}

	// Normalize email for consistent lookup
	normalizedEmail, err := s.identifierResolver.NormalizeEmail(ctx, identifier)
	if err != nil {
		return nil, fmt.Errorf("email normalization failed: %w", err)
	}

	// Find user by email
	user, err := s.userRepository.FindByEmail(ctx, normalizedEmail)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	// Check if user account is active
	if !user.IsActive {
		return nil, domain.ErrUserInactive
	}

	// Verify password
	if !s.passwordService.Verify(user.PasswordHash, password) {
		return nil, domain.ErrInvalidCredentials
	}

	// Check if phone is verified (required for all users)
	if !user.PhoneVerified {
		return nil, domain.ErrPhoneNotVerified
	}

	return user, nil
}

// SupportsIdentifier checks if this strategy can handle the given identifier
func (s *EmailAuthStrategy) SupportsIdentifier(ctx context.Context, identifier string) bool {
	if identifier == "" {
		return false
	}

	// Resolve identifier to check if it's an email
	resolution, err := s.identifierResolver.ResolveIdentifier(ctx, identifier)
	if err != nil || !resolution.IsValid {
		return false
	}

	return resolution.Type == domain.IdentifierTypeEmail
}

// GetIdentifierType returns the type of identifier this strategy handles
func (s *EmailAuthStrategy) GetIdentifierType() domain.IdentifierType {
	return domain.IdentifierTypeEmail
}

// ValidateCredentials performs email-specific credential validation
func (s *EmailAuthStrategy) ValidateCredentials(ctx context.Context, identifier, password string) error {
	if identifier == "" {
		return errors.New("email cannot be empty")
	}

	if password == "" {
		return errors.New("password cannot be empty")
	}

	// Validate email format
	if err := s.identifierResolver.ValidateIdentifier(ctx, identifier, domain.IdentifierTypeEmail); err != nil {
		return fmt.Errorf("invalid email format: %w", err)
	}

	// Password length validation (basic check)
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	return nil
}