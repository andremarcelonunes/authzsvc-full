package services

import (
	"context"
	"errors"
	"fmt"

	"github.com/you/authzsvc/domain"
)

// PhoneAuthStrategy implements authentication using phone numbers
type PhoneAuthStrategy struct {
	userRepository      domain.UserRepository
	passwordService     domain.PasswordService
	identifierResolver  domain.IdentifierResolutionService
}

// NewPhoneAuthStrategy creates a new phone authentication strategy
func NewPhoneAuthStrategy(
	userRepository domain.UserRepository,
	passwordService domain.PasswordService,
	identifierResolver domain.IdentifierResolutionService,
) domain.AuthenticationStrategy {
	return &PhoneAuthStrategy{
		userRepository:     userRepository,
		passwordService:    passwordService,
		identifierResolver: identifierResolver,
	}
}

// Authenticate performs authentication using phone number and password
func (s *PhoneAuthStrategy) Authenticate(ctx context.Context, identifier, password string) (*domain.User, error) {
	// Validate credentials format first
	if err := s.ValidateCredentials(ctx, identifier, password); err != nil {
		return nil, fmt.Errorf("credential validation failed: %w", err)
	}

	// Normalize phone number for consistent lookup (E.164 format)
	normalizedPhone, err := s.identifierResolver.NormalizePhone(ctx, identifier, "1") // Default to US country code
	if err != nil {
		return nil, fmt.Errorf("phone normalization failed: %w", err)
	}

	// Find user by phone
	user, err := s.userRepository.FindByPhone(ctx, normalizedPhone)
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

	// Check if phone is verified (enhanced security requirement for phone-based auth)
	if !user.PhoneVerified {
		return nil, domain.ErrPhoneNotVerified
	}

	// Verify password
	if !s.passwordService.Verify(user.PasswordHash, password) {
		return nil, domain.ErrInvalidCredentials
	}

	return user, nil
}

// SupportsIdentifier checks if this strategy can handle the given identifier
func (s *PhoneAuthStrategy) SupportsIdentifier(ctx context.Context, identifier string) bool {
	if identifier == "" {
		return false
	}

	// Resolve identifier to check if it's a phone
	resolution, err := s.identifierResolver.ResolveIdentifier(ctx, identifier)
	if err != nil || !resolution.IsValid {
		return false
	}

	return resolution.Type == domain.IdentifierTypePhone
}

// GetIdentifierType returns the type of identifier this strategy handles
func (s *PhoneAuthStrategy) GetIdentifierType() domain.IdentifierType {
	return domain.IdentifierTypePhone
}

// ValidateCredentials performs phone-specific credential validation
func (s *PhoneAuthStrategy) ValidateCredentials(ctx context.Context, identifier, password string) error {
	if identifier == "" {
		return errors.New("phone number cannot be empty")
	}

	if password == "" {
		return errors.New("password cannot be empty")
	}

	// Validate phone format
	if err := s.identifierResolver.ValidateIdentifier(ctx, identifier, domain.IdentifierTypePhone); err != nil {
		return fmt.Errorf("invalid phone number format: %w", err)
	}

	// Password length validation (basic check)
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters long")
	}

	return nil
}