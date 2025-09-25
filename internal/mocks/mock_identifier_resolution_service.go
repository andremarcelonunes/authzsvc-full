package mocks

import (
	"context"

	"github.com/you/authzsvc/domain"
)

// MockIdentifierResolutionService implements domain.IdentifierResolutionService for testing
type MockIdentifierResolutionService struct {
	ResolveIdentifierFunc func(ctx context.Context, identifier string) (*domain.IdentifierResolution, error)
	NormalizePhoneFunc    func(ctx context.Context, phone string, countryCode string) (string, error)
	NormalizeEmailFunc    func(ctx context.Context, email string) (string, error)
	ValidateIdentifierFunc func(ctx context.Context, identifier string, identifierType domain.IdentifierType) error
}

// NewMockIdentifierResolutionService creates a new mock identifier resolution service
func NewMockIdentifierResolutionService() *MockIdentifierResolutionService {
	return &MockIdentifierResolutionService{}
}

// ResolveIdentifier implements domain.IdentifierResolutionService
func (m *MockIdentifierResolutionService) ResolveIdentifier(ctx context.Context, identifier string) (*domain.IdentifierResolution, error) {
	if m.ResolveIdentifierFunc != nil {
		return m.ResolveIdentifierFunc(ctx, identifier)
	}
	
	// Default behavior: assume email if contains @, otherwise phone
	if identifier == "" {
		return nil, domain.ErrInvalidIdentifier
	}
	
	var identifierType domain.IdentifierType
	if containsAt := false; len(identifier) > 0 {
		for _, char := range identifier {
			if char == '@' {
				containsAt = true
				break
			}
		}
		if containsAt {
			identifierType = domain.IdentifierTypeEmail
		} else {
			identifierType = domain.IdentifierTypePhone
		}
	}
	
	return &domain.IdentifierResolution{
		Type:              identifierType,
		OriginalValue:     identifier,
		NormalizedValue:   identifier,
		IsValid:           true,
		ValidationMessage: "",
	}, nil
}

// NormalizePhone implements domain.IdentifierResolutionService
func (m *MockIdentifierResolutionService) NormalizePhone(ctx context.Context, phone string, countryCode string) (string, error) {
	if m.NormalizePhoneFunc != nil {
		return m.NormalizePhoneFunc(ctx, phone, countryCode)
	}
	
	// Default behavior: return phone with + prefix if not already present
	if phone == "" {
		return "", domain.ErrPhoneFormatInvalid
	}
	
	if phone[0] != '+' {
		return "+" + countryCode + phone, nil
	}
	return phone, nil
}

// NormalizeEmail implements domain.IdentifierResolutionService
func (m *MockIdentifierResolutionService) NormalizeEmail(ctx context.Context, email string) (string, error) {
	if m.NormalizeEmailFunc != nil {
		return m.NormalizeEmailFunc(ctx, email)
	}
	
	// Default behavior: return lowercase email
	if email == "" {
		return "", domain.ErrEmailFormatInvalid
	}
	
	// Simple lowercase conversion
	normalized := ""
	for _, char := range email {
		if char >= 'A' && char <= 'Z' {
			normalized += string(char + 32) // Convert to lowercase
		} else {
			normalized += string(char)
		}
	}
	
	return normalized, nil
}

// ValidateIdentifier implements domain.IdentifierResolutionService
func (m *MockIdentifierResolutionService) ValidateIdentifier(ctx context.Context, identifier string, identifierType domain.IdentifierType) error {
	if m.ValidateIdentifierFunc != nil {
		return m.ValidateIdentifierFunc(ctx, identifier, identifierType)
	}
	
	// Default behavior: basic validation
	if identifier == "" {
		return domain.ErrInvalidIdentifier
	}
	
	switch identifierType {
	case domain.IdentifierTypeEmail:
		// Simple check for @
		containsAt := false
		for _, char := range identifier {
			if char == '@' {
				containsAt = true
				break
			}
		}
		if !containsAt {
			return domain.ErrEmailFormatInvalid
		}
	case domain.IdentifierTypePhone:
		// Simple length check
		if len(identifier) < 10 {
			return domain.ErrPhoneFormatInvalid
		}
	default:
		return domain.ErrIdentifierTypeUnknown
	}
	
	return nil
}