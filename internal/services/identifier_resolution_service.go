package services

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/you/authzsvc/domain"
)

// IdentifierResolutionServiceImpl provides smart detection and resolution of authentication identifiers
type IdentifierResolutionServiceImpl struct {
	// Email validation regex - RFC 5322 compliant
	emailRegex *regexp.Regexp
	
	// Phone validation regex - supports various international formats
	phoneRegex *regexp.Regexp
	
	// E.164 normalization regex
	e164Regex *regexp.Regexp
}

// NewIdentifierResolutionService creates a new identifier resolution service instance
func NewIdentifierResolutionService() domain.IdentifierResolutionService {
	// Comprehensive email validation regex following RFC 5322
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9.!#$%&'*+/=?^_{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)
	
	// Phone number validation - supports international formats with country codes
	phoneRegex := regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	
	// E.164 format validation
	e164Regex := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)

	return &IdentifierResolutionServiceImpl{
		emailRegex: emailRegex,
		phoneRegex: phoneRegex,
		e164Regex:  e164Regex,
	}
}

// ResolveIdentifier detects whether an identifier is email or phone and normalizes it
func (s *IdentifierResolutionServiceImpl) ResolveIdentifier(ctx context.Context, identifier string) (*domain.IdentifierResolution, error) {
	if identifier == "" {
		return nil, fmt.Errorf("identifier cannot be empty")
	}

	// Trim whitespace
	identifier = strings.TrimSpace(identifier)
	
	resolution := &domain.IdentifierResolution{
		OriginalValue: identifier,
	}

	// Try email first (more common case)
	if s.isEmail(identifier) {
		resolution.Type = domain.IdentifierTypeEmail
		normalizedEmail, err := s.NormalizeEmail(ctx, identifier)
		if err != nil {
			resolution.IsValid = false
			resolution.ValidationMessage = fmt.Sprintf("email normalization failed: %v", err)
			return resolution, nil
		}
		resolution.NormalizedValue = normalizedEmail
		resolution.IsValid = true
		return resolution, nil
	}

	// Try phone number
	if s.isPhone(identifier) {
		resolution.Type = domain.IdentifierTypePhone
		
		// Default country code if not provided (US: +1)
		countryCode := "1"
		if strings.HasPrefix(identifier, "+") {
			countryCode = s.extractCountryCode(identifier)
		}
		
		normalizedPhone, err := s.NormalizePhone(ctx, identifier, countryCode)
		if err != nil {
			resolution.IsValid = false
			resolution.ValidationMessage = fmt.Sprintf("phone normalization failed: %v", err)
			return resolution, nil
		}
		
		resolution.NormalizedValue = normalizedPhone
		resolution.CountryCode = countryCode
		resolution.IsValid = true
		return resolution, nil
	}

	// Neither email nor phone
	resolution.IsValid = false
	resolution.ValidationMessage = "identifier must be a valid email address or phone number"
	return resolution, nil
}

// NormalizePhone converts phone number to E.164 format for consistent storage/lookup
func (s *IdentifierResolutionServiceImpl) NormalizePhone(ctx context.Context, phone string, countryCode string) (string, error) {
	if phone == "" {
		return "", fmt.Errorf("phone number cannot be empty")
	}

	// Remove all non-digit characters except leading +
	phone = strings.TrimSpace(phone)
	
	// If already in E.164 format, validate and return
	if s.e164Regex.MatchString(phone) {
		return phone, nil
	}

	// Remove all non-digit characters
	digitsOnly := regexp.MustCompile(`[^\d]`).ReplaceAllString(phone, "")
	
	if digitsOnly == "" {
		return "", fmt.Errorf("no digits found in phone number")
	}

	// Handle different country code scenarios
	var normalizedPhone string
	
	// If phone starts with country code (without +), add +
	if len(digitsOnly) >= 10 {
		// Check if it might already include country code
		if strings.HasPrefix(digitsOnly, countryCode) {
			normalizedPhone = "+" + digitsOnly
		} else {
			// Prepend country code
			normalizedPhone = "+" + countryCode + digitsOnly
		}
	} else {
		return "", fmt.Errorf("phone number too short")
	}

	// Final validation against E.164 format
	if !s.e164Regex.MatchString(normalizedPhone) {
		return "", fmt.Errorf("phone number does not conform to E.164 format")
	}

	return normalizedPhone, nil
}

// NormalizeEmail converts email to lowercase and trims whitespace
func (s *IdentifierResolutionServiceImpl) NormalizeEmail(ctx context.Context, email string) (string, error) {
	if email == "" {
		return "", fmt.Errorf("email cannot be empty")
	}

	// Trim whitespace and convert to lowercase
	normalized := strings.ToLower(strings.TrimSpace(email))
	
	// Validate normalized email
	if !s.emailRegex.MatchString(normalized) {
		return "", fmt.Errorf("invalid email format")
	}

	return normalized, nil
}

// ValidateIdentifier performs format validation on the identifier
func (s *IdentifierResolutionServiceImpl) ValidateIdentifier(ctx context.Context, identifier string, identifierType domain.IdentifierType) error {
	if identifier == "" {
		return fmt.Errorf("identifier cannot be empty")
	}

	identifier = strings.TrimSpace(identifier)

	switch identifierType {
	case domain.IdentifierTypeEmail:
		if !s.isEmail(identifier) {
			return fmt.Errorf("invalid email format")
		}
		return nil
		
	case domain.IdentifierTypePhone:
		if !s.isPhone(identifier) {
			return fmt.Errorf("invalid phone number format")
		}
		return nil
		
	default:
		return fmt.Errorf("unsupported identifier type: %s", identifierType)
	}
}

// isEmail checks if the identifier is a valid email format
func (s *IdentifierResolutionServiceImpl) isEmail(identifier string) bool {
	return s.emailRegex.MatchString(identifier)
}

// isPhone checks if the identifier is a valid phone number format
func (s *IdentifierResolutionServiceImpl) isPhone(identifier string) bool {
	// Remove non-digit characters except +
	cleaned := regexp.MustCompile(`[^\d+]`).ReplaceAllString(identifier, "")
	
	// Check if it matches international phone pattern
	return s.phoneRegex.MatchString(cleaned) || s.e164Regex.MatchString(cleaned)
}

// extractCountryCode extracts country code from a phone number with + prefix
func (s *IdentifierResolutionServiceImpl) extractCountryCode(phone string) string {
	if !strings.HasPrefix(phone, "+") {
		return "1" // Default to US
	}

	// Remove + and extract potential country codes
	digitsOnly := regexp.MustCompile(`[^\d]`).ReplaceAllString(phone[1:], "")
	
	if len(digitsOnly) == 0 {
		return "1"
	}

	// Common country code patterns (1-4 digits)
	// This is a simplified implementation - in production, use a proper country code library
	if len(digitsOnly) >= 11 && (strings.HasPrefix(digitsOnly, "1")) {
		return "1" // US/Canada
	}
	if len(digitsOnly) >= 12 && (strings.HasPrefix(digitsOnly, "44")) {
		return "44" // UK
	}
	if len(digitsOnly) >= 12 && (strings.HasPrefix(digitsOnly, "49")) {
		return "49" // Germany
	}
	if len(digitsOnly) >= 12 && (strings.HasPrefix(digitsOnly, "33")) {
		return "33" // France
	}
	if len(digitsOnly) >= 13 && (strings.HasPrefix(digitsOnly, "55")) {
		return "55" // Brazil
	}
	
	// Default to single digit country code
	return digitsOnly[:1]
}