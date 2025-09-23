package services

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/you/authzsvc/domain"
)

// BusinessValidationServiceImpl implements domain.BusinessValidationService
type BusinessValidationServiceImpl struct {
	userRepo   domain.UserRepository
	logger     *slog.Logger
	
	// Validation configuration
	passwordPolicy    PasswordPolicy
	emailValidation   EmailValidationConfig
	phoneValidation   PhoneValidationConfig
	userLimits       UserLimitsConfig
}

// PasswordPolicy defines password complexity requirements
type PasswordPolicy struct {
	MinLength           int
	MaxLength           int
	RequireUppercase    bool
	RequireLowercase    bool
	RequireNumbers      bool
	RequireSpecialChars bool
	ForbiddenPasswords  []string
	MaxRepeatingChars   int
}

// EmailValidationConfig defines email validation rules
type EmailValidationConfig struct {
	AllowedDomains    []string
	BlockedDomains    []string
	RequireVerification bool
	MaxLength         int
}

// PhoneValidationConfig defines phone validation rules
type PhoneValidationConfig struct {
	RequiredFormat    string // E.164, national, etc.
	AllowedCountries  []string
	BlockedCountries  []string
	RequireVerification bool
}

// UserLimitsConfig defines user-based limits
type UserLimitsConfig struct {
	MaxRegistrationsPerIP   int
	MaxRegistrationsPerDay  int
	MaxLoginAttemptsPerHour int
	MaxOTPAttemptsPerHour   int
}

// BusinessValidationConfig holds configuration for business validation
type BusinessValidationConfig struct {
	PasswordPolicy  PasswordPolicy
	EmailValidation EmailValidationConfig
	PhoneValidation PhoneValidationConfig
	UserLimits      UserLimitsConfig
}

// NewBusinessValidationService creates a new business validation service
func NewBusinessValidationService(
	userRepo domain.UserRepository,
	config BusinessValidationConfig,
) domain.BusinessValidationService {
	// Set default password policy if not provided
	if config.PasswordPolicy.MinLength == 0 {
		config.PasswordPolicy = PasswordPolicy{
			MinLength:           8,
			MaxLength:           128,
			RequireUppercase:    true,
			RequireLowercase:    true,
			RequireNumbers:      true,
			RequireSpecialChars: true,
			MaxRepeatingChars:   3,
			ForbiddenPasswords: []string{
				"password", "123456", "qwerty", "admin", "user",
				"password123", "123456789", "12345678", "abc123",
			},
		}
	}

	// Set default email validation if not provided
	if config.EmailValidation.MaxLength == 0 {
		config.EmailValidation = EmailValidationConfig{
			AllowedDomains:      []string{}, // Empty means allow all
			BlockedDomains:      []string{"tempmail.com", "10minutemail.com", "guerrillamail.com"},
			RequireVerification: true,
			MaxLength:          254, // RFC 5321 limit
		}
	}

	// Set default user limits if not provided
	if config.UserLimits.MaxRegistrationsPerIP == 0 {
		config.UserLimits = UserLimitsConfig{
			MaxRegistrationsPerIP:   5,
			MaxRegistrationsPerDay:  10,
			MaxLoginAttemptsPerHour: 10,
			MaxOTPAttemptsPerHour:   5,
		}
	}

	return &BusinessValidationServiceImpl{
		userRepo:        userRepo,
		logger:          slog.Default(),
		passwordPolicy:  config.PasswordPolicy,
		emailValidation: config.EmailValidation,
		phoneValidation: config.PhoneValidation,
		userLimits:      config.UserLimits,
	}
}

// ValidateRegistrationRules validates business rules for user registration
func (s *BusinessValidationServiceImpl) ValidateRegistrationRules(ctx context.Context, email, phone, password, role string) (*domain.ValidationResult, error) {
	startTime := time.Now()
	
	result := &domain.ValidationResult{
		ValidationID: fmt.Sprintf("biz_reg_%d", time.Now().UnixNano()),
		Timestamp:    startTime,
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: 0,
	}

	// Validate email business rules
	if err := s.validateEmailRules(email, result); err != nil {
		return nil, fmt.Errorf("email validation failed: %w", err)
	}

	// Validate phone business rules
	if err := s.validatePhoneRules(phone, result); err != nil {
		return nil, fmt.Errorf("phone validation failed: %w", err)
	}

	// Validate password complexity
	if err := s.validatePasswordComplexityRules(password, result); err != nil {
		return nil, fmt.Errorf("password complexity validation failed: %w", err)
	}

	// Validate role assignment
	if err := s.validateRoleRules(role, result); err != nil {
		return nil, fmt.Errorf("role validation failed: %w", err)
	}

	// Check for existing user with same email
	if existingUser, err := s.userRepo.FindByEmail(ctx, email); err == nil && existingUser != nil {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "EMAIL_ALREADY_EXISTS",
			Field:     "email",
			Message:   "Email address is already registered",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Value:     email,
			Timestamp: time.Now(),
		})
	}

	// Check for existing user with same phone
	if existingUser, err := s.userRepo.FindByPhone(ctx, phone); err == nil && existingUser != nil {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "PHONE_ALREADY_EXISTS",
			Field:     "phone",
			Message:   "Phone number is already registered",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Value:     phone,
			Timestamp: time.Now(),
		})
	}

	result.ValidationTime = time.Since(startTime)
	return result, nil
}

// ValidateLoginRules validates business rules for user login
func (s *BusinessValidationServiceImpl) ValidateLoginRules(ctx context.Context, email, password string, user *domain.User) (*domain.ValidationResult, error) {
	startTime := time.Now()
	
	result := &domain.ValidationResult{
		ValidationID: fmt.Sprintf("biz_login_%d", time.Now().UnixNano()),
		Timestamp:    startTime,
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: 0,
	}

	// Validate email format
	if err := s.validateEmailFormat(email, result); err != nil {
		return nil, fmt.Errorf("email format validation failed: %w", err)
	}

	// Validate password is not empty
	if password == "" {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "PASSWORD_REQUIRED",
			Field:     "password",
			Message:   "Password is required",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Timestamp: time.Now(),
		})
	}

	// If user is provided, validate user-specific rules
	if user != nil {
		if !user.IsActive {
			result.IsValid = false
			result.Passed = false
			result.Errors = append(result.Errors, domain.ValidationError{
				Code:      "USER_INACTIVE",
				Field:     "user",
				Message:   "User account is inactive",
				Severity:  domain.SeverityError,
				Category:  domain.CategoryBusiness,
				Timestamp: time.Now(),
			})
		}

		// Check phone verification requirement
		if s.phoneValidation.RequireVerification && !user.PhoneVerified {
			result.IsValid = false
			result.Passed = false
			result.Errors = append(result.Errors, domain.ValidationError{
				Code:      "PHONE_NOT_VERIFIED",
				Field:     "phone",
				Message:   "Phone number must be verified before login",
				Severity:  domain.SeverityError,
				Category:  domain.CategoryBusiness,
				Timestamp: time.Now(),
			})
		}
	}

	result.ValidationTime = time.Since(startTime)
	return result, nil
}

// ValidateOTPRules validates business rules for OTP verification
func (s *BusinessValidationServiceImpl) ValidateOTPRules(ctx context.Context, phone, code string, userID uint) (*domain.ValidationResult, error) {
	startTime := time.Now()
	
	result := &domain.ValidationResult{
		ValidationID: fmt.Sprintf("biz_otp_%d", time.Now().UnixNano()),
		Timestamp:    startTime,
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: 0,
	}

	// Validate phone format
	if err := s.validatePhoneFormat(phone, result); err != nil {
		return nil, fmt.Errorf("phone format validation failed: %w", err)
	}

	// Validate OTP code format (skip for OTP send requests where code is empty)
	if code != "" {
		if err := s.validateOTPFormat(code, result); err != nil {
			return nil, fmt.Errorf("OTP format validation failed: %w", err)
		}
	}

	// Validate user exists
	if user, err := s.userRepo.FindByID(ctx, userID); err != nil || user == nil {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "USER_NOT_FOUND",
			Field:     "user_id",
			Message:   "User not found",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Value:     userID,
			Timestamp: time.Now(),
		})
	}

	result.ValidationTime = time.Since(startTime)
	return result, nil
}

// ValidatePasswordComplexity validates password complexity rules
func (s *BusinessValidationServiceImpl) ValidatePasswordComplexity(ctx context.Context, password string) (*domain.ValidationResult, error) {
	startTime := time.Now()
	
	result := &domain.ValidationResult{
		ValidationID: fmt.Sprintf("biz_pwd_%d", time.Now().UnixNano()),
		Timestamp:    startTime,
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: 0,
	}

	if err := s.validatePasswordComplexityRules(password, result); err != nil {
		return nil, fmt.Errorf("password complexity validation failed: %w", err)
	}

	result.ValidationTime = time.Since(startTime)
	return result, nil
}

// ValidateBusinessRules validates general business rules
func (s *BusinessValidationServiceImpl) ValidateBusinessRules(ctx context.Context, entity interface{}, rules []domain.BusinessConstraint) (*domain.ValidationResult, error) {
	startTime := time.Now()
	
	result := &domain.ValidationResult{
		ValidationID: fmt.Sprintf("biz_gen_%d", time.Now().UnixNano()),
		Timestamp:    startTime,
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: 0,
	}

	// Process each business constraint
	for _, rule := range rules {
		s.processBusinessConstraint(entity, rule, result)
		result.RulesApplied++
	}

	result.ValidationTime = time.Since(startTime)
	return result, nil
}

// ValidateResourceLimits validates resource usage limits
func (s *BusinessValidationServiceImpl) ValidateResourceLimits(ctx context.Context, userID uint, resource string, requestedAmount int) error {
	// TODO: Implement resource limit validation
	return nil
}

// CheckQuotaLimits checks quota limits for a user operation
func (s *BusinessValidationServiceImpl) CheckQuotaLimits(ctx context.Context, userID uint, operation string) (*domain.QuotaStatus, error) {
	// TODO: Implement quota checking
	return &domain.QuotaStatus{
		UserID:       userID,
		Resource:     operation,
		CurrentUsage: 0,
		Limit:        100,
		Available:    100,
		ResetTime:    time.Now().Add(24 * time.Hour),
		IsExceeded:   false,
	}, nil
}

// ValidateDomainConstraints validates domain-specific constraints
func (s *BusinessValidationServiceImpl) ValidateDomainConstraints(ctx context.Context, entity interface{}, domainName string) (*domain.ValidationResult, error) {
	// TODO: Implement domain constraint validation
	return &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: 0,
	}, nil
}

// ExecuteCustomValidation executes custom validation logic
func (s *BusinessValidationServiceImpl) ExecuteCustomValidation(ctx context.Context, entity interface{}, validatorName string, params map[string]interface{}) (*domain.ValidationResult, error) {
	// TODO: Implement custom validation execution
	return &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: 0,
	}, nil
}

// Helper methods

func (s *BusinessValidationServiceImpl) validateEmailRules(email string, result *domain.ValidationResult) error {
	result.RulesApplied++

	// Basic email format validation
	if err := s.validateEmailFormat(email, result); err != nil {
		return err
	}

	// Domain validation
	if err := s.validateEmailDomain(email, result); err != nil {
		return err
	}

	// Length validation
	if len(email) > s.emailValidation.MaxLength {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "EMAIL_TOO_LONG",
			Field:     "email",
			Message:   fmt.Sprintf("Email address is too long (max %d characters)", s.emailValidation.MaxLength),
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Value:     email,
			Expected:  s.emailValidation.MaxLength,
			Timestamp: time.Now(),
		})
	}

	return nil
}

func (s *BusinessValidationServiceImpl) validateEmailFormat(email string, result *domain.ValidationResult) error {
	emailPattern := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailPattern.MatchString(email) {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "EMAIL_FORMAT_INVALID",
			Field:     "email",
			Message:   "Email address format is invalid",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Value:     email,
			Timestamp: time.Now(),
		})
	}
	return nil
}

func (s *BusinessValidationServiceImpl) validateEmailDomain(email string, result *domain.ValidationResult) error {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return nil // Format validation will catch this
	}
	
	emailDomain := strings.ToLower(parts[1])

	// Check blocked domains
	for _, blockedDomain := range s.emailValidation.BlockedDomains {
		if emailDomain == strings.ToLower(blockedDomain) {
			result.IsValid = false
			result.Passed = false
			result.Errors = append(result.Errors, domain.ValidationError{
				Code:      "EMAIL_DOMAIN_BLOCKED",
				Field:     "email",
				Message:   "Email domain is not allowed",
				Severity:  domain.SeverityError,
				Category:  domain.CategoryBusiness,
				Value:     email,
				Timestamp: time.Now(),
			})
			return nil
		}
	}

	// Check allowed domains (if specified)
	if len(s.emailValidation.AllowedDomains) > 0 {
		allowed := false
		for _, allowedDomain := range s.emailValidation.AllowedDomains {
			if emailDomain == strings.ToLower(allowedDomain) {
				allowed = true
				break
			}
		}
		if !allowed {
			result.IsValid = false
			result.Passed = false
			result.Errors = append(result.Errors, domain.ValidationError{
				Code:      "EMAIL_DOMAIN_NOT_ALLOWED",
				Field:     "email",
				Message:   "Email domain is not in the allowed list",
				Severity:  domain.SeverityError,
				Category:  domain.CategoryBusiness,
				Value:     email,
				Timestamp: time.Now(),
			})
		}
	}

	return nil
}

func (s *BusinessValidationServiceImpl) validatePhoneRules(phone string, result *domain.ValidationResult) error {
	result.RulesApplied++

	return s.validatePhoneFormat(phone, result)
}

func (s *BusinessValidationServiceImpl) validatePhoneFormat(phone string, result *domain.ValidationResult) error {
	// Basic phone number validation (digits, +, -, spaces, parentheses)
	phonePattern := regexp.MustCompile(`^[+]?[\d\s\-\(\)]{10,15}$`)
	if !phonePattern.MatchString(phone) {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "PHONE_FORMAT_INVALID",
			Field:     "phone",
			Message:   "Phone number format is invalid",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Value:     phone,
			Timestamp: time.Now(),
		})
	}
	return nil
}

func (s *BusinessValidationServiceImpl) validatePasswordComplexityRules(password string, result *domain.ValidationResult) error {
	result.RulesApplied++

	// Length validation
	if len(password) < s.passwordPolicy.MinLength {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "PASSWORD_TOO_SHORT",
			Field:     "password",
			Message:   fmt.Sprintf("Password must be at least %d characters long", s.passwordPolicy.MinLength),
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Expected:  s.passwordPolicy.MinLength,
			Timestamp: time.Now(),
		})
	}

	if len(password) > s.passwordPolicy.MaxLength {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "PASSWORD_TOO_LONG",
			Field:     "password",
			Message:   fmt.Sprintf("Password must be at most %d characters long", s.passwordPolicy.MaxLength),
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Expected:  s.passwordPolicy.MaxLength,
			Timestamp: time.Now(),
		})
	}

	// Character requirement validation
	if s.passwordPolicy.RequireUppercase && !regexp.MustCompile(`[A-Z]`).MatchString(password) {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "PASSWORD_MISSING_UPPERCASE",
			Field:     "password",
			Message:   "Password must contain at least one uppercase letter",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Timestamp: time.Now(),
		})
	}

	if s.passwordPolicy.RequireLowercase && !regexp.MustCompile(`[a-z]`).MatchString(password) {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "PASSWORD_MISSING_LOWERCASE",
			Field:     "password",
			Message:   "Password must contain at least one lowercase letter",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Timestamp: time.Now(),
		})
	}

	if s.passwordPolicy.RequireNumbers && !regexp.MustCompile(`[0-9]`).MatchString(password) {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "PASSWORD_MISSING_NUMBER",
			Field:     "password",
			Message:   "Password must contain at least one number",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Timestamp: time.Now(),
		})
	}

	if s.passwordPolicy.RequireSpecialChars && !regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(password) {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "PASSWORD_MISSING_SPECIAL",
			Field:     "password",
			Message:   "Password must contain at least one special character",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Timestamp: time.Now(),
		})
	}

	// Check for forbidden passwords
	passwordLower := strings.ToLower(password)
	for _, forbidden := range s.passwordPolicy.ForbiddenPasswords {
		if passwordLower == strings.ToLower(forbidden) {
			result.IsValid = false
			result.Passed = false
			result.Errors = append(result.Errors, domain.ValidationError{
				Code:      "PASSWORD_FORBIDDEN",
				Field:     "password",
				Message:   "Password is too common and not allowed",
				Severity:  domain.SeverityError,
				Category:  domain.CategoryBusiness,
				Timestamp: time.Now(),
			})
			break
		}
	}

	// Check for repeating characters
	if s.passwordPolicy.MaxRepeatingChars > 0 {
		if s.hasRepeatingChars(password, s.passwordPolicy.MaxRepeatingChars) {
			result.IsValid = false
			result.Passed = false
			result.Errors = append(result.Errors, domain.ValidationError{
				Code:      "PASSWORD_REPEATING_CHARS",
				Field:     "password",
				Message:   fmt.Sprintf("Password cannot have more than %d repeating characters", s.passwordPolicy.MaxRepeatingChars),
				Severity:  domain.SeverityError,
				Category:  domain.CategoryBusiness,
				Timestamp: time.Now(),
			})
		}
	}

	return nil
}

func (s *BusinessValidationServiceImpl) validateRoleRules(role string, result *domain.ValidationResult) error {
	result.RulesApplied++

	// Define allowed roles
	allowedRoles := []string{"user", "admin", "moderator"}
	
	roleValid := false
	for _, allowedRole := range allowedRoles {
		if role == allowedRole {
			roleValid = true
			break
		}
	}

	if !roleValid {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "ROLE_INVALID",
			Field:     "role",
			Message:   "Invalid role specified",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Value:     role,
			Expected:  allowedRoles,
			Timestamp: time.Now(),
		})
	}

	return nil
}

func (s *BusinessValidationServiceImpl) validateOTPFormat(code string, result *domain.ValidationResult) error {
	// OTP should be 6 digits
	otpPattern := regexp.MustCompile(`^\d{6}$`)
	if !otpPattern.MatchString(code) {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "OTP_FORMAT_INVALID",
			Field:     "otp_code",
			Message:   "OTP code must be 6 digits",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryBusiness,
			Value:     code,
			Expected:  "6 digits",
			Timestamp: time.Now(),
		})
	}
	return nil
}

func (s *BusinessValidationServiceImpl) processBusinessConstraint(entity interface{}, constraint domain.BusinessConstraint, result *domain.ValidationResult) {
	// TODO: Implement business constraint processing based on constraint type
	// This would involve checking domain rules, workflow states, resource limits, etc.
}

func (s *BusinessValidationServiceImpl) hasRepeatingChars(password string, maxRepeating int) bool {
	if len(password) <= maxRepeating {
		return false
	}

	count := 1
	for i := 1; i < len(password); i++ {
		if password[i] == password[i-1] {
			count++
			if count > maxRepeating {
				return true
			}
		} else {
			count = 1
		}
	}
	return false
}

// Compile-time interface compliance verification
var _ domain.BusinessValidationService = (*BusinessValidationServiceImpl)(nil)