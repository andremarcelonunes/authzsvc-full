package mocks

import (
	"context"

	"github.com/you/authzsvc/domain"
)

// MockBusinessValidationService implements domain.BusinessValidationService interface for testing
type MockBusinessValidationService struct {
	ValidateRegistrationRulesFunc func(ctx context.Context, email, phone, password, role string) (*domain.ValidationResult, error)
	ValidateLoginRulesFunc        func(ctx context.Context, email, password string, user *domain.User) (*domain.ValidationResult, error)
	ValidateOTPRulesFunc          func(ctx context.Context, phone, code string, userID uint) (*domain.ValidationResult, error)
	ValidatePasswordComplexityFunc func(ctx context.Context, password string) (*domain.ValidationResult, error)
	ValidateBusinessRulesFunc     func(ctx context.Context, entity interface{}, rules []domain.BusinessConstraint) (*domain.ValidationResult, error)
	ValidateResourceLimitsFunc    func(ctx context.Context, userID uint, resource string, requestedAmount int) error
	CheckQuotaLimitsFunc          func(ctx context.Context, userID uint, operation string) (*domain.QuotaStatus, error)
	ValidateDomainConstraintsFunc func(ctx context.Context, entity interface{}, domainName string) (*domain.ValidationResult, error)
	ExecuteCustomValidationFunc   func(ctx context.Context, entity interface{}, validatorName string, params map[string]interface{}) (*domain.ValidationResult, error)
}

// NewMockBusinessValidationService creates a new MockBusinessValidationService with default behaviors
func NewMockBusinessValidationService() *MockBusinessValidationService {
	return &MockBusinessValidationService{}
}

// ValidateRegistrationRules validates business rules for user registration
func (m *MockBusinessValidationService) ValidateRegistrationRules(ctx context.Context, email, phone, password, role string) (*domain.ValidationResult, error) {
	if m.ValidateRegistrationRulesFunc != nil {
		return m.ValidateRegistrationRulesFunc(ctx, email, phone, password, role)
	}
	// Default behavior: valid registration
	return &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: 1,
	}, nil
}

// ValidateLoginRules validates business rules for user login
func (m *MockBusinessValidationService) ValidateLoginRules(ctx context.Context, email, password string, user *domain.User) (*domain.ValidationResult, error) {
	if m.ValidateLoginRulesFunc != nil {
		return m.ValidateLoginRulesFunc(ctx, email, password, user)
	}
	// Default behavior: valid login
	return &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: 1,
	}, nil
}

// ValidateOTPRules validates business rules for OTP verification
func (m *MockBusinessValidationService) ValidateOTPRules(ctx context.Context, phone, code string, userID uint) (*domain.ValidationResult, error) {
	if m.ValidateOTPRulesFunc != nil {
		return m.ValidateOTPRulesFunc(ctx, phone, code, userID)
	}
	// Default behavior: valid OTP
	return &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: 1,
	}, nil
}

// ValidatePasswordComplexity validates password complexity rules
func (m *MockBusinessValidationService) ValidatePasswordComplexity(ctx context.Context, password string) (*domain.ValidationResult, error) {
	if m.ValidatePasswordComplexityFunc != nil {
		return m.ValidatePasswordComplexityFunc(ctx, password)
	}
	// Default behavior: valid password
	return &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: 1,
	}, nil
}

// ValidateBusinessRules validates general business rules
func (m *MockBusinessValidationService) ValidateBusinessRules(ctx context.Context, entity interface{}, rules []domain.BusinessConstraint) (*domain.ValidationResult, error) {
	if m.ValidateBusinessRulesFunc != nil {
		return m.ValidateBusinessRulesFunc(ctx, entity, rules)
	}
	// Default behavior: valid business rules
	return &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: len(rules),
	}, nil
}

// ValidateResourceLimits validates resource usage limits
func (m *MockBusinessValidationService) ValidateResourceLimits(ctx context.Context, userID uint, resource string, requestedAmount int) error {
	if m.ValidateResourceLimitsFunc != nil {
		return m.ValidateResourceLimitsFunc(ctx, userID, resource, requestedAmount)
	}
	// Default behavior: no limit exceeded
	return nil
}

// CheckQuotaLimits checks quota limits for a user operation
func (m *MockBusinessValidationService) CheckQuotaLimits(ctx context.Context, userID uint, operation string) (*domain.QuotaStatus, error) {
	if m.CheckQuotaLimitsFunc != nil {
		return m.CheckQuotaLimitsFunc(ctx, userID, operation)
	}
	// Default behavior: quota available
	return &domain.QuotaStatus{
		UserID:       userID,
		Resource:     operation,
		CurrentUsage: 0,
		Limit:        100,
		Available:    100,
		IsExceeded:   false,
	}, nil
}

// ValidateDomainConstraints validates domain-specific constraints
func (m *MockBusinessValidationService) ValidateDomainConstraints(ctx context.Context, entity interface{}, domainName string) (*domain.ValidationResult, error) {
	if m.ValidateDomainConstraintsFunc != nil {
		return m.ValidateDomainConstraintsFunc(ctx, entity, domainName)
	}
	// Default behavior: valid domain constraints
	return &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: 1,
	}, nil
}

// ExecuteCustomValidation executes custom validation logic
func (m *MockBusinessValidationService) ExecuteCustomValidation(ctx context.Context, entity interface{}, validatorName string, params map[string]interface{}) (*domain.ValidationResult, error) {
	if m.ExecuteCustomValidationFunc != nil {
		return m.ExecuteCustomValidationFunc(ctx, entity, validatorName, params)
	}
	// Default behavior: valid custom validation
	return &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: 1,
	}, nil
}

// Compile-time interface compliance verification
var _ domain.BusinessValidationService = (*MockBusinessValidationService)(nil)