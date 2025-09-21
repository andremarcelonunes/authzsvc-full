package mocks

import (
	"context"

	"github.com/you/authzsvc/domain"
)

// MockRequestValidationService implements domain.RequestValidationService interface for testing
type MockRequestValidationService struct {
	ValidateRequestFunc               func(ctx context.Context, request interface{}, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error)
	ValidateRegistrationRequestFunc   func(ctx context.Context, email, phone, password, role string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error)
	ValidateLoginRequestFunc          func(ctx context.Context, email, password string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error)
	ValidateOTPRequestFunc            func(ctx context.Context, phone, code string, userID uint, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error)
	ValidateFieldsFunc                func(ctx context.Context, fields map[string]interface{}, rules []domain.ValidationRule) (*domain.ValidationResult, error)
	ValidateFieldFunc                 func(ctx context.Context, fieldName string, value interface{}, constraints *domain.FieldConstraint) (*domain.FieldValidationResult, error)
	ValidateBatchFunc                 func(ctx context.Context, requests []interface{}, validationCtx *domain.ValidationContext) ([]domain.ValidationResult, error)
}

// NewMockRequestValidationService creates a new MockRequestValidationService with default behaviors
func NewMockRequestValidationService() *MockRequestValidationService {
	return &MockRequestValidationService{}
}

// ValidateRequest validates a request through the complete validation pipeline
func (m *MockRequestValidationService) ValidateRequest(ctx context.Context, request interface{}, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
	if m.ValidateRequestFunc != nil {
		return m.ValidateRequestFunc(ctx, request, validationCtx)
	}
	// Default behavior: valid request
	return &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		FieldResults: make(map[string]domain.FieldValidationResult),
		RulesApplied: 0,
	}, nil
}

// ValidateRegistrationRequest validates user registration requests
func (m *MockRequestValidationService) ValidateRegistrationRequest(ctx context.Context, email, phone, password, role string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
	if m.ValidateRegistrationRequestFunc != nil {
		return m.ValidateRegistrationRequestFunc(ctx, email, phone, password, role, validationCtx)
	}
	// Default behavior: valid registration
	return &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		FieldResults: make(map[string]domain.FieldValidationResult),
		RulesApplied: 0,
	}, nil
}

// ValidateLoginRequest validates user login requests
func (m *MockRequestValidationService) ValidateLoginRequest(ctx context.Context, email, password string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
	if m.ValidateLoginRequestFunc != nil {
		return m.ValidateLoginRequestFunc(ctx, email, password, validationCtx)
	}
	// Default behavior: valid login
	return &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		FieldResults: make(map[string]domain.FieldValidationResult),
		RulesApplied: 0,
	}, nil
}

// ValidateOTPRequest validates OTP verification requests
func (m *MockRequestValidationService) ValidateOTPRequest(ctx context.Context, phone, code string, userID uint, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
	if m.ValidateOTPRequestFunc != nil {
		return m.ValidateOTPRequestFunc(ctx, phone, code, userID, validationCtx)
	}
	// Default behavior: valid OTP
	return &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		FieldResults: make(map[string]domain.FieldValidationResult),
		RulesApplied: 0,
	}, nil
}

// ValidateFields validates individual fields against constraints
func (m *MockRequestValidationService) ValidateFields(ctx context.Context, fields map[string]interface{}, rules []domain.ValidationRule) (*domain.ValidationResult, error) {
	if m.ValidateFieldsFunc != nil {
		return m.ValidateFieldsFunc(ctx, fields, rules)
	}
	// Default behavior: all fields valid
	return &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		FieldResults: make(map[string]domain.FieldValidationResult),
		RulesApplied: 0,
	}, nil
}

// ValidateField validates a single field against constraints
func (m *MockRequestValidationService) ValidateField(ctx context.Context, fieldName string, value interface{}, constraints *domain.FieldConstraint) (*domain.FieldValidationResult, error) {
	if m.ValidateFieldFunc != nil {
		return m.ValidateFieldFunc(ctx, fieldName, value, constraints)
	}
	// Default behavior: field valid
	return &domain.FieldValidationResult{
		FieldName:     fieldName,
		IsValid:       true,
		OriginalValue: value,
		Errors:        []domain.ValidationError{},
		Warnings:      []domain.ValidationError{},
		AppliedRules:  []string{},
	}, nil
}

// ValidateBatch validates multiple requests in parallel
func (m *MockRequestValidationService) ValidateBatch(ctx context.Context, requests []interface{}, validationCtx *domain.ValidationContext) ([]domain.ValidationResult, error) {
	if m.ValidateBatchFunc != nil {
		return m.ValidateBatchFunc(ctx, requests, validationCtx)
	}
	// Default behavior: all requests valid
	results := make([]domain.ValidationResult, len(requests))
	for i := range results {
		results[i] = domain.ValidationResult{
			IsValid:      true,
			Passed:       true,
			Errors:       []domain.ValidationError{},
			Warnings:     []domain.ValidationError{},
			FieldResults: make(map[string]domain.FieldValidationResult),
			RulesApplied: 0,
		}
	}
	return results, nil
}

// Compile-time interface compliance verification
var _ domain.RequestValidationService = (*MockRequestValidationService)(nil)