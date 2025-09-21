package mocks

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
)

// MockSecurityValidationService implements domain.SecurityValidationService interface for testing
type MockSecurityValidationService struct {
	ScanForThreatsFunc        func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error)
	DetectXSSFunc             func(ctx context.Context, input string) (*domain.SecurityValidationResult, error)
	DetectSQLInjectionFunc    func(ctx context.Context, input string) (*domain.SecurityValidationResult, error)
	DetectScriptInjectionFunc func(ctx context.Context, input string) (*domain.SecurityValidationResult, error)
	SanitizeInputFunc         func(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (map[string]interface{}, error)
	SanitizeHTMLFunc          func(ctx context.Context, html string) (string, error)
	RecordViolationFunc       func(ctx context.Context, violation *domain.SecurityViolation) error
	GetViolationHistoryFunc   func(ctx context.Context, userID uint, timeWindow time.Duration) ([]domain.SecurityViolation, error)
}

// NewMockSecurityValidationService creates a new MockSecurityValidationService with default behaviors
func NewMockSecurityValidationService() *MockSecurityValidationService {
	return &MockSecurityValidationService{}
}

// ScanForThreats performs comprehensive threat scanning on input data
func (m *MockSecurityValidationService) ScanForThreats(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
	if m.ScanForThreatsFunc != nil {
		return m.ScanForThreatsFunc(ctx, input, rules)
	}
	// Default behavior: no threats detected
	return &domain.SecurityValidationResult{
		ThreatLevel:    domain.ThreatNone,
		ThreatTypes:    []domain.ThreatType{},
		Violations:     []domain.SecurityViolation{},
		SanitizedInput: input,
		BlockedContent: []string{},
		ScanResults:    make(map[string]interface{}),
	}, nil
}

// DetectXSS detects cross-site scripting attempts
func (m *MockSecurityValidationService) DetectXSS(ctx context.Context, input string) (*domain.SecurityValidationResult, error) {
	if m.DetectXSSFunc != nil {
		return m.DetectXSSFunc(ctx, input)
	}
	// Default behavior: no XSS detected
	return &domain.SecurityValidationResult{
		ThreatLevel: domain.ThreatNone,
		ThreatTypes: []domain.ThreatType{},
		Violations:  []domain.SecurityViolation{},
	}, nil
}

// DetectSQLInjection detects SQL injection attempts
func (m *MockSecurityValidationService) DetectSQLInjection(ctx context.Context, input string) (*domain.SecurityValidationResult, error) {
	if m.DetectSQLInjectionFunc != nil {
		return m.DetectSQLInjectionFunc(ctx, input)
	}
	// Default behavior: no SQL injection detected
	return &domain.SecurityValidationResult{
		ThreatLevel: domain.ThreatNone,
		ThreatTypes: []domain.ThreatType{},
		Violations:  []domain.SecurityViolation{},
	}, nil
}

// DetectScriptInjection detects script injection attempts
func (m *MockSecurityValidationService) DetectScriptInjection(ctx context.Context, input string) (*domain.SecurityValidationResult, error) {
	if m.DetectScriptInjectionFunc != nil {
		return m.DetectScriptInjectionFunc(ctx, input)
	}
	// Default behavior: no script injection detected
	return &domain.SecurityValidationResult{
		ThreatLevel: domain.ThreatNone,
		ThreatTypes: []domain.ThreatType{},
		Violations:  []domain.SecurityViolation{},
	}, nil
}

// SanitizeInput sanitizes input data according to security rules
func (m *MockSecurityValidationService) SanitizeInput(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (map[string]interface{}, error) {
	if m.SanitizeInputFunc != nil {
		return m.SanitizeInputFunc(ctx, input, rules)
	}
	// Default behavior: return input unchanged
	return input, nil
}

// SanitizeHTML sanitizes HTML content
func (m *MockSecurityValidationService) SanitizeHTML(ctx context.Context, html string) (string, error) {
	if m.SanitizeHTMLFunc != nil {
		return m.SanitizeHTMLFunc(ctx, html)
	}
	// Default behavior: return HTML unchanged
	return html, nil
}

// RecordViolation records a security violation
func (m *MockSecurityValidationService) RecordViolation(ctx context.Context, violation *domain.SecurityViolation) error {
	if m.RecordViolationFunc != nil {
		return m.RecordViolationFunc(ctx, violation)
	}
	// Default behavior: success
	return nil
}

// GetViolationHistory retrieves violation history for a user
func (m *MockSecurityValidationService) GetViolationHistory(ctx context.Context, userID uint, timeWindow time.Duration) ([]domain.SecurityViolation, error) {
	if m.GetViolationHistoryFunc != nil {
		return m.GetViolationHistoryFunc(ctx, userID, timeWindow)
	}
	// Default behavior: empty history
	return []domain.SecurityViolation{}, nil
}

// Compile-time interface compliance verification
var _ domain.SecurityValidationService = (*MockSecurityValidationService)(nil)