package mocks

import (
	"context"

	"github.com/you/authzsvc/domain"
)

// MockLGPDComplianceChecker implements domain.LGPDComplianceChecker interface for testing
type MockLGPDComplianceChecker struct {
	CanDeleteUserFunc               func(ctx context.Context, userID uint) (bool, string, error)
	GetRetentionRequirementsFunc    func(ctx context.Context, userID uint) ([]domain.DataRetentionPolicy, error)
	ValidateDeletionRequestFunc     func(ctx context.Context, request *domain.DeletionRequest) error
	IsAnonymizationSufficientFunc   func(ctx context.Context, userID uint) (bool, error)
	GenerateComplianceReportFunc    func(ctx context.Context, userID uint) (map[string]interface{}, error)
}

// NewMockLGPDComplianceChecker creates a new MockLGPDComplianceChecker with default behaviors
func NewMockLGPDComplianceChecker() *MockLGPDComplianceChecker {
	return &MockLGPDComplianceChecker{}
}

// CanDeleteUser checks if a user can be deleted based on legal requirements
func (m *MockLGPDComplianceChecker) CanDeleteUser(ctx context.Context, userID uint) (bool, string, error) {
	if m.CanDeleteUserFunc != nil {
		return m.CanDeleteUserFunc(ctx, userID)
	}
	return true, "", nil // Default: can delete
}

// GetRetentionRequirements returns data retention requirements for a user
func (m *MockLGPDComplianceChecker) GetRetentionRequirements(ctx context.Context, userID uint) ([]domain.DataRetentionPolicy, error) {
	if m.GetRetentionRequirementsFunc != nil {
		return m.GetRetentionRequirementsFunc(ctx, userID)
	}
	return []domain.DataRetentionPolicy{}, nil // Default: no requirements
}

// ValidateDeletionRequest validates a deletion request for compliance
func (m *MockLGPDComplianceChecker) ValidateDeletionRequest(ctx context.Context, request *domain.DeletionRequest) error {
	if m.ValidateDeletionRequestFunc != nil {
		return m.ValidateDeletionRequestFunc(ctx, request)
	}
	return nil // Default: valid
}

// IsAnonymizationSufficient checks if anonymization is sufficient for compliance
func (m *MockLGPDComplianceChecker) IsAnonymizationSufficient(ctx context.Context, userID uint) (bool, error) {
	if m.IsAnonymizationSufficientFunc != nil {
		return m.IsAnonymizationSufficientFunc(ctx, userID)
	}
	return true, nil // Default: sufficient
}

// GenerateComplianceReport generates a compliance report for a user
func (m *MockLGPDComplianceChecker) GenerateComplianceReport(ctx context.Context, userID uint) (map[string]interface{}, error) {
	if m.GenerateComplianceReportFunc != nil {
		return m.GenerateComplianceReportFunc(ctx, userID)
	}
	return map[string]interface{}{
		"user_id": userID,
		"status":  "compliant",
	}, nil // Default: compliant
}

// Compile-time interface compliance check
var _ domain.LGPDComplianceChecker = (*MockLGPDComplianceChecker)(nil)