package mocks

import (
	"context"

	"github.com/you/authzsvc/domain"
)

// MockIntegrityChecker implements domain.IntegrityChecker interface for testing
type MockIntegrityChecker struct {
	CalculateChecksumFunc           func(data interface{}) (string, error)
	VerifyChecksumFunc              func(data interface{}, expectedChecksum string) (bool, error)
	VerifyBatchIntegrityFunc        func(ctx context.Context, events []*domain.ComprehensiveAuditEvent) ([]bool, error)
	DetectTamperingFunc             func(ctx context.Context, event *domain.ComprehensiveAuditEvent) (bool, []string, error)
	ScanForIntegrityViolationsFunc  func(ctx context.Context, criteria *domain.AuditCriteria) ([]*domain.ComprehensiveAuditEvent, error)
}

// NewMockIntegrityChecker creates a new MockIntegrityChecker with default behaviors
func NewMockIntegrityChecker() *MockIntegrityChecker {
	return &MockIntegrityChecker{}
}

// CalculateChecksum calculates checksum for data
func (m *MockIntegrityChecker) CalculateChecksum(data interface{}) (string, error) {
	if m.CalculateChecksumFunc != nil {
		return m.CalculateChecksumFunc(data)
	}
	// Default behavior: return mock checksum
	return "mock_checksum_12345", nil
}

// VerifyChecksum verifies data against expected checksum
func (m *MockIntegrityChecker) VerifyChecksum(data interface{}, expectedChecksum string) (bool, error) {
	if m.VerifyChecksumFunc != nil {
		return m.VerifyChecksumFunc(data, expectedChecksum)
	}
	// Default behavior: valid checksum
	return true, nil
}

// VerifyBatchIntegrity verifies integrity of multiple events
func (m *MockIntegrityChecker) VerifyBatchIntegrity(ctx context.Context, events []*domain.ComprehensiveAuditEvent) ([]bool, error) {
	if m.VerifyBatchIntegrityFunc != nil {
		return m.VerifyBatchIntegrityFunc(ctx, events)
	}
	// Default behavior: all events are valid
	results := make([]bool, len(events))
	for i := range results {
		results[i] = true
	}
	return results, nil
}

// DetectTampering detects tampering in audit event
func (m *MockIntegrityChecker) DetectTampering(ctx context.Context, event *domain.ComprehensiveAuditEvent) (bool, []string, error) {
	if m.DetectTamperingFunc != nil {
		return m.DetectTamperingFunc(ctx, event)
	}
	// Default behavior: no tampering detected
	return false, []string{}, nil
}

// ScanForIntegrityViolations scans for integrity violations
func (m *MockIntegrityChecker) ScanForIntegrityViolations(ctx context.Context, criteria *domain.AuditCriteria) ([]*domain.ComprehensiveAuditEvent, error) {
	if m.ScanForIntegrityViolationsFunc != nil {
		return m.ScanForIntegrityViolationsFunc(ctx, criteria)
	}
	// Default behavior: no violations found
	return []*domain.ComprehensiveAuditEvent{}, nil
}

// Compile-time interface compliance verification
var _ domain.IntegrityChecker = (*MockIntegrityChecker)(nil)