package mocks

import (
	"context"
)

// MockDataCascadeDeletor implements domain.DataCascadeDeletor interface for testing
type MockDataCascadeDeletor struct {
	DeleteUserSessionsFunc       func(ctx context.Context, userID uint) (int, error)
	DeleteUserOTPRequestsFunc    func(ctx context.Context, userID uint) (int, error)
	DeletePasswordHistoryFunc    func(ctx context.Context, userID uint) (int, error)
	DeleteOrAnonymizeAuditLogsFunc func(ctx context.Context, userID uint, anonymize bool) (int, error)
	DeleteUserPoliciesFunc       func(ctx context.Context, userID uint) (int, error)
	DeleteUserTokensFunc         func(ctx context.Context, userID uint) (int, error)
	GetUserDataSummaryFunc       func(ctx context.Context, userID uint) (map[string]int, error)
}

// NewMockDataCascadeDeletor creates a new MockDataCascadeDeletor with default behaviors
func NewMockDataCascadeDeletor() *MockDataCascadeDeletor {
	return &MockDataCascadeDeletor{}
}

// DeleteUserSessions deletes all user sessions
func (m *MockDataCascadeDeletor) DeleteUserSessions(ctx context.Context, userID uint) (int, error) {
	if m.DeleteUserSessionsFunc != nil {
		return m.DeleteUserSessionsFunc(ctx, userID)
	}
	return 1, nil // Default: deleted 1 session
}

// DeleteUserOTPRequests deletes all OTP requests for a user
func (m *MockDataCascadeDeletor) DeleteUserOTPRequests(ctx context.Context, userID uint) (int, error) {
	if m.DeleteUserOTPRequestsFunc != nil {
		return m.DeleteUserOTPRequestsFunc(ctx, userID)
	}
	return 0, nil // Default: no OTP requests
}

// DeletePasswordHistory deletes password history for a user
func (m *MockDataCascadeDeletor) DeletePasswordHistory(ctx context.Context, userID uint) (int, error) {
	if m.DeletePasswordHistoryFunc != nil {
		return m.DeletePasswordHistoryFunc(ctx, userID)
	}
	return 2, nil // Default: deleted 2 password history records
}

// DeleteOrAnonymizeAuditLogs deletes or anonymizes audit logs for a user
func (m *MockDataCascadeDeletor) DeleteOrAnonymizeAuditLogs(ctx context.Context, userID uint, anonymize bool) (int, error) {
	if m.DeleteOrAnonymizeAuditLogsFunc != nil {
		return m.DeleteOrAnonymizeAuditLogsFunc(ctx, userID, anonymize)
	}
	return 5, nil // Default: processed 5 audit logs
}

// DeleteUserPolicies deletes user-specific policies
func (m *MockDataCascadeDeletor) DeleteUserPolicies(ctx context.Context, userID uint) (int, error) {
	if m.DeleteUserPoliciesFunc != nil {
		return m.DeleteUserPoliciesFunc(ctx, userID)
	}
	return 0, nil // Default: no user policies
}

// DeleteUserTokens deletes all user tokens
func (m *MockDataCascadeDeletor) DeleteUserTokens(ctx context.Context, userID uint) (int, error) {
	if m.DeleteUserTokensFunc != nil {
		return m.DeleteUserTokensFunc(ctx, userID)
	}
	return 0, nil // Default: no tokens
}

// GetUserDataSummary returns a summary of user data across all tables
func (m *MockDataCascadeDeletor) GetUserDataSummary(ctx context.Context, userID uint) (map[string]int, error) {
	if m.GetUserDataSummaryFunc != nil {
		return m.GetUserDataSummaryFunc(ctx, userID)
	}
	return map[string]int{
		"sessions":       1,
		"audit_logs":     5,
		"password_history": 2,
		"tokens":         0,
	}, nil // Default: sample data summary
}

// Compile-time interface compliance check - Note: Using interface from domain package
// var _ domain.DataCascadeDeletor = (*MockDataCascadeDeletor)(nil)