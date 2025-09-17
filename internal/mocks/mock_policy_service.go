package mocks

import "github.com/you/authzsvc/domain"

// MockPolicyService implements domain.PolicyService interface for testing
type MockPolicyService struct {
	AddPolicyFunc      func(role, resource, action string) error
	RemovePolicyFunc   func(role, resource, action string) error
	CheckPermissionFunc func(role, resource, action string) (bool, error)
	GetPoliciesFunc    func() [][]string
}

// NewMockPolicyService creates a new MockPolicyService with default behaviors
func NewMockPolicyService() *MockPolicyService {
	return &MockPolicyService{}
}

// AddPolicy adds a new authorization policy
func (m *MockPolicyService) AddPolicy(role, resource, action string) error {
	if m.AddPolicyFunc != nil {
		return m.AddPolicyFunc(role, resource, action)
	}
	// Default behavior: success
	return nil
}

// RemovePolicy removes an authorization policy
func (m *MockPolicyService) RemovePolicy(role, resource, action string) error {
	if m.RemovePolicyFunc != nil {
		return m.RemovePolicyFunc(role, resource, action)
	}
	// Default behavior: success
	return nil
}

// CheckPermission checks if a role has permission for a resource and action
func (m *MockPolicyService) CheckPermission(role, resource, action string) (bool, error) {
	if m.CheckPermissionFunc != nil {
		return m.CheckPermissionFunc(role, resource, action)
	}
	// Default behavior: admin has all permissions, user has limited permissions
	if role == "admin" {
		return true, nil
	}
	if role == "user" && resource == "/auth" {
		return true, nil
	}
	return false, nil
}

// GetPolicies returns all current policies
func (m *MockPolicyService) GetPolicies() [][]string {
	if m.GetPoliciesFunc != nil {
		return m.GetPoliciesFunc()
	}
	// Default behavior: return some mock policies
	return [][]string{
		{"admin", "/admin/*", "GET|POST|PUT|DELETE"},
		{"admin", "/auth/*", "GET|POST|PUT|DELETE"},
		{"user", "/auth/me", "GET"},
		{"user", "/auth/logout", "POST"},
	}
}

// Compile-time interface compliance verification
var _ domain.PolicyService = (*MockPolicyService)(nil)