package mocks

import "github.com/you/authzsvc/domain"

// MockCasbinEnforcer implements the CasbinEnforcer interface for testing
type MockCasbinEnforcer struct {
	AddPolicyFunc    func(params ...interface{}) (bool, error)
	RemovePolicyFunc func(params ...interface{}) (bool, error)
	EnforceFunc      func(rvals ...interface{}) (bool, error)
	GetPolicyFunc    func() ([][]string, error)
	SavePolicyFunc   func() error
	LoadPolicyFunc   func() error
	policies         [][]string
}

// Compile-time interface compliance verification
var _ domain.CasbinEnforcer = (*MockCasbinEnforcer)(nil)

// NewMockCasbinEnforcer creates a new MockCasbinEnforcer with default behaviors
func NewMockCasbinEnforcer() *MockCasbinEnforcer {
	return &MockCasbinEnforcer{
		policies: [][]string{
			{"admin", "/admin/*", "GET|POST|PUT|DELETE"},
			{"admin", "/auth/*", "GET|POST|PUT|DELETE"},
			{"user", "/auth/me", "GET"},
			{"user", "/auth/logout", "POST"},
		},
	}
}

// AddPolicy adds a new policy rule
func (m *MockCasbinEnforcer) AddPolicy(params ...interface{}) (bool, error) {
	if m.AddPolicyFunc != nil {
		return m.AddPolicyFunc(params...)
	}
	
	// Default behavior: add to internal policies list
	if len(params) >= 3 {
		policy := make([]string, len(params))
		for i, param := range params {
			if str, ok := param.(string); ok {
				policy[i] = str
			}
		}
		m.policies = append(m.policies, policy)
		return true, nil
	}
	return false, nil
}

// RemovePolicy removes a policy rule
func (m *MockCasbinEnforcer) RemovePolicy(params ...interface{}) (bool, error) {
	if m.RemovePolicyFunc != nil {
		return m.RemovePolicyFunc(params...)
	}
	
	// Default behavior: remove from internal policies list
	if len(params) >= 3 {
		targetPolicy := make([]string, len(params))
		for i, param := range params {
			if str, ok := param.(string); ok {
				targetPolicy[i] = str
			}
		}
		
		for i, policy := range m.policies {
			if len(policy) == len(targetPolicy) {
				match := true
				for j, val := range policy {
					if val != targetPolicy[j] {
						match = false
						break
					}
				}
				if match {
					m.policies = append(m.policies[:i], m.policies[i+1:]...)
					return true, nil
				}
			}
		}
	}
	return false, nil
}

// Enforce checks if a request should be allowed
func (m *MockCasbinEnforcer) Enforce(rvals ...interface{}) (bool, error) {
	if m.EnforceFunc != nil {
		return m.EnforceFunc(rvals...)
	}
	
	// Default behavior: simple role-based authorization
	if len(rvals) >= 3 {
		role, ok1 := rvals[0].(string)
		resource, ok2 := rvals[1].(string)
		action, ok3 := rvals[2].(string)
		
		if ok1 && ok2 && ok3 {
			// Admin can access everything
			if role == "admin" {
				return true, nil
			}
			
			// User can access auth endpoints
			if role == "user" && (resource == "/auth/me" || resource == "/auth/logout") {
				return true, nil
			}
			
			// Check against stored policies
			for _, policy := range m.policies {
				if len(policy) >= 3 && policy[0] == role {
					// Simple pattern matching for resources
					if policy[1] == resource || policy[1] == "/auth/*" || policy[1] == "/*" {
						// Check if action is allowed
						if policy[2] == action || policy[2] == "*" || 
						   (policy[2] == "GET|POST|PUT|DELETE" && (action == "GET" || action == "POST" || action == "PUT" || action == "DELETE")) {
							return true, nil
						}
					}
				}
			}
		}
	}
	
	return false, nil
}

// GetPolicy returns all policies
func (m *MockCasbinEnforcer) GetPolicy() ([][]string, error) {
	if m.GetPolicyFunc != nil {
		return m.GetPolicyFunc()
	}
	// Return copy of internal policies
	result := make([][]string, len(m.policies))
	for i, policy := range m.policies {
		result[i] = make([]string, len(policy))
		copy(result[i], policy)
	}
	return result, nil
}

// SavePolicy saves all policies
func (m *MockCasbinEnforcer) SavePolicy() error {
	if m.SavePolicyFunc != nil {
		return m.SavePolicyFunc()
	}
	// Default behavior: success
	return nil
}

// LoadPolicy loads all policies
func (m *MockCasbinEnforcer) LoadPolicy() error {
	if m.LoadPolicyFunc != nil {
		return m.LoadPolicyFunc()
	}
	// Default behavior: success
	return nil
}

// SetPolicies sets the internal policies (test helper)
func (m *MockCasbinEnforcer) SetPolicies(policies [][]string) {
	m.policies = make([][]string, len(policies))
	for i, policy := range policies {
		m.policies[i] = make([]string, len(policy))
		copy(m.policies[i], policy)
	}
}