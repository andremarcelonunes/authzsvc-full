package services

import (
	"testing"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// createPolicyServiceForTest creates a PolicyService with mock Casbin enforcer
func createPolicyServiceForTest(t *testing.T) (domain.PolicyService, *mocks.MockCasbinEnforcer) {
	t.Helper()

	// Create mock Casbin enforcer
	enforcer := mocks.NewMockCasbinEnforcer()

	// Create policy service using the test constructor
	policyService := NewPolicyServiceWithEnforcer(enforcer)

	return policyService, enforcer
}

func TestPolicyServiceImpl_AddPolicy(t *testing.T) {
	tests := []struct {
		name             string
		role             string
		resource         string
		action           string
		setupMock        func(*mocks.MockCasbinEnforcer)
		expectedError    error
		expectedAdded    bool
		expectedSaveCalled bool
	}{
		{
			name:     "successful policy addition",
			role:     "user",
			resource: "/api/profile",
			action:   "GET",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.AddPolicyFunc = func(params ...interface{}) (bool, error) {
					if len(params) == 3 &&
						params[0].(string) == "user" &&
						params[1].(string) == "/api/profile" &&
						params[2].(string) == "GET" {
						return true, nil
					}
					return false, nil
				}
				enforcer.SavePolicyFunc = func() error {
					return nil
				}
			},
			expectedError:      nil,
			expectedAdded:      true,
			expectedSaveCalled: true,
		},
		{
			name:     "policy already exists",
			role:     "admin",
			resource: "/api/admin",
			action:   "POST",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.AddPolicyFunc = func(params ...interface{}) (bool, error) {
					// Return false indicating policy already exists
					return false, nil
				}
				enforcer.SavePolicyFunc = func() error {
					return nil
				}
			},
			expectedError:      nil,
			expectedAdded:      false,
			expectedSaveCalled: true,
		},
		{
			name:     "add policy fails",
			role:     "user",
			resource: "/api/test",
			action:   "DELETE",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.AddPolicyFunc = func(params ...interface{}) (bool, error) {
					return false, domain.ErrUnauthorized
				}
				enforcer.SavePolicyFunc = func() error {
					t.Error("SavePolicy should not be called when AddPolicy fails")
					return nil
				}
			},
			expectedError:      domain.ErrUnauthorized,
			expectedAdded:      false,
			expectedSaveCalled: false,
		},
		{
			name:     "save policy fails",
			role:     "user",
			resource: "/api/test",
			action:   "PUT",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.AddPolicyFunc = func(params ...interface{}) (bool, error) {
					return true, nil
				}
				enforcer.SavePolicyFunc = func() error {
					return domain.ErrResourceNotFound
				}
			},
			expectedError:      domain.ErrResourceNotFound,
			expectedAdded:      true,
			expectedSaveCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create service and mock
			policyService, mockEnforcer := createPolicyServiceForTest(t)

			// Setup test-specific mock behavior
			tt.setupMock(mockEnforcer)

			// Track calls
			addPolicyCalled := false
			savePolicyCalled := false

			// Wrap functions to track calls
			originalAddPolicy := mockEnforcer.AddPolicyFunc
			mockEnforcer.AddPolicyFunc = func(params ...interface{}) (bool, error) {
				addPolicyCalled = true
				if originalAddPolicy != nil {
					return originalAddPolicy(params...)
				}
				return false, nil
			}

			originalSavePolicy := mockEnforcer.SavePolicyFunc
			mockEnforcer.SavePolicyFunc = func() error {
				savePolicyCalled = true
				if originalSavePolicy != nil {
					return originalSavePolicy()
				}
				return nil
			}

			// Execute test
			err := policyService.AddPolicy(tt.role, tt.resource, tt.action)

			// Validate error
			if tt.expectedError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.expectedError)
				}
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Validate function calls
			if !addPolicyCalled {
				t.Error("expected AddPolicy to be called")
			}

			if tt.expectedSaveCalled && !savePolicyCalled {
				t.Error("expected SavePolicy to be called")
			}

			if !tt.expectedSaveCalled && savePolicyCalled {
				t.Error("expected SavePolicy not to be called")
			}
		})
	}
}

func TestPolicyServiceImpl_RemovePolicy(t *testing.T) {
	tests := []struct {
		name             string
		role             string
		resource         string
		action           string
		setupMock        func(*mocks.MockCasbinEnforcer)
		expectedError    error
		expectedRemoved  bool
		expectedSaveCalled bool
	}{
		{
			name:     "successful policy removal",
			role:     "user",
			resource: "/api/profile",
			action:   "DELETE",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.RemovePolicyFunc = func(params ...interface{}) (bool, error) {
					if len(params) == 3 &&
						params[0].(string) == "user" &&
						params[1].(string) == "/api/profile" &&
						params[2].(string) == "DELETE" {
						return true, nil
					}
					return false, nil
				}
				enforcer.SavePolicyFunc = func() error {
					return nil
				}
			},
			expectedError:      nil,
			expectedRemoved:    true,
			expectedSaveCalled: true,
		},
		{
			name:     "policy does not exist",
			role:     "user",
			resource: "/api/nonexistent",
			action:   "GET",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.RemovePolicyFunc = func(params ...interface{}) (bool, error) {
					// Return false indicating policy doesn't exist
					return false, nil
				}
				enforcer.SavePolicyFunc = func() error {
					return nil
				}
			},
			expectedError:      nil,
			expectedRemoved:    false,
			expectedSaveCalled: true,
		},
		{
			name:     "remove policy fails",
			role:     "admin",
			resource: "/api/test",
			action:   "POST",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.RemovePolicyFunc = func(params ...interface{}) (bool, error) {
					return false, domain.ErrUnauthorized
				}
				enforcer.SavePolicyFunc = func() error {
					t.Error("SavePolicy should not be called when RemovePolicy fails")
					return nil
				}
			},
			expectedError:      domain.ErrUnauthorized,
			expectedRemoved:    false,
			expectedSaveCalled: false,
		},
		{
			name:     "save policy fails after removal",
			role:     "admin",
			resource: "/api/test",
			action:   "PUT",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.RemovePolicyFunc = func(params ...interface{}) (bool, error) {
					return true, nil
				}
				enforcer.SavePolicyFunc = func() error {
					return domain.ErrResourceNotFound
				}
			},
			expectedError:      domain.ErrResourceNotFound,
			expectedRemoved:    true,
			expectedSaveCalled: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create service and mock
			policyService, mockEnforcer := createPolicyServiceForTest(t)

			// Setup test-specific mock behavior
			tt.setupMock(mockEnforcer)

			// Track calls
			removePolicyCalled := false
			savePolicyCalled := false

			// Wrap functions to track calls
			originalRemovePolicy := mockEnforcer.RemovePolicyFunc
			mockEnforcer.RemovePolicyFunc = func(params ...interface{}) (bool, error) {
				removePolicyCalled = true
				if originalRemovePolicy != nil {
					return originalRemovePolicy(params...)
				}
				return false, nil
			}

			originalSavePolicy := mockEnforcer.SavePolicyFunc
			mockEnforcer.SavePolicyFunc = func() error {
				savePolicyCalled = true
				if originalSavePolicy != nil {
					return originalSavePolicy()
				}
				return nil
			}

			// Execute test
			err := policyService.RemovePolicy(tt.role, tt.resource, tt.action)

			// Validate error
			if tt.expectedError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.expectedError)
				}
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Validate function calls
			if !removePolicyCalled {
				t.Error("expected RemovePolicy to be called")
			}

			if tt.expectedSaveCalled && !savePolicyCalled {
				t.Error("expected SavePolicy to be called")
			}

			if !tt.expectedSaveCalled && savePolicyCalled {
				t.Error("expected SavePolicy not to be called")
			}
		})
	}
}

func TestPolicyServiceImpl_CheckPermission(t *testing.T) {
	tests := []struct {
		name               string
		role               string
		resource           string
		action             string
		setupMock          func(*mocks.MockCasbinEnforcer)
		expectedPermission bool
		expectedError      error
	}{
		{
			name:     "permission granted",
			role:     "admin",
			resource: "/api/admin",
			action:   "GET",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.EnforceFunc = func(rvals ...interface{}) (bool, error) {
					if len(rvals) == 3 &&
						rvals[0].(string) == "admin" &&
						rvals[1].(string) == "/api/admin" &&
						rvals[2].(string) == "GET" {
						return true, nil
					}
					return false, nil
				}
			},
			expectedPermission: true,
			expectedError:      nil,
		},
		{
			name:     "permission denied",
			role:     "user",
			resource: "/api/admin",
			action:   "DELETE",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.EnforceFunc = func(rvals ...interface{}) (bool, error) {
					// User doesn't have admin permissions
					return false, nil
				}
			},
			expectedPermission: false,
			expectedError:      nil,
		},
		{
			name:     "enforce error",
			role:     "user",
			resource: "/api/test",
			action:   "GET",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.EnforceFunc = func(rvals ...interface{}) (bool, error) {
					return false, domain.ErrUnauthorized
				}
			},
			expectedPermission: false,
			expectedError:      domain.ErrUnauthorized,
		},
		{
			name:     "user profile access",
			role:     "user",
			resource: "/api/profile",
			action:   "GET",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.EnforceFunc = func(rvals ...interface{}) (bool, error) {
					role := rvals[0].(string)
					resource := rvals[1].(string)
					action := rvals[2].(string)
					
					// Allow users to access their own profile
					if role == "user" && resource == "/api/profile" && action == "GET" {
						return true, nil
					}
					return false, nil
				}
			},
			expectedPermission: true,
			expectedError:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create service and mock
			policyService, mockEnforcer := createPolicyServiceForTest(t)

			// Setup test-specific mock behavior
			tt.setupMock(mockEnforcer)

			// Track calls
			enforceCalled := false

			// Wrap function to track calls
			originalEnforce := mockEnforcer.EnforceFunc
			mockEnforcer.EnforceFunc = func(rvals ...interface{}) (bool, error) {
				enforceCalled = true
				if originalEnforce != nil {
					return originalEnforce(rvals...)
				}
				return false, nil
			}

			// Execute test
			hasPermission, err := policyService.CheckPermission(tt.role, tt.resource, tt.action)

			// Validate result
			if hasPermission != tt.expectedPermission {
				t.Errorf("expected permission %t, got %t", tt.expectedPermission, hasPermission)
			}

			// Validate error
			if tt.expectedError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.expectedError)
				}
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Validate function calls
			if !enforceCalled {
				t.Error("expected Enforce to be called")
			}
		})
	}
}

func TestPolicyServiceImpl_GetPolicies(t *testing.T) {
	tests := []struct {
		name             string
		setupMock        func(*mocks.MockCasbinEnforcer)
		expectedPolicies [][]string
	}{
		{
			name: "get existing policies",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.GetPolicyFunc = func() ([][]string, error) {
					return [][]string{
						{"admin", "/api/admin/*", "GET|POST|PUT|DELETE"},
						{"user", "/api/profile", "GET|PUT"},
						{"user", "/api/logout", "POST"},
					}, nil
				}
			},
			expectedPolicies: [][]string{
				{"admin", "/api/admin/*", "GET|POST|PUT|DELETE"},
				{"user", "/api/profile", "GET|PUT"},
				{"user", "/api/logout", "POST"},
			},
		},
		{
			name: "no policies exist",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.GetPolicyFunc = func() ([][]string, error) {
					return [][]string{}, nil
				}
			},
			expectedPolicies: [][]string{},
		},
		{
			name: "single policy",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.GetPolicyFunc = func() ([][]string, error) {
					return [][]string{
						{"guest", "/api/public", "GET"},
					}, nil
				}
			},
			expectedPolicies: [][]string{
				{"guest", "/api/public", "GET"},
			},
		},
		{
			name: "get policy returns error (ignored)",
			setupMock: func(enforcer *mocks.MockCasbinEnforcer) {
				enforcer.GetPolicyFunc = func() ([][]string, error) {
					// PolicyService ignores the error in current implementation
					return [][]string{
						{"user", "/api/test", "GET"},
					}, domain.ErrUnauthorized
				}
			},
			expectedPolicies: [][]string{
				{"user", "/api/test", "GET"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create service and mock
			policyService, mockEnforcer := createPolicyServiceForTest(t)

			// Setup test-specific mock behavior
			tt.setupMock(mockEnforcer)

			// Track calls
			getPolicyCalled := false

			// Wrap function to track calls
			originalGetPolicy := mockEnforcer.GetPolicyFunc
			mockEnforcer.GetPolicyFunc = func() ([][]string, error) {
				getPolicyCalled = true
				if originalGetPolicy != nil {
					return originalGetPolicy()
				}
				return [][]string{}, nil
			}

			// Execute test
			policies := policyService.GetPolicies()

			// Validate result
			if len(policies) != len(tt.expectedPolicies) {
				t.Errorf("expected %d policies, got %d", len(tt.expectedPolicies), len(policies))
			}

			for i, expectedPolicy := range tt.expectedPolicies {
				if i >= len(policies) {
					t.Errorf("missing policy at index %d", i)
					continue
				}

				actualPolicy := policies[i]
				if len(actualPolicy) != len(expectedPolicy) {
					t.Errorf("policy %d: expected %d elements, got %d", i, len(expectedPolicy), len(actualPolicy))
					continue
				}

				for j, expectedElement := range expectedPolicy {
					if j >= len(actualPolicy) {
						t.Errorf("policy %d: missing element at index %d", i, j)
						continue
					}

					if actualPolicy[j] != expectedElement {
						t.Errorf("policy %d element %d: expected %s, got %s", i, j, expectedElement, actualPolicy[j])
					}
				}
			}

			// Validate function calls
			if !getPolicyCalled {
				t.Error("expected GetPolicy to be called")
			}
		})
	}
}

// Integration test for complete policy management flow
func TestPolicyServiceImpl_CompleteFlow(t *testing.T) {
	// Create service and mock
	policyService, mockEnforcer := createPolicyServiceForTest(t)

	// Setup comprehensive mock behavior
	policies := [][]string{}

	mockEnforcer.AddPolicyFunc = func(params ...interface{}) (bool, error) {
		policy := []string{
			params[0].(string),
			params[1].(string),
			params[2].(string),
		}
		policies = append(policies, policy)
		return true, nil
	}

	mockEnforcer.RemovePolicyFunc = func(params ...interface{}) (bool, error) {
		targetPolicy := []string{
			params[0].(string),
			params[1].(string),
			params[2].(string),
		}
		
		for i, policy := range policies {
			if len(policy) == 3 &&
				policy[0] == targetPolicy[0] &&
				policy[1] == targetPolicy[1] &&
				policy[2] == targetPolicy[2] {
				// Remove policy
				policies = append(policies[:i], policies[i+1:]...)
				return true, nil
			}
		}
		return false, nil
	}

	mockEnforcer.EnforceFunc = func(rvals ...interface{}) (bool, error) {
		role := rvals[0].(string)
		resource := rvals[1].(string)
		action := rvals[2].(string)

		for _, policy := range policies {
			if len(policy) == 3 &&
				policy[0] == role &&
				policy[1] == resource &&
				policy[2] == action {
				return true, nil
			}
		}
		return false, nil
	}

	mockEnforcer.GetPolicyFunc = func() ([][]string, error) {
		return policies, nil
	}

	mockEnforcer.SavePolicyFunc = func() error {
		return nil
	}

	// Test flow: Add -> Check -> List -> Remove -> Check -> List

	// Step 1: Add policy
	err := policyService.AddPolicy("user", "/api/profile", "GET")
	if err != nil {
		t.Fatalf("Failed to add policy: %v", err)
	}

	// Step 2: Check permission (should be granted)
	hasPermission, err := policyService.CheckPermission("user", "/api/profile", "GET")
	if err != nil {
		t.Fatalf("Failed to check permission: %v", err)
	}
	if !hasPermission {
		t.Error("Expected permission to be granted after adding policy")
	}

	// Step 3: List policies
	allPolicies := policyService.GetPolicies()
	if len(allPolicies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(allPolicies))
	}

	// Step 4: Add another policy
	err = policyService.AddPolicy("admin", "/api/admin", "POST")
	if err != nil {
		t.Fatalf("Failed to add second policy: %v", err)
	}

	// Step 5: Check both policies exist
	allPolicies = policyService.GetPolicies()
	if len(allPolicies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(allPolicies))
	}

	// Step 6: Remove first policy
	err = policyService.RemovePolicy("user", "/api/profile", "GET")
	if err != nil {
		t.Fatalf("Failed to remove policy: %v", err)
	}

	// Step 7: Check permission (should be denied)
	hasPermission, err = policyService.CheckPermission("user", "/api/profile", "GET")
	if err != nil {
		t.Fatalf("Failed to check permission after removal: %v", err)
	}
	if hasPermission {
		t.Error("Expected permission to be denied after removing policy")
	}

	// Step 8: Verify only one policy remains
	allPolicies = policyService.GetPolicies()
	if len(allPolicies) != 1 {
		t.Errorf("Expected 1 policy after removal, got %d", len(allPolicies))
	}

	// Step 9: Check second policy still works
	hasPermission, err = policyService.CheckPermission("admin", "/api/admin", "POST")
	if err != nil {
		t.Fatalf("Failed to check admin permission: %v", err)
	}
	if !hasPermission {
		t.Error("Expected admin permission to still be granted")
	}
}