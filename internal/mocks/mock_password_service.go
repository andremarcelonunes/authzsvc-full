package mocks

import "github.com/you/authzsvc/domain"

// MockPasswordService implements domain.PasswordService interface for testing
type MockPasswordService struct {
	HashFunc   func(password string) (string, error)
	VerifyFunc func(hashedPassword, password string) bool
}

// NewMockPasswordService creates a new MockPasswordService with default behaviors
func NewMockPasswordService() *MockPasswordService {
	return &MockPasswordService{}
}

// Hash generates a hash for the given password
func (m *MockPasswordService) Hash(password string) (string, error) {
	if m.HashFunc != nil {
		return m.HashFunc(password)
	}
	// Default behavior: return simple hash (for testing only)
	return "hashed_" + password, nil
}

// Verify verifies a password against its hash
func (m *MockPasswordService) Verify(hashedPassword, password string) bool {
	if m.VerifyFunc != nil {
		return m.VerifyFunc(hashedPassword, password)
	}
	// Default behavior: simple check for testing
	return hashedPassword == "hashed_"+password
}

// Compile-time interface compliance verification
var _ domain.PasswordService = (*MockPasswordService)(nil)