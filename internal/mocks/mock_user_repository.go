package mocks

import (
	"context"

	"github.com/you/authzsvc/domain"
)

// MockUserRepository implements domain.UserRepository interface for testing
type MockUserRepository struct {
	CreateFunc         func(ctx context.Context, user *domain.User) error
	FindByEmailFunc    func(ctx context.Context, email string) (*domain.User, error)
	FindByPhoneFunc    func(ctx context.Context, phone string) (*domain.User, error)
	FindByIDFunc       func(ctx context.Context, id uint) (*domain.User, error)
	FindByIdentifierFunc func(ctx context.Context, identifier string, identifierType domain.IdentifierType) (*domain.User, error) // CB-194
	UpdateFunc         func(ctx context.Context, user *domain.User) error
	ActivatePhoneFunc  func(ctx context.Context, userID uint) error
}

// NewMockUserRepository creates a new MockUserRepository with default behaviors
func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{}
}

// Create creates a new user
func (m *MockUserRepository) Create(ctx context.Context, user *domain.User) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, user)
	}
	// Default behavior: success
	return nil
}

// FindByEmail finds a user by email
func (m *MockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	if m.FindByEmailFunc != nil {
		return m.FindByEmailFunc(ctx, email)
	}
	// Default behavior: not found
	return nil, domain.ErrUserNotFound
}

// FindByPhone finds a user by phone number
func (m *MockUserRepository) FindByPhone(ctx context.Context, phone string) (*domain.User, error) {
	if m.FindByPhoneFunc != nil {
		return m.FindByPhoneFunc(ctx, phone)
	}
	// Default behavior: not found
	return nil, domain.ErrUserNotFound
}

// FindByID finds a user by ID
func (m *MockUserRepository) FindByID(ctx context.Context, id uint) (*domain.User, error) {
	if m.FindByIDFunc != nil {
		return m.FindByIDFunc(ctx, id)
	}
	// Default behavior: not found
	return nil, domain.ErrUserNotFound
}

// FindByIdentifier finds a user by identifier (email or phone) - CB-194
func (m *MockUserRepository) FindByIdentifier(ctx context.Context, identifier string, identifierType domain.IdentifierType) (*domain.User, error) {
	if m.FindByIdentifierFunc != nil {
		return m.FindByIdentifierFunc(ctx, identifier, identifierType)
	}
	
	// Default behavior: delegate to appropriate method
	switch identifierType {
	case domain.IdentifierTypeEmail:
		return m.FindByEmail(ctx, identifier)
	case domain.IdentifierTypePhone:
		return m.FindByPhone(ctx, identifier)
	default:
		return nil, domain.ErrIdentifierTypeUnknown
	}
}

// Update updates an existing user
func (m *MockUserRepository) Update(ctx context.Context, user *domain.User) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, user)
	}
	// Default behavior: success
	return nil
}

// ActivatePhone activates user's phone verification
func (m *MockUserRepository) ActivatePhone(ctx context.Context, userID uint) error {
	if m.ActivatePhoneFunc != nil {
		return m.ActivatePhoneFunc(ctx, userID)
	}
	// Default behavior: success
	return nil
}

// Compile-time interface compliance verification
var _ domain.UserRepository = (*MockUserRepository)(nil)