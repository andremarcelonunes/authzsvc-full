package mocks

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
)

// MockExtendedUserRepository implements domain.ExtendedUserRepository interface for testing
type MockExtendedUserRepository struct {
	*MockUserRepository // Embed existing user repository mock
	
	// Extended deletion methods
	SoftDeleteFunc             func(ctx context.Context, userID uint) error
	HardDeleteFunc             func(ctx context.Context, userID uint) error
	AnonymizeFunc              func(ctx context.Context, userID uint, anonymousData *domain.AnonymizedUser) error
	DeactivateFunc             func(ctx context.Context, userID uint, reason string) error
	ReactivateFunc             func(ctx context.Context, userID uint) error
	IsDeletedFunc              func(ctx context.Context, userID uint) (bool, error)
	FindUsersForDeletionFunc   func(ctx context.Context, beforeDate time.Time) ([]*domain.User, error)
}

// NewMockExtendedUserRepository creates a new MockExtendedUserRepository with default behaviors
func NewMockExtendedUserRepository() *MockExtendedUserRepository {
	return &MockExtendedUserRepository{
		MockUserRepository: NewMockUserRepository(),
	}
}

// SoftDelete marks a user as deleted (sets DeletedAt timestamp)
func (m *MockExtendedUserRepository) SoftDelete(ctx context.Context, userID uint) error {
	if m.SoftDeleteFunc != nil {
		return m.SoftDeleteFunc(ctx, userID)
	}
	return nil // Default: success
}

// HardDelete permanently removes a user from the database
func (m *MockExtendedUserRepository) HardDelete(ctx context.Context, userID uint) error {
	if m.HardDeleteFunc != nil {
		return m.HardDeleteFunc(ctx, userID)
	}
	return nil // Default: success
}

// Anonymize replaces user data with anonymous data
func (m *MockExtendedUserRepository) Anonymize(ctx context.Context, userID uint, anonymousData *domain.AnonymizedUser) error {
	if m.AnonymizeFunc != nil {
		return m.AnonymizeFunc(ctx, userID, anonymousData)
	}
	return nil // Default: success
}

// Deactivate sets is_active to false for a user
func (m *MockExtendedUserRepository) Deactivate(ctx context.Context, userID uint, reason string) error {
	if m.DeactivateFunc != nil {
		return m.DeactivateFunc(ctx, userID, reason)
	}
	return nil // Default: success
}

// Reactivate sets is_active to true and clears DeletedAt for a user
func (m *MockExtendedUserRepository) Reactivate(ctx context.Context, userID uint) error {
	if m.ReactivateFunc != nil {
		return m.ReactivateFunc(ctx, userID)
	}
	return nil // Default: success
}

// IsDeleted checks if a user has been soft deleted
func (m *MockExtendedUserRepository) IsDeleted(ctx context.Context, userID uint) (bool, error) {
	if m.IsDeletedFunc != nil {
		return m.IsDeletedFunc(ctx, userID)
	}
	return false, nil // Default: not deleted
}

// FindUsersForDeletion finds users that are scheduled for deletion before a certain date
func (m *MockExtendedUserRepository) FindUsersForDeletion(ctx context.Context, beforeDate time.Time) ([]*domain.User, error) {
	if m.FindUsersForDeletionFunc != nil {
		return m.FindUsersForDeletionFunc(ctx, beforeDate)
	}
	return []*domain.User{}, nil // Default: no users found
}

// Compile-time interface compliance check
var _ domain.ExtendedUserRepository = (*MockExtendedUserRepository)(nil)