package mocks

import (
	"context"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
)

// MockDeletionAuditRepository implements domain.DeletionAuditRepository interface for testing
type MockDeletionAuditRepository struct {
	CreateFunc           func(ctx context.Context, log *domain.DeletionAuditLog) error
	FindByRequestIDFunc  func(ctx context.Context, requestID uuid.UUID) ([]*domain.DeletionAuditLog, error)
	FindByUserIDFunc     func(ctx context.Context, userID uint) ([]*domain.DeletionAuditLog, error)
}

// NewMockDeletionAuditRepository creates a new MockDeletionAuditRepository with default behaviors
func NewMockDeletionAuditRepository() *MockDeletionAuditRepository {
	return &MockDeletionAuditRepository{}
}

// Create creates a new deletion audit log
func (m *MockDeletionAuditRepository) Create(ctx context.Context, log *domain.DeletionAuditLog) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, log)
	}
	// Default behavior: set ID and return success
	if log.ID == uuid.Nil {
		log.ID = uuid.New()
	}
	return nil
}

// FindByRequestID finds audit logs for a deletion request
func (m *MockDeletionAuditRepository) FindByRequestID(ctx context.Context, requestID uuid.UUID) ([]*domain.DeletionAuditLog, error) {
	if m.FindByRequestIDFunc != nil {
		return m.FindByRequestIDFunc(ctx, requestID)
	}
	return []*domain.DeletionAuditLog{}, nil // Default: empty list
}

// FindByUserID finds audit logs for a user
func (m *MockDeletionAuditRepository) FindByUserID(ctx context.Context, userID uint) ([]*domain.DeletionAuditLog, error) {
	if m.FindByUserIDFunc != nil {
		return m.FindByUserIDFunc(ctx, userID)
	}
	return []*domain.DeletionAuditLog{}, nil // Default: empty list
}

// Compile-time interface compliance check
var _ domain.DeletionAuditRepository = (*MockDeletionAuditRepository)(nil)