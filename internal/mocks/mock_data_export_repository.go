package mocks

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
)

// MockDataExportRepository implements domain.DataExportRepository interface for testing
type MockDataExportRepository struct {
	CreateFunc          func(ctx context.Context, export *domain.UserDataExport) error
	FindByIDFunc        func(ctx context.Context, id uuid.UUID) (*domain.UserDataExport, error)
	FindByUserIDFunc    func(ctx context.Context, userID uint) ([]*domain.UserDataExport, error)
	UpdateFunc          func(ctx context.Context, export *domain.UserDataExport) error
	DeleteExpiredFunc   func(ctx context.Context, beforeTime time.Time) error
}

// NewMockDataExportRepository creates a new MockDataExportRepository with default behaviors
func NewMockDataExportRepository() *MockDataExportRepository {
	return &MockDataExportRepository{}
}

// Create creates a new data export record
func (m *MockDataExportRepository) Create(ctx context.Context, export *domain.UserDataExport) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, export)
	}
	// Default behavior: set ID and return success
	if export.ExportID == uuid.Nil {
		export.ExportID = uuid.New()
	}
	return nil
}

// FindByID finds a data export by ID
func (m *MockDataExportRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.UserDataExport, error) {
	if m.FindByIDFunc != nil {
		return m.FindByIDFunc(ctx, id)
	}
	return nil, domain.ErrNotFound // Default: not found
}

// FindByUserID finds all data exports for a user
func (m *MockDataExportRepository) FindByUserID(ctx context.Context, userID uint) ([]*domain.UserDataExport, error) {
	if m.FindByUserIDFunc != nil {
		return m.FindByUserIDFunc(ctx, userID)
	}
	return []*domain.UserDataExport{}, nil // Default: empty list
}

// Update updates an existing data export record
func (m *MockDataExportRepository) Update(ctx context.Context, export *domain.UserDataExport) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, export)
	}
	return nil // Default: success
}

// DeleteExpired deletes expired export records
func (m *MockDataExportRepository) DeleteExpired(ctx context.Context, beforeTime time.Time) error {
	if m.DeleteExpiredFunc != nil {
		return m.DeleteExpiredFunc(ctx, beforeTime)
	}
	return nil // Default: success
}

// Compile-time interface compliance check
var _ domain.DataExportRepository = (*MockDataExportRepository)(nil)