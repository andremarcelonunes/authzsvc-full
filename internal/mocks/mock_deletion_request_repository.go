package mocks

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
)

// MockDeletionRequestRepository implements domain.DeletionRequestRepository interface for testing
type MockDeletionRequestRepository struct {
	CreateFunc       func(ctx context.Context, request *domain.DeletionRequest) error
	FindByIDFunc     func(ctx context.Context, id uuid.UUID) (*domain.DeletionRequest, error)
	FindByUserIDFunc func(ctx context.Context, userID uint) ([]*domain.DeletionRequest, error)
	UpdateFunc       func(ctx context.Context, request *domain.DeletionRequest) error
	ListPendingFunc  func(ctx context.Context, limit int) ([]*domain.DeletionRequest, error)
	ListScheduledFunc func(ctx context.Context, beforeTime time.Time) ([]*domain.DeletionRequest, error)
	SearchFunc       func(ctx context.Context, criteria domain.DeletionSearchCriteria) ([]*domain.DeletionRequest, error)
	
	// Export methods
	CreateExportFunc    func(ctx context.Context, export *domain.UserDataExport) error
	GetExportByIDFunc   func(ctx context.Context, id string) (*domain.UserDataExport, error)
	SearchExportsFunc   func(ctx context.Context, criteria domain.ExportSearchCriteria) ([]*domain.UserDataExport, error)
	UpdateExportFunc    func(ctx context.Context, export *domain.UserDataExport) error
}

// NewMockDeletionRequestRepository creates a new MockDeletionRequestRepository with default behaviors
func NewMockDeletionRequestRepository() *MockDeletionRequestRepository {
	return &MockDeletionRequestRepository{}
}

// Create creates a new deletion request
func (m *MockDeletionRequestRepository) Create(ctx context.Context, request *domain.DeletionRequest) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, request)
	}
	// Default behavior: set ID and return success
	if request.ID == uuid.Nil {
		request.ID = uuid.New()
	}
	return nil
}

// FindByID finds a deletion request by ID
func (m *MockDeletionRequestRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.DeletionRequest, error) {
	if m.FindByIDFunc != nil {
		return m.FindByIDFunc(ctx, id)
	}
	return nil, domain.ErrNotFound // Default: not found
}

// FindByUserID finds all deletion requests for a user
func (m *MockDeletionRequestRepository) FindByUserID(ctx context.Context, userID uint) ([]*domain.DeletionRequest, error) {
	if m.FindByUserIDFunc != nil {
		return m.FindByUserIDFunc(ctx, userID)
	}
	return []*domain.DeletionRequest{}, nil // Default: empty list
}

// Update updates an existing deletion request
func (m *MockDeletionRequestRepository) Update(ctx context.Context, request *domain.DeletionRequest) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, request)
	}
	return nil // Default: success
}

// ListPending lists pending deletion requests
func (m *MockDeletionRequestRepository) ListPending(ctx context.Context, limit int) ([]*domain.DeletionRequest, error) {
	if m.ListPendingFunc != nil {
		return m.ListPendingFunc(ctx, limit)
	}
	return []*domain.DeletionRequest{}, nil // Default: empty list
}

// ListScheduled lists scheduled deletion requests before a time
func (m *MockDeletionRequestRepository) ListScheduled(ctx context.Context, beforeTime time.Time) ([]*domain.DeletionRequest, error) {
	if m.ListScheduledFunc != nil {
		return m.ListScheduledFunc(ctx, beforeTime)
	}
	return []*domain.DeletionRequest{}, nil // Default: empty list
}

// Search searches deletion requests by criteria
func (m *MockDeletionRequestRepository) Search(ctx context.Context, criteria domain.DeletionSearchCriteria) ([]*domain.DeletionRequest, error) {
	if m.SearchFunc != nil {
		return m.SearchFunc(ctx, criteria)
	}
	return []*domain.DeletionRequest{}, nil
}

// CreateExport creates a new data export record
func (m *MockDeletionRequestRepository) CreateExport(ctx context.Context, export *domain.UserDataExport) error {
	if m.CreateExportFunc != nil {
		return m.CreateExportFunc(ctx, export)
	}
	return nil
}

// GetExportByID retrieves an export by ID
func (m *MockDeletionRequestRepository) GetExportByID(ctx context.Context, id string) (*domain.UserDataExport, error) {
	if m.GetExportByIDFunc != nil {
		return m.GetExportByIDFunc(ctx, id)
	}
	return nil, fmt.Errorf("export not found")
}

// SearchExports searches exports by criteria
func (m *MockDeletionRequestRepository) SearchExports(ctx context.Context, criteria domain.ExportSearchCriteria) ([]*domain.UserDataExport, error) {
	if m.SearchExportsFunc != nil {
		return m.SearchExportsFunc(ctx, criteria)
	}
	return []*domain.UserDataExport{}, nil
}

// UpdateExport updates an export record
func (m *MockDeletionRequestRepository) UpdateExport(ctx context.Context, export *domain.UserDataExport) error {
	if m.UpdateExportFunc != nil {
		return m.UpdateExportFunc(ctx, export)
	}
	return nil
}

// Compile-time interface compliance check
var _ domain.DeletionRequestRepository = (*MockDeletionRequestRepository)(nil)