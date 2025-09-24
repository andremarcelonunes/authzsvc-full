package repositories

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
	"gorm.io/gorm"
)

// DeletionRequestRepository implements domain.DeletionRequestRepository
type DeletionRequestRepository struct {
	db *gorm.DB
}

// NewDeletionRequestRepository creates a new deletion request repository
func NewDeletionRequestRepository(db *gorm.DB) *DeletionRequestRepository {
	return &DeletionRequestRepository{db: db}
}

// Create saves a new deletion request
func (r *DeletionRequestRepository) Create(ctx context.Context, request *domain.DeletionRequest) error {
	return r.db.WithContext(ctx).Create(request).Error
}

// FindByID finds a deletion request by ID
func (r *DeletionRequestRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.DeletionRequest, error) {
	var request domain.DeletionRequest
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&request).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return &request, nil
}

// FindByUserID finds all deletion requests for a user
func (r *DeletionRequestRepository) FindByUserID(ctx context.Context, userID uint) ([]*domain.DeletionRequest, error) {
	var requests []*domain.DeletionRequest
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Find(&requests).Error
	return requests, err
}

// Update updates a deletion request
func (r *DeletionRequestRepository) Update(ctx context.Context, request *domain.DeletionRequest) error {
	return r.db.WithContext(ctx).Save(request).Error
}

// ListPending finds pending deletion requests
func (r *DeletionRequestRepository) ListPending(ctx context.Context, limit int) ([]*domain.DeletionRequest, error) {
	var requests []*domain.DeletionRequest
	err := r.db.WithContext(ctx).
		Where("status IN ?", []domain.DeletionRequestStatus{
			domain.DeletionStatusPending,
			domain.DeletionStatusScheduled,
		}).
		Order("created_at ASC").
		Limit(limit).
		Find(&requests).Error
	return requests, err
}

// ListScheduled finds deletion requests scheduled before a certain time
func (r *DeletionRequestRepository) ListScheduled(ctx context.Context, beforeTime time.Time) ([]*domain.DeletionRequest, error) {
	var requests []*domain.DeletionRequest
	err := r.db.WithContext(ctx).
		Where("status = ? AND scheduled_for <= ?", domain.DeletionStatusScheduled, beforeTime).
		Order("scheduled_for ASC").
		Find(&requests).Error
	return requests, err
}

// Search searches deletion requests by criteria
func (r *DeletionRequestRepository) Search(ctx context.Context, criteria domain.DeletionSearchCriteria) ([]*domain.DeletionRequest, error) {
	var requests []*domain.DeletionRequest
	query := r.db.WithContext(ctx)
	
	if criteria.UserID != nil {
		query = query.Where("user_id = ?", *criteria.UserID)
	}
	if criteria.Status != "" {
		query = query.Where("status = ?", criteria.Status)
	}
	if criteria.ScheduledBefore != nil {
		query = query.Where("scheduled_for <= ?", *criteria.ScheduledBefore)
	}
	if criteria.CreatedAfter != nil {
		query = query.Where("created_at >= ?", *criteria.CreatedAfter)
	}
	
	if criteria.Limit > 0 {
		query = query.Limit(criteria.Limit)
	}
	if criteria.Offset > 0 {
		query = query.Offset(criteria.Offset)
	}
	
	err := query.Find(&requests).Error
	return requests, err
}

// Export methods

// CreateExport creates a new data export record
func (r *DeletionRequestRepository) CreateExport(ctx context.Context, export *domain.UserDataExport) error {
	return r.db.WithContext(ctx).Create(export).Error
}

// GetExportByID retrieves an export by ID
func (r *DeletionRequestRepository) GetExportByID(ctx context.Context, id string) (*domain.UserDataExport, error) {
	exportUUID, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid export ID: %w", err)
	}
	
	var export domain.UserDataExport
	err = r.db.WithContext(ctx).Where("export_id = ?", exportUUID).First(&export).Error
	if err != nil {
		return nil, err
	}
	return &export, nil
}

// SearchExports searches exports by criteria
func (r *DeletionRequestRepository) SearchExports(ctx context.Context, criteria domain.ExportSearchCriteria) ([]*domain.UserDataExport, error) {
	var exports []*domain.UserDataExport
	query := r.db.WithContext(ctx)
	
	if criteria.UserID != nil {
		query = query.Where("user_id = ?", *criteria.UserID)
	}
	if criteria.ExpiredBefore != nil {
		query = query.Where("expires_at <= ?", *criteria.ExpiredBefore)
	}
	if criteria.CreatedAfter != nil {
		query = query.Where("created_at >= ?", *criteria.CreatedAfter)
	}
	
	if criteria.Limit > 0 {
		query = query.Limit(criteria.Limit)
	}
	if criteria.Offset > 0 {
		query = query.Offset(criteria.Offset)
	}
	
	err := query.Find(&exports).Error
	return exports, err
}

// UpdateExport updates an export record
func (r *DeletionRequestRepository) UpdateExport(ctx context.Context, export *domain.UserDataExport) error {
	return r.db.WithContext(ctx).Save(export).Error
}

// Compile-time interface compliance check
var _ domain.DeletionRequestRepository = (*DeletionRequestRepository)(nil)