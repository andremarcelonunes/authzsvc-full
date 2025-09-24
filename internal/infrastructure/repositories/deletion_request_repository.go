package repositories

import (
	"context"
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

// Compile-time interface compliance check
var _ domain.DeletionRequestRepository = (*DeletionRequestRepository)(nil)