package repositories

import (
	"context"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
	"gorm.io/gorm"
)

// DeletionAuditRepository implements domain.DeletionAuditRepository
type DeletionAuditRepository struct {
	db *gorm.DB
}

// NewDeletionAuditRepository creates a new deletion audit repository
func NewDeletionAuditRepository(db *gorm.DB) *DeletionAuditRepository {
	return &DeletionAuditRepository{db: db}
}

// Create saves a new deletion audit log entry
func (r *DeletionAuditRepository) Create(ctx context.Context, log *domain.DeletionAuditLog) error {
	return r.db.WithContext(ctx).Create(log).Error
}

// FindByRequestID finds all audit logs for a deletion request
func (r *DeletionAuditRepository) FindByRequestID(ctx context.Context, requestID uuid.UUID) ([]*domain.DeletionAuditLog, error) {
	var logs []*domain.DeletionAuditLog
	err := r.db.WithContext(ctx).
		Where("request_id = ?", requestID).
		Order("performed_at DESC").
		Find(&logs).Error
	return logs, err
}

// FindByUserID finds all audit logs for a user's deletion activities
func (r *DeletionAuditRepository) FindByUserID(ctx context.Context, userID uint) ([]*domain.DeletionAuditLog, error) {
	var logs []*domain.DeletionAuditLog
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("performed_at DESC").
		Find(&logs).Error
	return logs, err
}

// Note: Audit logs should never be deleted, only archived according to LGPD requirements

// Compile-time interface compliance check
var _ domain.DeletionAuditRepository = (*DeletionAuditRepository)(nil)