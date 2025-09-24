package repositories

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
	"gorm.io/gorm"
)

// DataExportRepository implements domain.DataExportRepository
type DataExportRepository struct {
	db *gorm.DB
}

// NewDataExportRepository creates a new data export repository
func NewDataExportRepository(db *gorm.DB) *DataExportRepository {
	return &DataExportRepository{db: db}
}

// Create saves a new data export record
func (r *DataExportRepository) Create(ctx context.Context, export *domain.UserDataExport) error {
	return r.db.WithContext(ctx).Create(export).Error
}

// FindByID finds a data export by ID
func (r *DataExportRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.UserDataExport, error) {
	var export domain.UserDataExport
	err := r.db.WithContext(ctx).Where("export_id = ?", id).First(&export).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	return &export, nil
}

// FindByUserID finds all data exports for a user
func (r *DataExportRepository) FindByUserID(ctx context.Context, userID uint) ([]*domain.UserDataExport, error) {
	var exports []*domain.UserDataExport
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("requested_at DESC").
		Find(&exports).Error
	return exports, err
}

// Update updates a data export record
func (r *DataExportRepository) Update(ctx context.Context, export *domain.UserDataExport) error {
	return r.db.WithContext(ctx).Save(export).Error
}

// DeleteExpired removes expired data exports
func (r *DataExportRepository) DeleteExpired(ctx context.Context, beforeTime time.Time) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ?", beforeTime).
		Delete(&domain.UserDataExport{}).Error
}

// Compile-time interface compliance check
var _ domain.DataExportRepository = (*DataExportRepository)(nil)