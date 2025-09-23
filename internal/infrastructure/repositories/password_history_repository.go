package repositories

import (
	"context"
	"time"

	"gorm.io/gorm"
)

// DBPasswordHistory represents the database model for password history
type DBPasswordHistory struct {
	ID           uint      `gorm:"primaryKey;autoIncrement" json:"id"`
	UserID       uint      `gorm:"not null;index" json:"user_id"`
	PasswordHash string    `gorm:"type:varchar(255);not null" json:"password_hash"`
	CreatedAt    time.Time `gorm:"autoCreateTime;index" json:"created_at"`
}

// TableName specifies the table name for GORM
func (DBPasswordHistory) TableName() string {
	return "auth.password_history"
}


// PasswordHistoryRepository handles password history data operations
type PasswordHistoryRepository struct {
	db *gorm.DB
}

// NewPasswordHistoryRepository creates a new password history repository
func NewPasswordHistoryRepository(db *gorm.DB) *PasswordHistoryRepository {
	return &PasswordHistoryRepository{db: db}
}

// Add adds a password to the user's history
func (r *PasswordHistoryRepository) Add(ctx context.Context, userID uint, passwordHash string, source string) error {
	history := &DBPasswordHistory{
		UserID:       userID,
		PasswordHash: passwordHash,
	}
	return r.db.WithContext(ctx).Create(history).Error
}

// GetRecentPasswords gets recent password hashes for a user (for reuse prevention)
func (r *PasswordHistoryRepository) GetRecentPasswords(ctx context.Context, userID uint, count int) ([]string, error) {
	var histories []DBPasswordHistory
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(count).
		Find(&histories).Error
	if err != nil {
		return nil, err
	}

	hashes := make([]string, len(histories))
	for i, history := range histories {
		hashes[i] = history.PasswordHash
	}
	return hashes, nil
}

// CleanupOldHistory removes old password history entries (keep only recent N entries)
func (r *PasswordHistoryRepository) CleanupOldHistory(ctx context.Context, userID uint, keepCount int) error {
	// Get IDs of entries to keep
	var keepIDs []uint
	err := r.db.WithContext(ctx).
		Model(&DBPasswordHistory{}).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(keepCount).
		Pluck("id", &keepIDs).Error
	if err != nil {
		return err
	}

	if len(keepIDs) == 0 {
		return nil // No history to clean up
	}

	// Delete entries not in the keep list
	return r.db.WithContext(ctx).
		Where("user_id = ? AND id NOT IN (?)", userID, keepIDs).
		Delete(&DBPasswordHistory{}).Error
}

// CountUserHistory counts password history entries for a user
func (r *PasswordHistoryRepository) CountUserHistory(ctx context.Context, userID uint) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&DBPasswordHistory{}).
		Where("user_id = ?", userID).
		Count(&count).Error
	return count, err
}

