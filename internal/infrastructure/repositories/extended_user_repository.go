package repositories

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
	"gorm.io/gorm"
)

// ExtendedUserRepository extends the basic UserRepository with deletion capabilities
type ExtendedUserRepository struct {
	*UserRepositoryImpl // Embed the existing UserRepositoryImpl
	db                  *gorm.DB
}

// NewExtendedUserRepository creates a new extended user repository
func NewExtendedUserRepository(db *gorm.DB) *ExtendedUserRepository {
	userRepo := NewUserRepository(db).(*UserRepositoryImpl)
	return &ExtendedUserRepository{
		UserRepositoryImpl: userRepo,
		db:                 db,
	}
}

// SoftDelete marks a user as deleted (sets DeletedAt timestamp)
func (r *ExtendedUserRepository) SoftDelete(ctx context.Context, userID uint) error {
	now := time.Now()
	result := r.db.WithContext(ctx).
		Model(&domain.User{}).
		Where("id = ?", userID).
		Update("deleted_at", now)
	
	if result.Error != nil {
		return result.Error
	}
	
	if result.RowsAffected == 0 {
		return domain.ErrUserNotFound
	}
	
	return nil
}

// HardDelete permanently removes a user from the database
func (r *ExtendedUserRepository) HardDelete(ctx context.Context, userID uint) error {
	result := r.db.WithContext(ctx).
		Unscoped(). // Bypass soft delete to perform hard delete
		Delete(&domain.User{}, userID)
	
	if result.Error != nil {
		return result.Error
	}
	
	if result.RowsAffected == 0 {
		return domain.ErrUserNotFound
	}
	
	return nil
}

// Anonymize replaces user data with anonymous data
func (r *ExtendedUserRepository) Anonymize(ctx context.Context, userID uint, anonymousData *domain.AnonymizedUser) error {
	// Update user record with anonymous data
	result := r.db.WithContext(ctx).
		Model(&domain.User{}).
		Where("id = ?", userID).
		Updates(map[string]any{
			"email":      anonymousData.Email,
			"phone":      anonymousData.Phone,
			"deleted_at": anonymousData.AnonymizedAt,
		})
	
	if result.Error != nil {
		return result.Error
	}
	
	if result.RowsAffected == 0 {
		return domain.ErrUserNotFound
	}
	
	// In a full implementation, you would also create an entry in the anonymized_users table
	// For now, we'll just update the existing user record
	
	return nil
}

// Deactivate sets is_active to false for a user
func (r *ExtendedUserRepository) Deactivate(ctx context.Context, userID uint, reason string) error {
	result := r.db.WithContext(ctx).
		Model(&domain.User{}).
		Where("id = ?", userID).
		Update("is_active", false)
	
	if result.Error != nil {
		return result.Error
	}
	
	if result.RowsAffected == 0 {
		return domain.ErrUserNotFound
	}
	
	return nil
}

// Reactivate sets is_active to true and clears DeletedAt for a user
func (r *ExtendedUserRepository) Reactivate(ctx context.Context, userID uint) error {
	result := r.db.WithContext(ctx).
		Model(&domain.User{}).
		Where("id = ?", userID).
		Updates(map[string]any{
			"is_active":  true,
			"deleted_at": nil,
		})
	
	if result.Error != nil {
		return result.Error
	}
	
	if result.RowsAffected == 0 {
		return domain.ErrUserNotFound
	}
	
	return nil
}

// IsDeleted checks if a user has been soft deleted
func (r *ExtendedUserRepository) IsDeleted(ctx context.Context, userID uint) (bool, error) {
	var user domain.User
	err := r.db.WithContext(ctx).
		Unscoped(). // Include soft-deleted records
		Select("deleted_at").
		Where("id = ?", userID).
		First(&user).Error
	
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return false, domain.ErrUserNotFound
		}
		return false, err
	}
	
	return user.DeletedAt != nil, nil
}

// FindUsersForDeletion finds users that are scheduled for deletion before a certain date
func (r *ExtendedUserRepository) FindUsersForDeletion(ctx context.Context, beforeDate time.Time) ([]*domain.User, error) {
	var users []*domain.User
	
	// Find users that are soft-deleted and have been deleted before the specified date
	err := r.db.WithContext(ctx).
		Unscoped(). // Include soft-deleted records
		Where("deleted_at IS NOT NULL AND deleted_at < ?", beforeDate).
		Find(&users).Error
	
	return users, err
}

// Compile-time interface compliance check
var _ domain.ExtendedUserRepository = (*ExtendedUserRepository)(nil)