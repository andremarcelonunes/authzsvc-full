package repositories

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
	"gorm.io/gorm"
)

// UserRepositoryImpl implements domain.UserRepository using GORM
type UserRepositoryImpl struct {
	db *gorm.DB
}

// DBUser represents the database model for User (with GORM tags)
type DBUser struct {
	ID            uint           `gorm:"primaryKey"`
	Email         string         `gorm:"uniqueIndex;size:255"`
	Phone         string         `gorm:"index;size:32"`
	PasswordHash  string         `gorm:"column:password"`
	Role          string         `gorm:"index;size:64"`
	IsActive      bool           `gorm:"index"`
	PhoneVerified bool           `gorm:"index"`
	CreatedAt     time.Time `gorm:"index"`
	UpdatedAt     time.Time `gorm:"index"`
	DeletedAt     gorm.DeletedAt `gorm:"index"`
}

// TableName returns the table name for GORM
func (DBUser) TableName() string {
	return "users"
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB) domain.UserRepository {
	return &UserRepositoryImpl{db: db}
}

// Create implements domain.UserRepository
func (r *UserRepositoryImpl) Create(ctx context.Context, user *domain.User) error {
	dbUser := r.domainToDB(user)
	if err := r.db.WithContext(ctx).Create(dbUser).Error; err != nil {
		return err
	}
	user.ID = dbUser.ID
	return nil
}

// FindByEmail implements domain.UserRepository
func (r *UserRepositoryImpl) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	var dbUser DBUser
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&dbUser).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return r.dbToDomain(&dbUser), nil
}

// FindByPhone implements domain.UserRepository
func (r *UserRepositoryImpl) FindByPhone(ctx context.Context, phone string) (*domain.User, error) {
	var dbUser DBUser
	err := r.db.WithContext(ctx).Where("phone = ?", phone).First(&dbUser).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return r.dbToDomain(&dbUser), nil
}

// FindByID implements domain.UserRepository
func (r *UserRepositoryImpl) FindByID(ctx context.Context, id uint) (*domain.User, error) {
	var dbUser DBUser
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&dbUser).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, domain.ErrUserNotFound
		}
		return nil, err
	}
	return r.dbToDomain(&dbUser), nil
}

// Update implements domain.UserRepository
func (r *UserRepositoryImpl) Update(ctx context.Context, user *domain.User) error {
	dbUser := r.domainToDB(user)
	return r.db.WithContext(ctx).Save(dbUser).Error
}

// ActivatePhone implements domain.UserRepository
func (r *UserRepositoryImpl) ActivatePhone(ctx context.Context, userID uint) error {
	return r.db.WithContext(ctx).Model(&DBUser{}).Where("id = ?", userID).Update("phone_verified", true).Error
}

// domainToDB converts domain user to database user
func (r *UserRepositoryImpl) domainToDB(user *domain.User) *DBUser {
	return &DBUser{
		ID:            user.ID,
		Email:         user.Email,
		Phone:         user.Phone,
		PasswordHash:  user.PasswordHash,
		Role:          user.Role,
		IsActive:      user.IsActive,
		PhoneVerified: user.PhoneVerified,
	}
}

// dbToDomain converts database user to domain user
func (r *UserRepositoryImpl) dbToDomain(dbUser *DBUser) *domain.User {
	return &domain.User{
		ID:            dbUser.ID,
		Email:         dbUser.Email,
		Phone:         dbUser.Phone,
		PasswordHash:  dbUser.PasswordHash,
		Role:          dbUser.Role,
		IsActive:      dbUser.IsActive,
		PhoneVerified: dbUser.PhoneVerified,
		CreatedAt:     dbUser.CreatedAt,
		UpdatedAt:     dbUser.UpdatedAt,
	}
}