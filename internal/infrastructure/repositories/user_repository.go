package repositories

import (
	"context"
	"reflect"
	"time"

	"github.com/you/authzsvc/domain"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

// nullIfEmptySerializer is the gorm serializer behind the tag `serializer:nullifempty`: the Go
// value stays a plain string, but an empty string is written as SQL NULL and NULL is read back as
// "". It is what lets many users without e-mail coexist under the unique index on e-mail
// (a unique index on "" would allow only one, while NULLs never collide).
type nullIfEmptySerializer struct{}

// Scan implements schema.SerializerInterface: NULL (or an empty value) becomes "".
func (nullIfEmptySerializer) Scan(ctx context.Context, field *schema.Field, dst reflect.Value, dbValue interface{}) error {
	value := ""
	switch v := dbValue.(type) {
	case nil:
	case string:
		value = v
	case []byte:
		value = string(v)
	}
	field.ReflectValueOf(ctx, dst).SetString(value)
	return nil
}

// Value implements schema.SerializerValuerInterface: "" becomes NULL.
func (nullIfEmptySerializer) Value(ctx context.Context, field *schema.Field, dst reflect.Value, fieldValue interface{}) (interface{}, error) {
	if s, ok := fieldValue.(string); ok && s != "" {
		return s, nil
	}
	return nil, nil
}

func init() {
	schema.RegisterSerializer("nullifempty", nullIfEmptySerializer{})
}

// UserRepositoryImpl implements domain.UserRepository using GORM
type UserRepositoryImpl struct {
	db *gorm.DB
}

// DBUser represents the database model for User (with GORM tags)
type DBUser struct {
	ID            uint           `gorm:"primaryKey"`
	Email         string         `gorm:"uniqueIndex;size:255;serializer:nullifempty"` // "" is stored as NULL (see nullIfEmptySerializer)
	Phone         string         `gorm:"uniqueIndex;size:32"` // the only identifier of a user without e-mail
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
	if email == "" {
		// An empty e-mail means "no e-mail": it never identifies a user.
		return nil, domain.ErrUserNotFound
	}
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

// ExistsByRole implements domain.UserRepository
func (r *UserRepositoryImpl) ExistsByRole(ctx context.Context, role string) (bool, error) {
	var count int64
	if err := r.db.WithContext(ctx).Model(&DBUser{}).Where("role = ?", role).Limit(1).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

// FindByPhone implements domain.UserRepository
func (r *UserRepositoryImpl) FindByPhone(ctx context.Context, phone string) (*domain.User, error) {
	if phone == "" {
		return nil, domain.ErrUserNotFound
	}
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

// FindByIdentifier implements domain.UserRepository - CB-194
func (r *UserRepositoryImpl) FindByIdentifier(ctx context.Context, identifier string, identifierType domain.IdentifierType) (*domain.User, error) {
	if identifier == "" {
		return nil, domain.ErrUserNotFound
	}
	var dbUser DBUser
	var err error

	switch identifierType {
	case domain.IdentifierTypeEmail:
		err = r.db.WithContext(ctx).Where("email = ?", identifier).First(&dbUser).Error
	case domain.IdentifierTypePhone:
		err = r.db.WithContext(ctx).Where("phone = ?", identifier).First(&dbUser).Error
	default:
		return nil, domain.ErrIdentifierTypeUnknown
	}

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
	// created_at is not carried by domainToDB: omit it so Save does not overwrite it with the zero time.
	return r.db.WithContext(ctx).Omit("created_at").Save(dbUser).Error
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