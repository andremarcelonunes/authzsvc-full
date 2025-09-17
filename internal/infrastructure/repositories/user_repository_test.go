package repositories

import (
	"context"
	"testing"
	"time"

	"github.com/you/authzsvc/domain"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// setupTestDB creates an in-memory SQLite database for testing
func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("failed to connect database: %v", err)
	}
	
	// Auto-migrate the schema
	if err := db.AutoMigrate(&DBUser{}); err != nil {
		t.Fatalf("failed to migrate database: %v", err)
	}
	
	return db
}

func TestUserRepositoryImpl_FindByPhone(t *testing.T) {
	tests := []struct {
		name          string
		setupData     func(db *gorm.DB)
		phone         string
		expectedUser  *domain.User
		expectedError error
	}{
		{
			name: "successful find by phone",
			setupData: func(db *gorm.DB) {
				user := &DBUser{
					ID:            1,
					Email:         "test@example.com",
					Phone:         "+1234567890",
					PasswordHash:  "hashed_password",
					Role:          "user",
					IsActive:      true,
					PhoneVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				db.Create(user)
			},
			phone: "+1234567890",
			expectedUser: &domain.User{
				ID:            1,
				Email:         "test@example.com",
				Phone:         "+1234567890",
				PasswordHash:  "hashed_password",
				Role:          "user",
				IsActive:      true,
				PhoneVerified: false,
			},
			expectedError: nil,
		},
		{
			name: "phone not found",
			setupData: func(db *gorm.DB) {
				// No data setup
			},
			phone:         "+9876543210",
			expectedUser:  nil,
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "find verified phone user",
			setupData: func(db *gorm.DB) {
				user := &DBUser{
					ID:            2,
					Email:         "verified@example.com",
					Phone:         "+1111111111",
					PasswordHash:  "hashed_password",
					Role:          "user",
					IsActive:      true,
					PhoneVerified: true, // Verified phone
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				db.Create(user)
			},
			phone: "+1111111111",
			expectedUser: &domain.User{
				ID:            2,
				Email:         "verified@example.com",
				Phone:         "+1111111111",
				PasswordHash:  "hashed_password",
				Role:          "user",
				IsActive:      true,
				PhoneVerified: true,
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test database
			db := setupTestDB(t)
			
			// Setup test data
			tt.setupData(db)
			
			// Create repository
			repo := NewUserRepository(db)
			
			// Execute test
			user, err := repo.FindByPhone(context.Background(), tt.phone)
			
			// Assert error
			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			// Assert user
			if user == nil {
				t.Fatal("user is nil")
			}
			
			if user.ID != tt.expectedUser.ID {
				t.Errorf("expected ID %d, got %d", tt.expectedUser.ID, user.ID)
			}
			if user.Email != tt.expectedUser.Email {
				t.Errorf("expected email %s, got %s", tt.expectedUser.Email, user.Email)
			}
			if user.Phone != tt.expectedUser.Phone {
				t.Errorf("expected phone %s, got %s", tt.expectedUser.Phone, user.Phone)
			}
			if user.PhoneVerified != tt.expectedUser.PhoneVerified {
				t.Errorf("expected phone_verified %v, got %v", tt.expectedUser.PhoneVerified, user.PhoneVerified)
			}
		})
	}
}

func TestUserRepositoryImpl_ActivatePhone(t *testing.T) {
	tests := []struct {
		name          string
		setupData     func(db *gorm.DB) uint
		userID        uint
		expectedError error
		validateData  func(t *testing.T, db *gorm.DB, userID uint)
	}{
		{
			name: "successful phone activation",
			setupData: func(db *gorm.DB) uint {
				user := &DBUser{
					Email:         "test@example.com",
					Phone:         "+1234567890",
					PasswordHash:  "hashed_password",
					Role:          "user",
					IsActive:      true,
					PhoneVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				db.Create(user)
				return user.ID
			},
			expectedError: nil,
			validateData: func(t *testing.T, db *gorm.DB, userID uint) {
				var user DBUser
				if err := db.First(&user, userID).Error; err != nil {
					t.Fatalf("failed to find user: %v", err)
				}
				if !user.PhoneVerified {
					t.Error("expected phone_verified to be true")
				}
			},
		},
		{
			name: "idempotent activation - already verified",
			setupData: func(db *gorm.DB) uint {
				user := &DBUser{
					Email:         "verified@example.com",
					Phone:         "+1111111111",
					PasswordHash:  "hashed_password",
					Role:          "user",
					IsActive:      true,
					PhoneVerified: true, // Already verified
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				db.Create(user)
				return user.ID
			},
			expectedError: nil,
			validateData: func(t *testing.T, db *gorm.DB, userID uint) {
				var user DBUser
				if err := db.First(&user, userID).Error; err != nil {
					t.Fatalf("failed to find user: %v", err)
				}
				if !user.PhoneVerified {
					t.Error("expected phone_verified to remain true")
				}
			},
		},
		{
			name: "activate non-existent user",
			setupData: func(db *gorm.DB) uint {
				// No data setup
				return 999 // Non-existent ID
			},
			userID:        999,
			expectedError: nil, // GORM doesn't error on UPDATE with no matching rows
			validateData: func(t *testing.T, db *gorm.DB, userID uint) {
				var count int64
				db.Model(&DBUser{}).Where("id = ? AND phone_verified = ?", userID, true).Count(&count)
				if count != 0 {
					t.Error("no rows should be affected for non-existent user")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test database
			db := setupTestDB(t)
			
			// Setup test data and get user ID
			userID := tt.setupData(db)
			if tt.userID != 0 {
				userID = tt.userID
			}
			
			// Create repository
			repo := NewUserRepository(db)
			
			// Execute test
			err := repo.ActivatePhone(context.Background(), userID)
			
			// Assert error
			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			// Validate data changes
			tt.validateData(t, db, userID)
		})
	}
}

func TestUserRepositoryImpl_FindByEmail(t *testing.T) {
	tests := []struct {
		name          string
		setupData     func(db *gorm.DB)
		email         string
		expectedUser  *domain.User
		expectedError error
	}{
		{
			name: "successful find by email",
			setupData: func(db *gorm.DB) {
				user := &DBUser{
					ID:            1,
					Email:         "test@example.com",
					Phone:         "+1234567890",
					PasswordHash:  "hashed_password",
					Role:          "user",
					IsActive:      true,
					PhoneVerified: true,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				db.Create(user)
			},
			email: "test@example.com",
			expectedUser: &domain.User{
				ID:            1,
				Email:         "test@example.com",
				Phone:         "+1234567890",
				PasswordHash:  "hashed_password",
				Role:          "user",
				IsActive:      true,
				PhoneVerified: true,
			},
			expectedError: nil,
		},
		{
			name: "email not found",
			setupData: func(db *gorm.DB) {
				// No data setup
			},
			email:         "nonexistent@example.com",
			expectedUser:  nil,
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "exact case email search",
			setupData: func(db *gorm.DB) {
				user := &DBUser{
					ID:            2,
					Email:         "ExactCase@Example.Com",
					Phone:         "+9876543210",
					PasswordHash:  "hashed_password",
					Role:          "admin",
					IsActive:      true,
					PhoneVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				db.Create(user)
			},
			email: "ExactCase@Example.Com", // Exact case match
			expectedUser: &domain.User{
				ID:            2,
				Email:         "ExactCase@Example.Com",
				Phone:         "+9876543210",
				Role:          "admin",
				IsActive:      true,
				PhoneVerified: false,
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test database
			db := setupTestDB(t)
			
			// Setup test data
			tt.setupData(db)
			
			// Create repository
			repo := NewUserRepository(db)
			
			// Execute test
			user, err := repo.FindByEmail(context.Background(), tt.email)
			
			// Assert error
			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			// Assert user
			if user == nil {
				t.Fatal("user is nil")
			}
			
			if user.ID != tt.expectedUser.ID {
				t.Errorf("expected ID %d, got %d", tt.expectedUser.ID, user.ID)
			}
			if user.Email != tt.expectedUser.Email {
				t.Errorf("expected email %s, got %s", tt.expectedUser.Email, user.Email)
			}
			if user.Role != tt.expectedUser.Role {
				t.Errorf("expected role %s, got %s", tt.expectedUser.Role, user.Role)
			}
		})
	}
}

func TestUserRepositoryImpl_FindByID(t *testing.T) {
	tests := []struct {
		name          string
		setupData     func(db *gorm.DB) uint
		userID        uint
		expectedUser  *domain.User
		expectedError error
	}{
		{
			name: "successful find by ID",
			setupData: func(db *gorm.DB) uint {
				user := &DBUser{
					Email:         "findbyid@example.com",
					Phone:         "+1111111111",
					PasswordHash:  "hashed_password",
					Role:          "user",
					IsActive:      true,
					PhoneVerified: true,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				db.Create(user)
				return user.ID
			},
			expectedUser: &domain.User{
				Email:         "findbyid@example.com",
				Phone:         "+1111111111",
				Role:          "user",
				IsActive:      true,
				PhoneVerified: true,
			},
			expectedError: nil,
		},
		{
			name: "user not found by ID",
			setupData: func(db *gorm.DB) uint {
				return 999 // Non-existent ID
			},
			userID:        999,
			expectedUser:  nil,
			expectedError: domain.ErrUserNotFound,
		},
		{
			name: "find inactive user by ID",
			setupData: func(db *gorm.DB) uint {
				user := &DBUser{
					Email:         "inactive@example.com",
					Phone:         "+2222222222",
					PasswordHash:  "hashed_password",
					Role:          "user",
					IsActive:      false, // Inactive user
					PhoneVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				db.Create(user)
				return user.ID
			},
			expectedUser: &domain.User{
				Email:         "inactive@example.com",
				Phone:         "+2222222222",
				Role:          "user",
				IsActive:      false,
				PhoneVerified: false,
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test database
			db := setupTestDB(t)
			
			// Setup test data and get user ID
			userID := tt.setupData(db)
			if tt.userID != 0 {
				userID = tt.userID
			}
			
			// Create repository
			repo := NewUserRepository(db)
			
			// Execute test
			user, err := repo.FindByID(context.Background(), userID)
			
			// Assert error
			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			// Assert user
			if user == nil {
				t.Fatal("user is nil")
			}
			
			if user.Email != tt.expectedUser.Email {
				t.Errorf("expected email %s, got %s", tt.expectedUser.Email, user.Email)
			}
			if user.Phone != tt.expectedUser.Phone {
				t.Errorf("expected phone %s, got %s", tt.expectedUser.Phone, user.Phone)
			}
			if user.IsActive != tt.expectedUser.IsActive {
				t.Errorf("expected is_active %v, got %v", tt.expectedUser.IsActive, user.IsActive)
			}
		})
	}
}

func TestUserRepositoryImpl_Update(t *testing.T) {
	tests := []struct {
		name          string
		setupData     func(db *gorm.DB) *domain.User
		updateUser    func(*domain.User) *domain.User
		expectedError error
		validateData  func(t *testing.T, db *gorm.DB, userID uint)
	}{
		{
			name: "successful user update",
			setupData: func(db *gorm.DB) *domain.User {
				user := &DBUser{
					Email:         "update@example.com",
					Phone:         "+3333333333",
					PasswordHash:  "old_password",
					Role:          "user",
					IsActive:      true,
					PhoneVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				db.Create(user)
				return &domain.User{
					ID:            user.ID,
					Email:         user.Email,
					Phone:         user.Phone,
					PasswordHash:  user.PasswordHash,
					Role:          user.Role,
					IsActive:      user.IsActive,
					PhoneVerified: user.PhoneVerified,
					CreatedAt:     user.CreatedAt,
					UpdatedAt:     user.UpdatedAt,
				}
			},
			updateUser: func(user *domain.User) *domain.User {
				user.PasswordHash = "new_password_hash"
				user.Role = "admin"
				user.PhoneVerified = true
				return user
			},
			expectedError: nil,
			validateData: func(t *testing.T, db *gorm.DB, userID uint) {
				var user DBUser
				if err := db.First(&user, userID).Error; err != nil {
					t.Fatalf("failed to find updated user: %v", err)
				}
				if user.PasswordHash != "new_password_hash" {
					t.Error("password hash not updated")
				}
				if user.Role != "admin" {
					t.Error("role not updated")
				}
				if !user.PhoneVerified {
					t.Error("phone verification not updated")
				}
			},
		},
		{
			name: "update creates non-existent user (upsert behavior)",
			setupData: func(db *gorm.DB) *domain.User {
				// Return non-existent user - GORM Save() will create it
				return &domain.User{
					ID:           999,
					Email:        "nonexistent@example.com",
					PasswordHash: "password",
					Role:         "user",
					IsActive:     false,
				}
			},
			updateUser: func(user *domain.User) *domain.User {
				user.Role = "admin"
				user.IsActive = true
				return user
			},
			expectedError: nil, // GORM Save() creates if not exists (upsert)
			validateData: func(t *testing.T, db *gorm.DB, userID uint) {
				// Verify user was created with updated values
				var user DBUser
				if err := db.First(&user, userID).Error; err != nil {
					t.Fatalf("expected user to be created: %v", err)
				}
				if user.Role != "admin" {
					t.Errorf("expected role to be admin, got %s", user.Role)
				}
				if !user.IsActive {
					t.Error("expected user to be active after upsert")
				}
			},
		},
		{
			name: "update user with validation constraints",
			setupData: func(db *gorm.DB) *domain.User {
				user := &DBUser{
					Email:         "constraints@example.com",
					Phone:         "+4444444444",
					PasswordHash:  "password",
					Role:          "user",
					IsActive:      true,
					PhoneVerified: false,
					CreatedAt:     time.Now(),
					UpdatedAt:     time.Now(),
				}
				db.Create(user)
				return &domain.User{
					ID:            user.ID,
					Email:         user.Email,
					Phone:         user.Phone,
					PasswordHash:  user.PasswordHash,
					Role:          user.Role,
					IsActive:      user.IsActive,
					PhoneVerified: user.PhoneVerified,
					CreatedAt:     user.CreatedAt,
					UpdatedAt:     user.UpdatedAt,
				}
			},
			updateUser: func(user *domain.User) *domain.User {
				user.IsActive = false
				user.Phone = "+9999999999"
				return user
			},
			expectedError: nil,
			validateData: func(t *testing.T, db *gorm.DB, userID uint) {
				var user DBUser
				if err := db.First(&user, userID).Error; err != nil {
					t.Fatalf("failed to find updated user: %v", err)
				}
				if user.IsActive {
					t.Error("user should be inactive")
				}
				if user.Phone != "+9999999999" {
					t.Error("phone not updated")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test database
			db := setupTestDB(t)
			
			// Setup test data
			originalUser := tt.setupData(db)
			updatedUser := tt.updateUser(originalUser)
			
			// Create repository
			repo := NewUserRepository(db)
			
			// Execute test
			err := repo.Update(context.Background(), updatedUser)
			
			// Assert error
			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			// Validate data changes
			tt.validateData(t, db, updatedUser.ID)
		})
	}
}

func TestUserRepositoryImpl_Create_EdgeCases(t *testing.T) {
	tests := []struct {
		name          string
		user          *domain.User
		expectedError error
		validateData  func(t *testing.T, db *gorm.DB)
	}{
		{
			name: "create user with minimal required fields",
			user: &domain.User{
				Email:        "minimal@example.com",
				PasswordHash: "hash",
				Role:         "user",
			},
			expectedError: nil,
			validateData: func(t *testing.T, db *gorm.DB) {
				var user DBUser
				if err := db.Where("email = ?", "minimal@example.com").First(&user).Error; err != nil {
					t.Errorf("user not created: %v", err)
				}
				if user.Phone != "" {
					t.Error("phone should be empty")
				}
				if user.IsActive {
					t.Error("user should be inactive by default")
				}
			},
		},
		{
			name: "create user with all fields",
			user: &domain.User{
				Email:         "complete@example.com",
				Phone:         "+5555555555",
				PasswordHash:  "complete_hash",
				Role:          "admin",
				IsActive:      true,
				PhoneVerified: true,
			},
			expectedError: nil,
			validateData: func(t *testing.T, db *gorm.DB) {
				var user DBUser
				if err := db.Where("email = ?", "complete@example.com").First(&user).Error; err != nil {
					t.Errorf("user not created: %v", err)
				}
				if user.Role != "admin" {
					t.Error("role not set correctly")
				}
				if !user.IsActive {
					t.Error("user should be active")
				}
				if !user.PhoneVerified {
					t.Error("phone should be verified")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test database
			db := setupTestDB(t)
			
			// Create repository
			repo := NewUserRepository(db)
			
			// Execute test
			err := repo.Create(context.Background(), tt.user)
			
			// Assert error
			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			// Validate data
			tt.validateData(t, db)
		})
	}
}

func TestUserRepositoryImpl_FindByPhone_DatabaseTransaction(t *testing.T) {
	// Test database transaction atomicity
	db := setupTestDB(t)
	repo := NewUserRepository(db)
	
	// Create a user
	user := &domain.User{
		Email:         "transaction@example.com",
		Phone:         "+1234567890",
		PasswordHash:  "hashed_password",
		Role:          "user",
		IsActive:      true,
		PhoneVerified: false,
	}
	
	if err := repo.Create(context.Background(), user); err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
	
	// Start a transaction and verify phone within transaction
	tx := db.Begin()
	ctx := context.Background()
	
	// Use transaction context
	txRepo := &UserRepositoryImpl{db: tx}
	
	// Find user by phone in transaction
	foundUser, err := txRepo.FindByPhone(ctx, "+1234567890")
	if err != nil {
		tx.Rollback()
		t.Fatalf("failed to find user by phone: %v", err)
	}
	
	// Activate phone in transaction
	if err := txRepo.ActivatePhone(ctx, foundUser.ID); err != nil {
		tx.Rollback()
		t.Fatalf("failed to activate phone: %v", err)
	}
	
	// Verify phone is activated within transaction
	updatedUser, err := txRepo.FindByPhone(ctx, "+1234567890")
	if err != nil {
		tx.Rollback()
		t.Fatalf("failed to find updated user: %v", err)
	}
	
	if !updatedUser.PhoneVerified {
		tx.Rollback()
		t.Error("phone should be verified within transaction")
	}
	
	// Commit transaction
	if err := tx.Commit().Error; err != nil {
		t.Fatalf("failed to commit transaction: %v", err)
	}
	
	// Verify changes are persisted after commit
	finalUser, err := repo.FindByPhone(context.Background(), "+1234567890")
	if err != nil {
		t.Fatalf("failed to find user after commit: %v", err)
	}
	
	if !finalUser.PhoneVerified {
		t.Error("phone verification should be persisted after commit")
	}
}