package e2e

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/infrastructure/auth"
	"github.com/you/authzsvc/internal/infrastructure/repositories"
)

// TestUserFactory provides utilities for creating test users consistently
type TestUserFactory struct {
	t           *testing.T
	db          *gorm.DB
	passwordSvc domain.PasswordService
}

// NewTestUserFactory creates a new test user factory
func NewTestUserFactory(t *testing.T, db *gorm.DB) *TestUserFactory {
	t.Helper()
	return &TestUserFactory{
		t:           t,
		db:          db,
		passwordSvc: auth.NewPasswordService(),
	}
}

// TestUserOptions configures test user creation
type TestUserOptions struct {
	Email         string
	Phone         string
	Password      string
	Role          string
	IsActive      bool
	PhoneVerified bool
	HashPassword  bool
}

// DefaultTestUser returns default test user options
func DefaultTestUser() *TestUserOptions {
	return &TestUserOptions{
		Email:         generateTestEmail(),
		Phone:         generateTestPhone(),
		Password:      "Test123!@#",
		Role:          "user",
		IsActive:      true,
		PhoneVerified: true,
		HashPassword:  true,
	}
}

// AdminTestUser returns test user options for admin user
func AdminTestUser() *TestUserOptions {
	opts := DefaultTestUser()
	opts.Role = "admin"
	opts.Email = generateTestAdminEmail()
	return opts
}

// CreateUser creates a test user with the given options
func (f *TestUserFactory) CreateUser(opts *TestUserOptions) (*domain.User, error) {
	f.t.Helper()

	if opts == nil {
		opts = DefaultTestUser()
	}

	// Use DBUser entity which has correct GORM column mappings
	dbUser := &repositories.DBUser{
		Email:         opts.Email,
		Phone:         opts.Phone,
		Role:          opts.Role,
		IsActive:      opts.IsActive,
		PhoneVerified: opts.PhoneVerified,
	}

	// Hash password if requested - use the same password service as the application
	if opts.HashPassword {
		hashedPassword, err := f.passwordSvc.Hash(opts.Password)
		if err != nil {
			return nil, fmt.Errorf("failed to hash password: %w", err)
		}
		dbUser.PasswordHash = hashedPassword
	} else {
		dbUser.PasswordHash = opts.Password
	}

	// Create user in database using DBUser entity
	if err := f.db.Create(dbUser).Error; err != nil {
		return nil, fmt.Errorf("failed to create test user: %w", err)
	}

	// Convert back to domain User for return
	user := &domain.User{
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

	return user, nil
}

// CreateUserT creates a test user or fails the test
func (f *TestUserFactory) CreateUserT(opts *TestUserOptions) *domain.User {
	f.t.Helper()

	user, err := f.CreateUser(opts)
	if err != nil {
		f.t.Fatalf("Failed to create test user: %v", err)
	}
	return user
}

// CreateUsers creates multiple test users
func (f *TestUserFactory) CreateUsers(count int, opts *TestUserOptions) ([]*domain.User, error) {
	f.t.Helper()

	users := make([]*domain.User, 0, count)

	for i := 0; i < count; i++ {
		userOpts := *opts // Copy options
		userOpts.Email = fmt.Sprintf("test%d_%s", i, generateTestEmail())
		userOpts.Phone = generateTestPhone()

		user, err := f.CreateUser(&userOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to create test user %d: %w", i, err)
		}
		users = append(users, user)
	}

	return users, nil
}

// CreateUsersT creates multiple test users or fails the test
func (f *TestUserFactory) CreateUsersT(count int, opts *TestUserOptions) []*domain.User {
	f.t.Helper()

	users, err := f.CreateUsers(count, opts)
	if err != nil {
		f.t.Fatalf("Failed to create test users: %v", err)
	}
	return users
}

// TestAuthRequestFactory provides utilities for creating test auth requests
type TestAuthRequestFactory struct {
	t *testing.T
}

// NewTestAuthRequestFactory creates a new auth request factory
func NewTestAuthRequestFactory(t *testing.T) *TestAuthRequestFactory {
	t.Helper()
	return &TestAuthRequestFactory{t: t}
}

// CreateAuthRequest creates a test auth request
func (f *TestAuthRequestFactory) CreateAuthRequest(email, password string) *domain.AuthRequest {
	f.t.Helper()

	return &domain.AuthRequest{
		Email:    email,
		Password: password,
	}
}

// CreateValidAuthRequest creates a valid auth request for a test user
func (f *TestAuthRequestFactory) CreateValidAuthRequest(user *domain.User, password string) *domain.AuthRequest {
	f.t.Helper()

	return &domain.AuthRequest{
		Email:    user.Email,
		Password: password,
	}
}

// TestOTPRequestFactory provides utilities for creating test OTP requests
type TestOTPRequestFactory struct {
	t *testing.T
}

// NewTestOTPRequestFactory creates a new OTP request factory
func NewTestOTPRequestFactory(t *testing.T) *TestOTPRequestFactory {
	t.Helper()
	return &TestOTPRequestFactory{t: t}
}

// CreateOTPRequest creates a test OTP request
func (f *TestOTPRequestFactory) CreateOTPRequest(userID uint, phone string) *domain.OTPRequest {
	f.t.Helper()

	return &domain.OTPRequest{
		UserID:    userID,
		Phone:     phone,
		Code:      generateOTPCode(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
		Attempts:  0,
	}
}

// CreateExpiredOTPRequest creates an expired OTP request for testing
func (f *TestOTPRequestFactory) CreateExpiredOTPRequest(userID uint, phone string) *domain.OTPRequest {
	f.t.Helper()

	return &domain.OTPRequest{
		UserID:    userID,
		Phone:     phone,
		Code:      generateOTPCode(),
		ExpiresAt: time.Now().Add(-1 * time.Minute), // Already expired
		Attempts:  0,
	}
}

// TestSessionFactory provides utilities for creating test sessions
type TestSessionFactory struct {
	t     *testing.T
	suite *TestSuite
}

// NewTestSessionFactory creates a new session factory
func NewTestSessionFactory(t *testing.T, suite *TestSuite) *TestSessionFactory {
	t.Helper()
	return &TestSessionFactory{
		t:     t,
		suite: suite,
	}
}

// CreateSession creates a test session in Redis
func (f *TestSessionFactory) CreateSession(userID uint) (*domain.Session, error) {
	f.t.Helper()

	sessionID := generateSessionID()
	session := &domain.Session{
		ID:        sessionID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	// Store session in Redis with test prefix
	ctx := context.Background()
	key := f.suite.GetRedisKey(fmt.Sprintf("session:%s", sessionID))
	err := f.suite.Redis.Set(ctx, key, fmt.Sprintf("%d", userID), 24*time.Hour).Err()
	if err != nil {
		return nil, fmt.Errorf("failed to create test session: %w", err)
	}

	return session, nil
}

// CreateSessionT creates a test session or fails the test
func (f *TestSessionFactory) CreateSessionT(userID uint) *domain.Session {
	f.t.Helper()

	session, err := f.CreateSession(userID)
	if err != nil {
		f.t.Fatalf("Failed to create test session: %v", err)
	}
	return session
}

// TestDataFixtures provides common test data fixtures
type TestDataFixtures struct {
	t     *testing.T
	suite *TestSuite
	db    *gorm.DB
}

// NewTestDataFixtures creates a new fixtures instance
func NewTestDataFixtures(t *testing.T, suite *TestSuite) *TestDataFixtures {
	t.Helper()
	return &TestDataFixtures{
		t:     t,
		suite: suite,
		db:    suite.DB,
	}
}

// CreateCompleteUserFixture creates a user with session for complete testing
func (f *TestDataFixtures) CreateCompleteUserFixture() (*domain.User, *domain.Session, error) {
	f.t.Helper()

	// Create user
	userFactory := NewTestUserFactory(f.t, f.db)
	user, err := userFactory.CreateUser(DefaultTestUser())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Create session
	sessionFactory := NewTestSessionFactory(f.t, f.suite)
	session, err := sessionFactory.CreateSession(user.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session: %w", err)
	}

	return user, session, nil
}

// CreateCompleteUserFixtureT creates a complete user fixture or fails the test
func (f *TestDataFixtures) CreateCompleteUserFixtureT() (*domain.User, *domain.Session) {
	f.t.Helper()

	user, session, err := f.CreateCompleteUserFixture()
	if err != nil {
		f.t.Fatalf("Failed to create complete user fixture: %v", err)
	}
	return user, session
}

// CreateAdminUserFixture creates an admin user for testing
func (f *TestDataFixtures) CreateAdminUserFixture() (*domain.User, error) {
	f.t.Helper()

	userFactory := NewTestUserFactory(f.t, f.db)
	return userFactory.CreateUser(AdminTestUser())
}

// CreateAdminUserFixtureT creates an admin user or fails the test
func (f *TestDataFixtures) CreateAdminUserFixtureT() *domain.User {
	f.t.Helper()

	user, err := f.CreateAdminUserFixture()
	if err != nil {
		f.t.Fatalf("Failed to create admin user fixture: %v", err)
	}
	return user
}

// CreateTestUsersForPerformance creates multiple users for performance testing
func (f *TestDataFixtures) CreateTestUsersForPerformance(count int) ([]*domain.User, error) {
	f.t.Helper()

	userFactory := NewTestUserFactory(f.t, f.db)
	opts := DefaultTestUser()
	
	return userFactory.CreateUsers(count, opts)
}

// CreateTestUsersForPerformanceT creates users for performance testing or fails the test
func (f *TestDataFixtures) CreateTestUsersForPerformanceT(count int) []*domain.User {
	f.t.Helper()

	users, err := f.CreateTestUsersForPerformance(count)
	if err != nil {
		f.t.Fatalf("Failed to create performance test users: %v", err)
	}
	return users
}

// Helper functions for generating test data

// generateTestEmail creates a unique test email address
func generateTestEmail() string {
	timestamp := time.Now().UnixNano()
	// Add random component to prevent collisions in rapid succession
	n, _ := rand.Int(rand.Reader, big.NewInt(999999))
	return fmt.Sprintf("test.user.%d.%d@e2etest.local", timestamp, n.Int64())
}

// generateTestAdminEmail creates a unique admin test email address
func generateTestAdminEmail() string {
	timestamp := time.Now().UnixNano()
	// Add random component to prevent collisions in rapid succession
	n, _ := rand.Int(rand.Reader, big.NewInt(999999))
	return fmt.Sprintf("admin.user.%d.%d@e2etest.local", timestamp, n.Int64())
}

// generateTestPhone creates a test phone number
func generateTestPhone() string {
	// Generate a random 10-digit number with timestamp to ensure uniqueness
	timestamp := time.Now().UnixNano() % 10000000000 // Last 10 digits of timestamp
	n, _ := rand.Int(rand.Reader, big.NewInt(1000))   // Add random component
	return fmt.Sprintf("+1%010d%03d", timestamp, n.Int64())
}

// generateOTPCode creates a 6-digit OTP code for testing
func generateOTPCode() string {
	code, _ := rand.Int(rand.Reader, big.NewInt(1000000))
	return fmt.Sprintf("%06d", code.Int64())
}

// generateSessionID creates a unique session ID
func generateSessionID() string {
	timestamp := time.Now().UnixNano()
	return fmt.Sprintf("sess_%d", timestamp)
}

// TestPasswordHelper provides password-related utilities for testing
type TestPasswordHelper struct {
	t *testing.T
}

// NewTestPasswordHelper creates a password helper
func NewTestPasswordHelper(t *testing.T) *TestPasswordHelper {
	t.Helper()
	return &TestPasswordHelper{t: t}
}

// ValidPassword returns a valid test password
func (h *TestPasswordHelper) ValidPassword() string {
	return "Test123!@#"
}

// WeakPassword returns a weak password for validation testing
func (h *TestPasswordHelper) WeakPassword() string {
	return "123"
}

// LongPassword returns a very long password for edge case testing
func (h *TestPasswordHelper) LongPassword() string {
	return "This_Is_A_Very_Long_Password_That_Exceeds_Normal_Length_Requirements_For_Edge_Case_Testing_123!@#"
}

// HashPassword hashes a password using bcrypt
func (h *TestPasswordHelper) HashPassword(password string) string {
	h.t.Helper()

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		h.t.Fatalf("Failed to hash password: %v", err)
	}
	return string(hashedPassword)
}

// TestConstants provides common test constants
var TestConstants = struct {
	ValidEmail         string
	InvalidEmail       string
	ValidPhone         string
	InvalidPhone       string
	ValidPassword      string
	WeakPassword       string
	DefaultUserRole    string
	AdminRole          string
	SessionExpiryHours int
	OTPExpiryMinutes   int
}{
	ValidEmail:         "test@e2etest.local",
	InvalidEmail:       "invalid-email",
	ValidPhone:         "+15551234567",
	InvalidPhone:       "123",
	ValidPassword:      "Test123!@#",
	WeakPassword:       "123",
	DefaultUserRole:    "user",
	AdminRole:          "admin",
	SessionExpiryHours: 24,
	OTPExpiryMinutes:   5,
}

// CleanupTestData removes all test data created by fixtures
func CleanupTestData(t *testing.T, suite *TestSuite) {
	t.Helper()

	// Clean database
	helper := NewDatabaseTestHelper(t, suite)
	if err := helper.CleanAllTables(); err != nil {
		t.Logf("Warning: Failed to clean database: %v", err)
	}

	// Clean Redis
	ctx := context.Background()
	keys, err := suite.Redis.Keys(ctx, fmt.Sprintf("%s:*", suite.TestPrefix)).Result()
	if err == nil && len(keys) > 0 {
		if err := suite.Redis.Del(ctx, keys...).Err(); err != nil {
			t.Logf("Warning: Failed to clean Redis keys: %v", err)
		}
	}
}

