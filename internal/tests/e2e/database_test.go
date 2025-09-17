package e2e

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/you/authzsvc/domain"
)

// DatabaseTestHelper provides utilities for database testing with isolation
type DatabaseTestHelper struct {
	suite *TestSuite
	tx    *gorm.DB
	t     *testing.T
}

// NewDatabaseTestHelper creates a new database test helper
func NewDatabaseTestHelper(t *testing.T, suite *TestSuite) *DatabaseTestHelper {
	t.Helper()
	
	return &DatabaseTestHelper{
		suite: suite,
		t:     t,
	}
}

// WithTransaction executes a function within an isolated database transaction
// The transaction is automatically rolled back after execution for test isolation
func (h *DatabaseTestHelper) WithTransaction(fn func(tx *gorm.DB) error) error {
	h.t.Helper()

	tx := h.suite.DB.Begin()
	if tx.Error != nil {
		return fmt.Errorf("failed to begin transaction: %w", tx.Error)
	}

	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r)
		}
	}()

	// Store transaction for helper methods
	h.tx = tx

	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}

	// Always rollback in tests for complete isolation
	tx.Rollback()
	return nil
}

// WithTransactionT executes a function within an isolated database transaction
// Automatically fails the test if transaction setup fails
func (h *DatabaseTestHelper) WithTransactionT(fn func(tx *gorm.DB)) {
	h.t.Helper()

	err := h.WithTransaction(func(tx *gorm.DB) error {
		fn(tx)
		return nil
	})

	if err != nil {
		h.t.Fatalf("Database transaction failed: %v", err)
	}
}

// CleanAllTables removes all data from test database tables
func (h *DatabaseTestHelper) CleanAllTables() error {
	h.t.Helper()

	// Disable foreign key constraints temporarily
	if err := h.suite.DB.Exec("SET session_replication_role = replica").Error; err != nil {
		return fmt.Errorf("failed to disable foreign key constraints: %w", err)
	}

	// List of tables to clean (in dependency order - dependent tables first)
	tables := []string{
		"casbin_rule",     // Casbin policies
		"users",           // User data
		// Add additional tables as they are created
	}

	// Clean each table
	for _, table := range tables {
		if err := h.suite.DB.Exec(fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", table)).Error; err != nil {
			h.t.Logf("Warning: Failed to clean table %s: %v", table, err)
		}
	}

	// Re-enable foreign key constraints
	if err := h.suite.DB.Exec("SET session_replication_role = DEFAULT").Error; err != nil {
		return fmt.Errorf("failed to re-enable foreign key constraints: %w", err)
	}

	return nil
}

// CleanAllTablesT removes all data from test database tables or fails the test
func (h *DatabaseTestHelper) CleanAllTablesT() {
	h.t.Helper()

	if err := h.CleanAllTables(); err != nil {
		h.t.Fatalf("Failed to clean database tables: %v", err)
	}
}

// CountRecords returns the number of records in a table
func (h *DatabaseTestHelper) CountRecords(table string) (int64, error) {
	h.t.Helper()

	var count int64
	err := h.suite.DB.Raw(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count).Error
	return count, err
}

// CountRecordsT returns the number of records in a table or fails the test
func (h *DatabaseTestHelper) CountRecordsT(table string) int64 {
	h.t.Helper()

	count, err := h.CountRecords(table)
	if err != nil {
		h.t.Fatalf("Failed to count records in table %s: %v", table, err)
	}
	return count
}

// TableExists checks if a table exists in the database
func (h *DatabaseTestHelper) TableExists(table string) (bool, error) {
	h.t.Helper()

	var exists bool
	query := `
		SELECT EXISTS (
			SELECT 1 FROM information_schema.tables 
			WHERE table_schema = 'auth' AND table_name = ?
		)`
	
	err := h.suite.DB.Raw(query, table).Scan(&exists).Error
	return exists, err
}

// TableExistsT checks if a table exists or fails the test
func (h *DatabaseTestHelper) TableExistsT(table string) bool {
	h.t.Helper()

	exists, err := h.TableExists(table)
	if err != nil {
		h.t.Fatalf("Failed to check if table %s exists: %v", table, err)
	}
	return exists
}

// WaitForTable waits for a table to exist (useful for migration testing)
func (h *DatabaseTestHelper) WaitForTable(table string, timeout time.Duration) error {
	h.t.Helper()

	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		exists, err := h.TableExists(table)
		if err != nil {
			return fmt.Errorf("error checking table existence: %w", err)
		}
		if exists {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	
	return fmt.Errorf("table %s did not appear within timeout %v", table, timeout)
}

// ExecuteSQL executes raw SQL and returns the result
func (h *DatabaseTestHelper) ExecuteSQL(query string, args ...interface{}) *gorm.DB {
	h.t.Helper()
	
	return h.suite.DB.Exec(query, args...)
}

// ExecuteSQLT executes raw SQL or fails the test
func (h *DatabaseTestHelper) ExecuteSQLT(query string, args ...interface{}) {
	h.t.Helper()

	result := h.ExecuteSQL(query, args...)
	if result.Error != nil {
		h.t.Fatalf("SQL execution failed: %v", result.Error)
	}
}

// CheckTableSchema validates that a table has expected columns
func (h *DatabaseTestHelper) CheckTableSchema(table string, expectedColumns []string) error {
	h.t.Helper()

	query := `
		SELECT column_name 
		FROM information_schema.columns 
		WHERE table_schema = 'auth' AND table_name = ?
		ORDER BY column_name`

	var actualColumns []string
	err := h.suite.DB.Raw(query, table).Scan(&actualColumns).Error
	if err != nil {
		return fmt.Errorf("failed to query table schema: %w", err)
	}

	// Create a map for expected columns for easy lookup
	expectedMap := make(map[string]bool)
	for _, col := range expectedColumns {
		expectedMap[col] = true
	}

	// Check if all expected columns exist
	for _, expected := range expectedColumns {
		found := false
		for _, actual := range actualColumns {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("expected column '%s' not found in table '%s'", expected, table)
		}
	}

	return nil
}

// CheckTableSchemaT validates table schema or fails the test
func (h *DatabaseTestHelper) CheckTableSchemaT(table string, expectedColumns []string) {
	h.t.Helper()

	if err := h.CheckTableSchema(table, expectedColumns); err != nil {
		h.t.Fatalf("Table schema validation failed: %v", err)
	}
}

// DatabaseTestTransaction represents an isolated database transaction for testing
type DatabaseTestTransaction struct {
	tx *gorm.DB
	t  *testing.T
}

// NewDatabaseTestTransaction creates a new isolated database transaction
func NewDatabaseTestTransaction(t *testing.T, db *gorm.DB) *DatabaseTestTransaction {
	t.Helper()

	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("Failed to begin test transaction: %v", tx.Error)
	}

	testTx := &DatabaseTestTransaction{
		tx: tx,
		t:  t,
	}

	// Automatically rollback when test completes
	t.Cleanup(func() {
		testTx.Rollback()
	})

	return testTx
}

// DB returns the transaction database instance
func (tx *DatabaseTestTransaction) DB() *gorm.DB {
	return tx.tx
}

// Rollback rolls back the transaction
func (tx *DatabaseTestTransaction) Rollback() {
	if tx.tx != nil {
		tx.tx.Rollback()
		tx.tx = nil
	}
}

// CreateUser creates a user within the transaction
func (tx *DatabaseTestTransaction) CreateUser(user *domain.User) error {
	tx.t.Helper()
	
	return tx.tx.Create(user).Error
}

// CreateUserT creates a user or fails the test
func (tx *DatabaseTestTransaction) CreateUserT(user *domain.User) {
	tx.t.Helper()

	if err := tx.CreateUser(user); err != nil {
		tx.t.Fatalf("Failed to create test user: %v", err)
	}
}

// FindUserByEmail finds a user by email within the transaction
func (tx *DatabaseTestTransaction) FindUserByEmail(email string) (*domain.User, error) {
	tx.t.Helper()

	var user domain.User
	err := tx.tx.Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

// FindUserByEmailT finds a user by email or fails the test
func (tx *DatabaseTestTransaction) FindUserByEmailT(email string) *domain.User {
	tx.t.Helper()

	user, err := tx.FindUserByEmail(email)
	if err != nil {
		tx.t.Fatalf("Failed to find user by email %s: %v", email, err)
	}
	return user
}

// AssertUserExists verifies that a user exists in the database
func (tx *DatabaseTestTransaction) AssertUserExists(t *testing.T, email string) *domain.User {
	t.Helper()

	user, err := tx.FindUserByEmail(email)
	if err != nil {
		t.Fatalf("Expected user %s to exist, but got error: %v", email, err)
	}
	return user
}

// AssertUserNotExists verifies that a user does not exist in the database
func (tx *DatabaseTestTransaction) AssertUserNotExists(t *testing.T, email string) {
	t.Helper()

	_, err := tx.FindUserByEmail(email)
	if err == nil {
		t.Fatalf("Expected user %s to not exist, but it was found", email)
	}
	if err != gorm.ErrRecordNotFound {
		t.Fatalf("Unexpected error while checking for user %s: %v", email, err)
	}
}

// MeasureQueryPerformance measures the performance of a database query
func (h *DatabaseTestHelper) MeasureQueryPerformance(query string, args ...interface{}) (time.Duration, error) {
	h.t.Helper()

	start := time.Now()
	result := h.suite.DB.Exec(query, args...)
	duration := time.Since(start)

	if result.Error != nil {
		return 0, result.Error
	}

	return duration, nil
}

// MeasureQueryPerformanceT measures query performance or fails the test
func (h *DatabaseTestHelper) MeasureQueryPerformanceT(query string, args ...interface{}) time.Duration {
	h.t.Helper()

	duration, err := h.MeasureQueryPerformance(query, args...)
	if err != nil {
		h.t.Fatalf("Query performance measurement failed: %v", err)
	}
	return duration
}

// ValidateDatabasePerformance checks if database operations meet performance requirements
func (h *DatabaseTestHelper) ValidateDatabasePerformance(t *testing.T) {
	t.Helper()

	// Test basic user lookup performance (CB-176 requirement: <50ms)
	duration := h.MeasureQueryPerformanceT("SELECT * FROM users WHERE email = $1 LIMIT 1", "test@example.com")
	
	if duration > 50*time.Millisecond {
		t.Errorf("Database query took %v, exceeds 50ms target", duration)
	}

	t.Logf("Database performance: User lookup took %v", duration)
}

// GetRawConnection returns the raw database connection for advanced operations
func (h *DatabaseTestHelper) GetRawConnection() *sql.DB {
	h.t.Helper()

	rawDB, err := h.suite.DB.DB()
	if err != nil {
		h.t.Fatalf("Failed to get raw database connection: %v", err)
	}
	return rawDB
}