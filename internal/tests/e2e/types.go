package e2e

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/you/authzsvc/internal/config"
)

// TestSuite holds the E2E test infrastructure
type TestSuite struct {
	Config     *config.Config
	DB         *gorm.DB
	RawDB      *sql.DB
	Redis      *redis.Client
	TestPrefix string
	StartTime  time.Time
}

// GetRedisKey generates a Redis key with test prefix for isolation
func (ts *TestSuite) GetRedisKey(key string) string {
	return fmt.Sprintf("%s:%s", ts.TestPrefix, key)
}

// CleanAllDatabaseTables removes all data from test tables for cleanup
func CleanAllDatabaseTables(suite *TestSuite) error {
	// Disable foreign key constraints temporarily
	if err := suite.DB.Exec("SET session_replication_role = replica").Error; err != nil {
		return fmt.Errorf("failed to disable foreign key constraints: %w", err)
	}

	// List of tables to clean (in dependency order - dependent tables first)
	tables := []string{
		"comprehensive_audit_events", // CB-183 audit events
		"casbin_rule",                // Casbin policies
		"users",                      // User data
		// Add additional tables as they are created
	}

	// Clean each table
	for _, table := range tables {
		if err := suite.DB.Exec(fmt.Sprintf("TRUNCATE TABLE %s RESTART IDENTITY CASCADE", table)).Error; err != nil {
			// Don't fail on cleanup errors, just log them
			continue
		}
	}

	// Re-enable foreign key constraints
	if err := suite.DB.Exec("SET session_replication_role = DEFAULT").Error; err != nil {
		return fmt.Errorf("failed to re-enable foreign key constraints: %w", err)
	}

	return nil
}

