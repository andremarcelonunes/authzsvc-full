package database

import (
	"fmt"

	"github.com/casbin/gorm-adapter/v3"
	"github.com/you/authzsvc/internal/infrastructure/repositories"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

// Open creates a new database connection with production-ready settings
func Open(dsn string) (*gorm.DB, error) {
	config := &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
		NamingStrategy: schema.NamingStrategy{
			TablePrefix: "auth.",
		},
	}
	
	return gorm.Open(postgres.Open(dsn), config)
}

// AutoMigrate performs database migration for all required tables
// This includes user tables and Casbin policy tables for RBAC
func AutoMigrate(db *gorm.DB) error {
	// Migrate user tables using GORM models
	if err := db.AutoMigrate(&repositories.DBUser{}); err != nil {
		return fmt.Errorf("failed to migrate users table: %w", err)
	}

	// Initialize Casbin GORM adapter tables
	// This will create the casbin_rules table if it doesn't exist
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return fmt.Errorf("failed to initialize Casbin GORM adapter: %w", err)
	}

	// The adapter automatically creates the casbin_rules table
	// We just need to ensure it's properly initialized
	_ = adapter

	return nil
}

// Note: Using GORM's built-in NamingStrategy with TablePrefix instead of custom implementation