package database

import (
	"fmt"

	"github.com/casbin/gorm-adapter/v3"
	"github.com/you/authzsvc/domain"
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

// Models is the single list of tables the service reads or writes. Both startup paths migrate exactly
// this list, and TestEveryPersistedModelIsMigrated fails when a persisted model is missing from it.
// Casbin's table is created by its own adapter in AutoMigrate; sessions, OTP state and SMS budget are
// in Redis. The users table comes first (other tables refer to its ids).
func Models() []interface{} {
	return []interface{}{
		&repositories.DBUser{},                  // auth.users
		&repositories.DBPasswordHistory{},       // auth.password_history: reuse check, deletion
		&repositories.DBPasswordChangeRequest{}, // auth.password_change_requests: password change and e-mail reset requests
		&domain.ComprehensiveAuditEvent{},       // CB-183 audit events
		&domain.SecurityViolation{},             // CB-182 security violations
		&domain.ValidationRule{},                // CB-182 validation rules
		&domain.DeletionRequest{},               // LGPD deletion
		&domain.UserDataExport{},
		&domain.DeletionAuditLog{},
		&domain.DataRetentionPolicy{},
		&domain.AnonymizedUser{},
	}
}

// AutoMigrate performs database migration for all required tables: every model of Models(), the
// Casbin policy table for RBAC, and the CB-183 audit indexes.
func AutoMigrate(db *gorm.DB) error {
	for _, model := range Models() {
		if err := db.AutoMigrate(model); err != nil {
			return fmt.Errorf("failed to migrate %T: %w", model, err)
		}
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

	// CB-183: Create performance indexes for audit queries after migration
	if err := createAuditIndexes(db); err != nil {
		return fmt.Errorf("failed to create audit performance indexes: %w", err)
	}

	return nil
}

// createAuditIndexes creates performance indexes for the audit events table
func createAuditIndexes(db *gorm.DB) error {
	// Core performance indexes for CB-183 requirements
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp_desc ON auth.audit_events (timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_audit_events_user_id ON auth.audit_events (user_id) WHERE user_id IS NOT NULL",
		"CREATE INDEX IF NOT EXISTS idx_audit_events_event_type ON auth.audit_events (event_type)",
		"CREATE INDEX IF NOT EXISTS idx_audit_events_event_category ON auth.audit_events (event_category)",
		"CREATE INDEX IF NOT EXISTS idx_audit_events_session_id ON auth.audit_events (session_id) WHERE session_id != ''",
		"CREATE INDEX IF NOT EXISTS idx_audit_events_correlation_id ON auth.audit_events (correlation_id) WHERE correlation_id IS NOT NULL",
		"CREATE INDEX IF NOT EXISTS idx_audit_events_ip_address ON auth.audit_events (ip_address) WHERE ip_address IS NOT NULL",
		"CREATE INDEX IF NOT EXISTS idx_audit_events_success ON auth.audit_events (success)",
		
		// LGPD/GDPR compliance indexes
		"CREATE INDEX IF NOT EXISTS idx_audit_events_legal_basis ON auth.audit_events (legal_basis) WHERE legal_basis != ''",
		"CREATE INDEX IF NOT EXISTS idx_audit_events_data_classification ON auth.audit_events (data_classification) WHERE data_classification != ''",
		"CREATE INDEX IF NOT EXISTS idx_audit_events_retention_policy ON auth.audit_events (retention_policy) WHERE retention_policy != ''",
		
		// Security analysis indexes
		"CREATE INDEX IF NOT EXISTS idx_audit_events_security_category ON auth.audit_events (event_category) WHERE event_category = 'security'",
		"CREATE INDEX IF NOT EXISTS idx_audit_events_failed_auth ON auth.audit_events (event_type, success) WHERE event_type LIKE '%login%' AND success = false",
		
		// Composite indexes for common query patterns
		"CREATE INDEX IF NOT EXISTS idx_audit_events_user_time ON auth.audit_events (user_id, timestamp DESC) WHERE user_id IS NOT NULL",
		"CREATE INDEX IF NOT EXISTS idx_audit_events_type_time ON auth.audit_events (event_type, timestamp DESC)",
		"CREATE INDEX IF NOT EXISTS idx_audit_events_category_time ON auth.audit_events (event_category, timestamp DESC)",
		
		// GIN index for JSONB metadata searches
		"CREATE INDEX IF NOT EXISTS idx_audit_events_metadata_gin ON auth.audit_events USING gin(metadata) WHERE metadata IS NOT NULL",
		"CREATE INDEX IF NOT EXISTS idx_audit_events_request_data_gin ON auth.audit_events USING gin(request_data) WHERE request_data IS NOT NULL",
	}

	for _, indexSQL := range indexes {
		if err := db.Exec(indexSQL).Error; err != nil {
			return fmt.Errorf("failed to create index: %s, error: %w", indexSQL, err)
		}
	}

	return nil
}

// Note: Using GORM's built-in NamingStrategy with TablePrefix instead of custom implementation