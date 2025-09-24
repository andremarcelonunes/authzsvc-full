package domain

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// StringList is a custom type for []string that can be stored in PostgreSQL as JSONB
type StringList []string

// Value implements the driver.Valuer interface for database storage
func (s StringList) Value() (driver.Value, error) {
	if s == nil {
		return nil, nil
	}
	return json.Marshal(s)
}

// Scan implements the sql.Scanner interface for database retrieval
func (s *StringList) Scan(value interface{}) error {
	if value == nil {
		*s = nil
		return nil
	}
	
	switch v := value.(type) {
	case []byte:
		return json.Unmarshal(v, s)
	case string:
		return json.Unmarshal([]byte(v), s)
	default:
		return fmt.Errorf("cannot scan %T into StringList", value)
	}
}

// DeletionRequest represents a user deletion request for LGPD compliance
type DeletionRequest struct {
	ID                uuid.UUID              `json:"id" gorm:"type:uuid;primary_key"`
	UserID            uint                   `json:"user_id" gorm:"not null;index"`
	RequestType       DeletionRequestType    `json:"request_type" gorm:"not null"`
	Status            DeletionRequestStatus  `json:"status" gorm:"not null;index"`
	Reason            string                 `json:"reason" gorm:"type:text"`
	LegalBasis        string                 `json:"legal_basis"`
	RequestedBy       string                 `json:"requested_by" gorm:"not null"` // user/admin/system
	RequestedAt       time.Time              `json:"requested_at" gorm:"not null"`
	ProcessedAt       *time.Time             `json:"processed_at"`
	CompletedAt       *time.Time             `json:"completed_at"`
	ScheduledFor      *time.Time             `json:"scheduled_for"` // For delayed deletion
	RetentionRequired bool                   `json:"retention_required"`
	RetentionReason   string                 `json:"retention_reason"`
	RetentionUntil    *time.Time             `json:"retention_until"`
	DataExported      bool                   `json:"data_exported"`
	DataExportPath    string                 `json:"data_export_path"`
	AnonymizationLog  datatypes.JSON         `json:"anonymization_log" gorm:"type:jsonb"`
	CreatedAt         time.Time              `json:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at"`
}

// DeletionRequestType defines the type of deletion request
type DeletionRequestType string

const (
	DeletionTypeFullDelete      DeletionRequestType = "full_delete"      // Complete data erasure
	DeletionTypeSoftDelete      DeletionRequestType = "soft_delete"      // Mark as deleted, retain for legal
	DeletionTypeAnonymization   DeletionRequestType = "anonymization"    // Replace PII with anonymous data
	DeletionTypeDeactivation    DeletionRequestType = "deactivation"    // Account deactivation only
	DeletionTypeExportAndDelete DeletionRequestType = "export_delete"    // Export then delete
)

// DeletionRequestStatus represents the status of a deletion request
type DeletionRequestStatus string

const (
	DeletionStatusPending     DeletionRequestStatus = "pending"      // Awaiting processing
	DeletionStatusProcessing  DeletionRequestStatus = "processing"   // Currently being processed
	DeletionStatusCompleted   DeletionRequestStatus = "completed"    // Successfully completed
	DeletionStatusFailed      DeletionRequestStatus = "failed"       // Failed to process
	DeletionStatusScheduled   DeletionRequestStatus = "scheduled"    // Scheduled for future
	DeletionStatusCancelled   DeletionRequestStatus = "cancelled"    // Request cancelled
	DeletionStatusPartial     DeletionRequestStatus = "partial"      // Partially completed (some data retained)
)

// AnonymizationDetails contains details about data anonymization
type AnonymizationDetails struct {
	FieldsAnonymized []string               `json:"fields_anonymized"`
	Method           string                 `json:"method"` // hash, random, synthetic
	Timestamp        time.Time              `json:"timestamp"`
	OriginalDataHash string                 `json:"original_data_hash"` // For verification
	Metadata         map[string]any `json:"metadata"`
}

// UserDataExport represents exported user data for LGPD data portability
type UserDataExport struct {
	ExportID      uuid.UUID  `gorm:"type:uuid;primaryKey" json:"export_id"`
	UserID        uint       `gorm:"not null;index" json:"user_id"`
	RequestedAt   time.Time  `gorm:"not null" json:"requested_at"`
	GeneratedAt   time.Time  `json:"generated_at"`
	ExpiresAt     time.Time  `gorm:"not null" json:"expires_at"`
	Format        string     `gorm:"size:10;not null" json:"format"` // json, csv, xml
	DownloadURL   string     `gorm:"size:500" json:"download_url"`
	Checksum      string     `gorm:"size:128" json:"checksum"`
	Size          int64      `json:"size_bytes"`
	IncludedData  StringList `gorm:"type:jsonb" json:"included_data"`
	ExcludedData  StringList `gorm:"type:jsonb" json:"excluded_data"` // Data retained for legal reasons
	Downloaded    bool       `gorm:"default:false" json:"downloaded"`
	DownloadCount int        `gorm:"default:0" json:"download_count"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// DataRetentionPolicy defines retention requirements for different data types
type DataRetentionPolicy struct {
	ID              uuid.UUID     `json:"id" gorm:"type:uuid;primary_key"`
	DataType        string        `json:"data_type" gorm:"not null;uniqueIndex"`
	RetentionPeriod time.Duration `json:"retention_period"`
	LegalBasis      string        `json:"legal_basis"`
	Mandatory       bool          `json:"mandatory"`
	Description     string        `json:"description"`
	AppliesTo       StringList    `json:"applies_to" gorm:"type:jsonb"` // user types, regions, etc.
	CreatedAt       time.Time     `json:"created_at"`
	UpdatedAt       time.Time     `json:"updated_at"`
}

// ExportSearchCriteria defines search criteria for exports
type ExportSearchCriteria struct {
	UserID        *uint
	Status        *ExportStatus
	ExpiredBefore *time.Time
	CreatedAfter  *time.Time
	Limit         int
	Offset        int
}

// DeletionSearchCriteria defines search criteria for deletion requests
type DeletionSearchCriteria struct {
	UserID          *uint
	Status          DeletionRequestStatus
	ScheduledBefore *time.Time
	CreatedAfter    *time.Time
	Limit           int
	Offset          int
}

// AnonymizedUser represents a user after anonymization
type AnonymizedUser struct {
	ID                uint      `json:"id" gorm:"primary_key"`
	AnonymousID       string    `json:"anonymous_id" gorm:"uniqueIndex"` // e.g., "ANON_USER_12345"
	Email             string    `json:"email"`                            // e.g., "deleted_user_12345@anonymous.local"
	Phone             string    `json:"phone"`                            // e.g., "+00000000000"
	Role              string    `json:"role"`                             // Retained for statistics
	AccountCreatedAt  time.Time `json:"account_created_at"`               // Original creation date
	AnonymizedAt      time.Time `json:"anonymized_at"`
	RetainedForReason string    `json:"retained_for_reason"` // Legal/regulatory reason
	RetainedUntil     *time.Time `json:"retained_until"`
}

// DeletionAuditLog tracks all deletion-related activities for compliance
type DeletionAuditLog struct {
	ID             uuid.UUID              `json:"id" gorm:"type:uuid;primary_key"`
	RequestID      uuid.UUID              `json:"request_id" gorm:"not null;index"`
	UserID         uint                   `json:"user_id" gorm:"not null;index"`
	Action         string                 `json:"action" gorm:"not null"`
	PerformedBy    string                 `json:"performed_by"`
	PerformedAt    time.Time              `json:"performed_at"`
	IPAddress      string                 `json:"ip_address"`
	UserAgent      string                 `json:"user_agent"`
	Result         string                 `json:"result"`
	ErrorMessage   string                 `json:"error_message,omitempty"`
	AffectedTables []string               `json:"affected_tables" gorm:"type:jsonb"`
	RecordsDeleted map[string]int         `json:"records_deleted" gorm:"type:jsonb"`
	Metadata       datatypes.JSON `json:"metadata" gorm:"type:jsonb"`
	CreatedAt      time.Time              `json:"created_at"`
}