package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
)

// CB-183 Audit Logging System Domain Entities

// ComprehensiveAuditEvent represents a comprehensive audit event for security and compliance
// Extends the existing AuditEvent with additional CB-183 features
type ComprehensiveAuditEvent struct {
	ID             uint64                 `json:"id" gorm:"primaryKey;autoIncrement"`
	EventType      string                 `json:"event_type" gorm:"not null;index;size:50"`
	EventCategory  AuditEventCategory     `json:"event_category" gorm:"not null;index;size:30"`
	Timestamp      time.Time              `json:"timestamp" gorm:"not null;default:CURRENT_TIMESTAMP;index"`
	
	// User context
	UserID         *uint                  `json:"user_id,omitempty" gorm:"index"`
	SessionID      string                 `json:"session_id,omitempty" gorm:"index;size:128"`
	IPAddress      string                 `json:"ip_address,omitempty" gorm:"type:inet"`
	UserAgent      string                 `json:"user_agent,omitempty" gorm:"type:text"`
	
	// Event details
	Success        bool                   `json:"success" gorm:"not null;default:true"`
	ResourceType   string                 `json:"resource_type,omitempty" gorm:"size:50"`
	ResourceID     string                 `json:"resource_id,omitempty" gorm:"size:128"`
	Action         string                 `json:"action" gorm:"not null;size:50"`
	
	// LGPD/GDPR compliance fields
	LegalBasis       LegalBasis           `json:"legal_basis,omitempty" gorm:"size:50"`
	DataClassification DataClassification `json:"data_classification,omitempty" gorm:"size:30"`
	RetentionPolicy  RetentionPolicy      `json:"retention_policy,omitempty" gorm:"size:50"`
	
	// Event data (encrypted for sensitive information)
	Metadata       datatypes.JSON `json:"metadata,omitempty" gorm:"type:jsonb"`
	RequestData    datatypes.JSON `json:"request_data,omitempty" gorm:"type:jsonb"`
	ResponseData   datatypes.JSON `json:"response_data,omitempty" gorm:"type:jsonb"`
	ErrorDetails   string                 `json:"error_details,omitempty" gorm:"type:text"`
	
	// Correlation and tracing
	CorrelationID  uuid.UUID              `json:"correlation_id,omitempty" gorm:"type:uuid;index"`
	
	// Security and integrity
	Checksum       string                 `json:"checksum,omitempty" gorm:"size:64"`
	EncryptedFields datatypes.JSON `json:"encrypted_fields,omitempty" gorm:"type:jsonb"`
	
	// Audit metadata
	CreatedAt      time.Time              `json:"created_at" gorm:"autoCreateTime;not null"`
	UpdatedAt      time.Time              `json:"updated_at" gorm:"autoUpdateTime;not null"`
}

// AuditEventCategory groups related audit events
type AuditEventCategory string

const (
	CategoryAuthentication AuditEventCategory = "authentication"
	CategoryAuthorization  AuditEventCategory = "authorization"
	CategoryDataAccess     AuditEventCategory = "data_access"
	CategoryAuditSecurity  AuditEventCategory = "security" // Renamed to avoid conflict
	CategorySystem         AuditEventCategory = "system"
	CategoryCompliance     AuditEventCategory = "compliance"
)

// CB-183 Event Types (extending existing AuditEventType)
const (
	// Authentication events (compatible with existing)
	EventTypeLoginAttempt     = "login_attempt"
	EventTypeLoginSuccess     = "login_success"
	EventTypeLoginFailure     = "login_failure"
	EventTypeLogout           = "logout"
	EventTypePasswordReset    = "password_reset"
	EventTypeAccountLocked    = "account_locked"
	
	// Authorization events
	EventTypePermissionCheck  = "permission_check"
	EventTypeAccessDenied     = "access_denied"
	EventTypeAccessGranted    = "access_granted"
	EventTypeRoleChange       = "role_change"
	
	// Data access events (LGPD compliance)
	EventTypeDataRead         = "data_read"
	EventTypeDataWrite        = "data_write"
	EventTypeDataUpdate       = "data_update"
	EventTypeDataDelete       = "data_delete"
	EventTypeDataExport       = "data_export"
	
	// Security events
	EventTypeSecurityViolation = "security_violation"
	EventTypeSuspiciousActivity = "suspicious_activity"
	EventTypeBruteForceDetected = "brute_force_detected"
	EventTypeValidationFailure  = "validation_failure"
	
	// System events
	EventTypeSystemStartup    = "system_startup"
	EventTypeSystemShutdown   = "system_shutdown"
	EventTypeConfigChange     = "config_change"
	
	// Compliance events
	EventTypeConsentGranted   = "consent_granted"
	EventTypeConsentRevoked   = "consent_revoked"
	EventTypeDataRetention    = "data_retention"
	EventTypeDataPurge        = "data_purge"
)

// LegalBasis defines LGPD/GDPR legal basis for data processing
type LegalBasis string

const (
	LegalBasisConsent        LegalBasis = "consent"
	LegalBasisContract       LegalBasis = "contract"
	LegalBasisLegalObligation LegalBasis = "legal_obligation"
	LegalBasisVitalInterests LegalBasis = "vital_interests"
	LegalBasisPublicTask     LegalBasis = "public_task"
	LegalBasisLegitimateInterests LegalBasis = "legitimate_interests"
)

// DataClassification defines sensitivity levels of data
type DataClassification string

const (
	DataClassificationPublic    DataClassification = "public"
	DataClassificationInternal  DataClassification = "internal"
	DataClassificationConfidential DataClassification = "confidential"
	DataClassificationRestricted DataClassification = "restricted"
	DataClassificationPII       DataClassification = "pii" // Personally Identifiable Information
	DataClassificationSensitive DataClassification = "sensitive"
)

// RetentionPolicy defines how long audit data should be retained
type RetentionPolicy string

const (
	RetentionPolicyShort   RetentionPolicy = "short"   // 30 days
	RetentionPolicyMedium  RetentionPolicy = "medium"  // 1 year
	RetentionPolicyLong    RetentionPolicy = "long"    // 7 years
	RetentionPolicyPermanent RetentionPolicy = "permanent"
	RetentionPolicyLegal   RetentionPolicy = "legal"   // As required by law
)

// AuthEvent represents authentication-specific audit information
type AuthEvent struct {
	UserID          uint                   `json:"user_id"`
	Email           string                 `json:"email,omitempty"`
	Action          string                 `json:"action"`
	Success         bool                   `json:"success"`
	FailureReason   string                 `json:"failure_reason,omitempty"`
	SessionID       string                 `json:"session_id,omitempty"`
	IPAddress       string                 `json:"ip_address"`
	UserAgent       string                 `json:"user_agent,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// AuthzEvent represents authorization-specific audit information
type AuthzEvent struct {
	UserID          uint                   `json:"user_id"`
	Role            string                 `json:"role"`
	Resource        string                 `json:"resource"`
	Action          string                 `json:"action"`
	Decision        AuthzDecision          `json:"decision"`
	PolicyApplied   string                 `json:"policy_applied,omitempty"`
	IPAddress       string                 `json:"ip_address"`
	SessionID       string                 `json:"session_id,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// AuthzDecision represents authorization decision outcomes
type AuthzDecision string

const (
	AuthzDecisionAllow AuthzDecision = "allow"
	AuthzDecisionDeny  AuthzDecision = "deny"
	AuthzDecisionError AuthzDecision = "error"
)

// DataAccessEvent represents data access audit information for LGPD compliance
type DataAccessEvent struct {
	UserID             uint                   `json:"user_id"`
	DataSubjectID      *uint                  `json:"data_subject_id,omitempty"` // Who's data was accessed
	DataType           string                 `json:"data_type"`
	Operation          DataOperation          `json:"operation"`
	LegalBasis         LegalBasis             `json:"legal_basis"`
	ConsentID          string                 `json:"consent_id,omitempty"`
	DataClassification DataClassification     `json:"data_classification"`
	FieldsAccessed     []string               `json:"fields_accessed"`
	RecordsCount       int                    `json:"records_count"`
	IPAddress          string                 `json:"ip_address"`
	SessionID          string                 `json:"session_id,omitempty"`
	Timestamp          time.Time              `json:"timestamp"`
	Purpose            string                 `json:"purpose,omitempty"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
}

// DataOperation defines types of data operations
type DataOperation string

const (
	DataOperationRead   DataOperation = "read"
	DataOperationWrite  DataOperation = "write"
	DataOperationUpdate DataOperation = "update"
	DataOperationDelete DataOperation = "delete"
	DataOperationExport DataOperation = "export"
	DataOperationImport DataOperation = "import"
)

// SecurityEvent represents security-related audit information
type SecurityEvent struct {
	EventType       SecurityEventType      `json:"event_type"`
	Severity        SecuritySeverity       `json:"severity"`
	Description     string                 `json:"description"`
	UserID          *uint                  `json:"user_id,omitempty"`
	IPAddress       string                 `json:"ip_address"`
	UserAgent       string                 `json:"user_agent,omitempty"`
	SessionID       string                 `json:"session_id,omitempty"`
	ThreatIndicators []string              `json:"threat_indicators,omitempty"`
	ActionTaken     SecurityAction         `json:"action_taken"`
	BlockedRequest  map[string]interface{} `json:"blocked_request,omitempty"`
	Timestamp       time.Time              `json:"timestamp"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// SecurityEventType defines types of security events
type SecurityEventType string

const (
	SecurityEventTypeXSS              SecurityEventType = "xss_attempt"
	SecurityEventTypeSQLInjection     SecurityEventType = "sql_injection"
	SecurityEventTypePathTraversal    SecurityEventType = "path_traversal"
	SecurityEventTypeBruteForce       SecurityEventType = "brute_force"
	SecurityEventTypeRateLimitExceeded SecurityEventType = "rate_limit_exceeded"
	SecurityEventTypeSuspiciousRequest SecurityEventType = "suspicious_request"
	SecurityEventTypeIntegrityViolation SecurityEventType = "integrity_violation"
	SecurityEventTypeUnauthorizedAccess SecurityEventType = "unauthorized_access"
)

// SecuritySeverity defines security event severity levels
type SecuritySeverity string

const (
	SecuritySeverityLow      SecuritySeverity = "low"
	SecuritySeverityMedium   SecuritySeverity = "medium"
	SecuritySeverityHigh     SecuritySeverity = "high"
	SecuritySeverityCritical SecuritySeverity = "critical"
)

// SecurityAction defines actions taken in response to security events
type SecurityAction string

const (
	SecurityActionLog       SecurityAction = "log"
	SecurityActionWarn      SecurityAction = "warn"
	SecurityActionBlock     SecurityAction = "block"
	SecurityActionSanitize  SecurityAction = "sanitize"
	SecurityActionAlert     SecurityAction = "alert"
	SecurityActionBan       SecurityAction = "ban"
)

// AuditCriteria represents search/filter criteria for audit events
type AuditCriteria struct {
	// Time range
	StartTime   *time.Time `json:"start_time,omitempty"`
	EndTime     *time.Time `json:"end_time,omitempty"`
	
	// Event filters
	EventTypes     []string               `json:"event_types,omitempty"`
	EventCategories []AuditEventCategory `json:"event_categories,omitempty"`
	Success        *bool                `json:"success,omitempty"`
	
	// User filters
	UserIDs        []uint               `json:"user_ids,omitempty"`
	SessionIDs     []string             `json:"session_ids,omitempty"`
	IPAddresses    []string             `json:"ip_addresses,omitempty"`
	
	// Resource filters
	ResourceTypes  []string             `json:"resource_types,omitempty"`
	ResourceIDs    []string             `json:"resource_ids,omitempty"`
	Actions        []string             `json:"actions,omitempty"`
	
	// Compliance filters
	LegalBases     []LegalBasis         `json:"legal_bases,omitempty"`
	DataClassifications []DataClassification `json:"data_classifications,omitempty"`
	
	// Security filters
	SecurityEvents  bool                `json:"security_events,omitempty"`
	MinSeverity    *SecuritySeverity    `json:"min_severity,omitempty"`
	
	// Pagination
	Limit          int                  `json:"limit"`
	Offset         int                  `json:"offset"`
	OrderBy        string               `json:"order_by"`
	OrderDirection string               `json:"order_direction"`
}

// AuditResults represents the result of audit query operations
type AuditResults struct {
	Events     []ComprehensiveAuditEvent `json:"events"`
	Total      int64                     `json:"total"`
	Page       int                       `json:"page"`
	PageSize   int                       `json:"page_size"`
	TotalPages int                       `json:"total_pages"`
	HasMore    bool                      `json:"has_more"`
}

// ExportCriteria represents criteria for exporting audit data
type ExportCriteria struct {
	AuditCriteria
	Format        ExportFormat `json:"format"`
	IncludeFields []string     `json:"include_fields,omitempty"`
	ExcludeFields []string     `json:"exclude_fields,omitempty"`
	Encryption    bool         `json:"encryption"`
	MaxRecords    int          `json:"max_records"`
}

// ExportFormat defines supported export formats
type ExportFormat string

const (
	ExportFormatJSON ExportFormat = "json"
	ExportFormatCSV  ExportFormat = "csv"
	ExportFormatXLSX ExportFormat = "xlsx"
	ExportFormatPDF  ExportFormat = "pdf"
)

// ExportResult represents the result of audit data export
type ExportResult struct {
	ExportID     string          `json:"export_id"`
	Format       ExportFormat    `json:"format"`
	RecordsCount int             `json:"records_count"`
	FileSize     int64           `json:"file_size"`
	FilePath     string          `json:"file_path,omitempty"`
	DownloadURL  string          `json:"download_url,omitempty"`
	ExpiresAt    time.Time       `json:"expires_at"`
	Checksum     string          `json:"checksum"`
	Encrypted    bool            `json:"encrypted"`
	CreatedAt    time.Time       `json:"created_at"`
	Status       ExportStatus    `json:"status"`
	Error        string          `json:"error,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// ExportStatus defines export operation status
type ExportStatus string

const (
	ExportStatusPending    ExportStatus = "pending"
	ExportStatusProcessing ExportStatus = "processing"
	ExportStatusCompleted  ExportStatus = "completed"
	ExportStatusFailed     ExportStatus = "failed"
	ExportStatusExpired    ExportStatus = "expired"
)

// TableName returns the table name for ComprehensiveAuditEvent GORM model
func (ComprehensiveAuditEvent) TableName() string {
	return "audit_events"
}

// CalculateChecksum generates a checksum for integrity verification
func (ae *ComprehensiveAuditEvent) CalculateChecksum() string {
	// Create a consistent string representation for checksum calculation
	data := struct {
		EventType    string    `json:"event_type"`
		Timestamp    time.Time `json:"timestamp"`
		UserID       *uint     `json:"user_id"`
		SessionID    string    `json:"session_id"`
		Action       string    `json:"action"`
		Success      bool      `json:"success"`
		ResourceType string    `json:"resource_type"`
		ResourceID   string    `json:"resource_id"`
	}{
		EventType:    ae.EventType,
		Timestamp:    ae.Timestamp,
		UserID:       ae.UserID,
		SessionID:    ae.SessionID,
		Action:       ae.Action,
		Success:      ae.Success,
		ResourceType: ae.ResourceType,
		ResourceID:   ae.ResourceID,
	}
	
	jsonData, _ := json.Marshal(data)
	hash := sha256.Sum256(jsonData)
	return hex.EncodeToString(hash[:])
}

// VerifyIntegrity verifies the integrity of the audit event
func (ae *ComprehensiveAuditEvent) VerifyIntegrity() bool {
	calculatedChecksum := ae.CalculateChecksum()
	return ae.Checksum == calculatedChecksum
}

// SetCorrelationID sets a new correlation ID for the audit event
func (ae *ComprehensiveAuditEvent) SetCorrelationID() {
	ae.CorrelationID = uuid.New()
}

// BeforeCreate GORM hook to set checksum and correlation ID before saving
func (ae *ComprehensiveAuditEvent) BeforeCreate() error {
	if ae.CorrelationID == uuid.Nil {
		ae.SetCorrelationID()
	}
	ae.Checksum = ae.CalculateChecksum()
	return nil
}