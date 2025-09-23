package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// CB-183 Audit Logging System Interfaces

// ComprehensiveAuditRepository defines audit event data access operations
type ComprehensiveAuditRepository interface {
	// Core audit operations
	Create(ctx context.Context, event *ComprehensiveAuditEvent) error
	CreateBatch(ctx context.Context, events []*ComprehensiveAuditEvent) error
	FindByID(ctx context.Context, id uint64) (*ComprehensiveAuditEvent, error)
	
	// Query operations
	Query(ctx context.Context, criteria *AuditCriteria) (*AuditResults, error)
	Count(ctx context.Context, criteria *AuditCriteria) (int64, error)
	
	// Specialized queries
	FindByUser(ctx context.Context, userID uint, limit, offset int) ([]*ComprehensiveAuditEvent, error)
	FindBySession(ctx context.Context, sessionID string, limit, offset int) ([]*ComprehensiveAuditEvent, error)
	FindByCorrelationID(ctx context.Context, correlationID uuid.UUID) ([]*ComprehensiveAuditEvent, error)
	FindByTimeRange(ctx context.Context, startTime, endTime time.Time, limit, offset int) ([]*ComprehensiveAuditEvent, error)
	
	// Security queries
	FindSecurityEvents(ctx context.Context, severity SecuritySeverity, limit, offset int) ([]*ComprehensiveAuditEvent, error)
	FindFailedLogins(ctx context.Context, timeWindow time.Duration) ([]*ComprehensiveAuditEvent, error)
	FindSuspiciousActivity(ctx context.Context, ipAddress string, timeWindow time.Duration) ([]*ComprehensiveAuditEvent, error)
	
	// Compliance queries (LGPD/GDPR)
	FindDataAccessEvents(ctx context.Context, dataSubjectID uint, timeWindow time.Duration) ([]*ComprehensiveAuditEvent, error)
	FindByLegalBasis(ctx context.Context, legalBasis LegalBasis, limit, offset int) ([]*ComprehensiveAuditEvent, error)
	
	// Data retention and cleanup
	DeleteOldEvents(ctx context.Context, retentionPolicy RetentionPolicy, olderThan time.Time) (int64, error)
	ArchiveEvents(ctx context.Context, criteria *AuditCriteria) error
	
	// Performance and statistics
	GetEventStatistics(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error)
	GetUserActivitySummary(ctx context.Context, userID uint, timeRange time.Duration) (map[string]interface{}, error)
}

// ComprehensiveAuditLogger defines the main audit logging interface
type ComprehensiveAuditLogger interface {
	// Authentication event logging
	LogAuthenticationEvent(ctx context.Context, event *AuthEvent) error
	LogLoginAttempt(ctx context.Context, userID uint, email, ipAddress string, success bool, reason string) error
	LogLogout(ctx context.Context, userID uint, sessionID, ipAddress string) error
	LogPasswordReset(ctx context.Context, userID uint, ipAddress string) error
	
	// Password change event logging (CB-183 specific)
	LogPasswordChangeInitiated(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error
	LogPasswordChangeCompleted(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error
	LogPasswordChangeFailed(ctx context.Context, userID *uint, requestID, reason, ipAddress, userAgent string) error
	LogPasswordChangeCancelled(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error
	LogPasswordChangeExpired(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error
	
	// Authorization event logging  
	LogAuthorizationEvent(ctx context.Context, event *AuthzEvent) error
	LogPermissionCheck(ctx context.Context, userID uint, resource, action string, decision AuthzDecision) error
	LogAccessDenied(ctx context.Context, userID uint, resource, action, reason string) error
	
	// Data access logging (LGPD compliance)
	LogDataAccessEvent(ctx context.Context, event *DataAccessEvent) error
	LogDataRead(ctx context.Context, userID, dataSubjectID uint, dataType string, fieldsAccessed []string) error
	LogDataWrite(ctx context.Context, userID uint, dataType string, recordsAffected int) error
	LogDataExport(ctx context.Context, userID uint, exportType, legalBasis string, recordsCount int) error
	
	// Security event logging
	LogSecurityEvent(ctx context.Context, event *SecurityEvent) error
	LogSecurityViolation(ctx context.Context, eventType SecurityEventType, severity SecuritySeverity, description string, userID *uint, ipAddress string) error
	LogBruteForceAttempt(ctx context.Context, ipAddress, userAgent string, attemptCount int) error
	LogSuspiciousActivity(ctx context.Context, userID *uint, ipAddress, description string, indicators []string) error
	
	// System event logging
	LogSystemEvent(ctx context.Context, eventType string, description string, metadata map[string]interface{}) error
	LogUserRegistrationEvent(ctx context.Context, userID uint, email, phone, role string) error
	LogConfigChange(ctx context.Context, userID uint, configKey, oldValue, newValue string) error
	
	// Compliance event logging
	LogConsentEvent(ctx context.Context, userID uint, consentType, action string, legalBasis LegalBasis) error
	LogDataRetentionEvent(ctx context.Context, policy RetentionPolicy, recordsAffected int, description string) error
	
	// Query operations
	QueryEvents(ctx context.Context, criteria *AuditCriteria) (*AuditResults, error)
	ExportEvents(ctx context.Context, criteria *ExportCriteria) (*ExportResult, error)
	
	// Health and monitoring
	GetHealthStatus(ctx context.Context) (map[string]interface{}, error)
	GetMetrics(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error)
}

// DataEncryptor defines encryption operations for sensitive audit data
type DataEncryptor interface {
	// Encryption operations
	Encrypt(ctx context.Context, data []byte) ([]byte, error)
	Decrypt(ctx context.Context, encryptedData []byte) ([]byte, error)
	
	// Field-level encryption
	EncryptFields(ctx context.Context, data map[string]interface{}, sensitiveFields []string) (map[string]interface{}, error)
	DecryptFields(ctx context.Context, data map[string]interface{}, encryptedFields []string) (map[string]interface{}, error)
	
	// Key management
	RotateKeys(ctx context.Context) error
	GetKeyVersion(ctx context.Context) (string, error)
}

// IntegrityChecker defines integrity verification operations
type IntegrityChecker interface {
	// Checksum operations
	CalculateChecksum(data interface{}) (string, error)
	VerifyChecksum(data interface{}, expectedChecksum string) (bool, error)
	
	// Batch verification
	VerifyBatchIntegrity(ctx context.Context, events []*ComprehensiveAuditEvent) ([]bool, error)
	
	// Tamper detection
	DetectTampering(ctx context.Context, event *ComprehensiveAuditEvent) (bool, []string, error)
	ScanForIntegrityViolations(ctx context.Context, criteria *AuditCriteria) ([]*ComprehensiveAuditEvent, error)
}

// AsyncProcessor defines asynchronous audit processing operations
type AsyncProcessor interface {
	// Async processing
	ProcessEventAsync(ctx context.Context, event *ComprehensiveAuditEvent) error
	ProcessEventsAsync(ctx context.Context, events []*ComprehensiveAuditEvent) error
	
	// Queue management
	GetQueueStatus(ctx context.Context) (map[string]interface{}, error)
	GetProcessingStatistics(ctx context.Context) (map[string]interface{}, error)
	
	// Error handling
	GetFailedEvents(ctx context.Context, limit, offset int) ([]*ComprehensiveAuditEvent, error)
	RetryFailedEvents(ctx context.Context, maxRetries int) error
}

// AuditMetrics defines metrics collection and reporting operations
type AuditMetrics interface {
	// Performance metrics
	RecordEventProcessingTime(ctx context.Context, duration time.Duration)
	RecordEventWriteLatency(ctx context.Context, latency time.Duration)
	RecordEventQueryLatency(ctx context.Context, latency time.Duration)
	
	// Volume metrics
	IncrementEventCount(ctx context.Context, eventType string)
	IncrementSecurityEventCount(ctx context.Context, severity SecuritySeverity)
	RecordEventBatchSize(ctx context.Context, size int)
	
	// Compliance metrics
	RecordDataAccessCount(ctx context.Context, dataType string, operation DataOperation)
	RecordConsentEvent(ctx context.Context, consentType string)
	
	// Health metrics
	RecordSystemHealth(ctx context.Context, component string, healthy bool)
	RecordErrorRate(ctx context.Context, errorType string, rate float64)
	
	// Reporting
	GetMetrics(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error)
	GetComplianceReport(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error)
}

// AuditExporter defines audit data export operations
type AuditExporter interface {
	// Export operations
	ExportToJSON(ctx context.Context, events []*ComprehensiveAuditEvent) ([]byte, error)
	ExportToCSV(ctx context.Context, events []*ComprehensiveAuditEvent) ([]byte, error)
	ExportToXLSX(ctx context.Context, events []*ComprehensiveAuditEvent) ([]byte, error)
	ExportToPDF(ctx context.Context, events []*ComprehensiveAuditEvent, template string) ([]byte, error)
	
	// File operations
	CreateExportFile(ctx context.Context, format ExportFormat, data []byte, encryption bool) (*ExportResult, error)
	GetExportStatus(ctx context.Context, exportID string) (*ExportResult, error)
	CleanupExpiredExports(ctx context.Context) error
	
	// Compliance exports
	ExportForCompliance(ctx context.Context, criteria *ExportCriteria, regulation string) (*ExportResult, error)
	GenerateComplianceReport(ctx context.Context, userID uint, timeRange time.Duration) (*ExportResult, error)
}

// ComprehensiveAuditService defines the main audit service interface combining all audit operations
type ComprehensiveAuditService interface {
	ComprehensiveAuditLogger
	
	// Administrative operations
	GetAuditConfiguration(ctx context.Context) (map[string]interface{}, error)
	UpdateRetentionPolicy(ctx context.Context, policy RetentionPolicy, eventTypes []string) error
	
	// Data management
	ArchiveOldEvents(ctx context.Context, policy RetentionPolicy) (int64, error)
	PurgeEvents(ctx context.Context, criteria *AuditCriteria) (int64, error)
	
	// Security operations
	DetectAnomalies(ctx context.Context, timeRange time.Duration) ([]*ComprehensiveAuditEvent, error)
	GenerateSecurityReport(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error)
	
	// Compliance operations
	GenerateLGPDReport(ctx context.Context, dataSubjectID uint, timeRange time.Duration) (*ExportResult, error)
	TrackDataSubjectRights(ctx context.Context, dataSubjectID uint) (map[string]interface{}, error)
	
	// Health and monitoring
	PerformHealthCheck(ctx context.Context) error
	GetSystemMetrics(ctx context.Context) (map[string]interface{}, error)
}