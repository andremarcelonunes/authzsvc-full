package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/config"
	"gorm.io/datatypes"
)

// ComprehensiveAuditServiceImpl implements domain.ComprehensiveAuditService
type ComprehensiveAuditServiceImpl struct {
	repo           domain.ComprehensiveAuditRepository
	encryptor      domain.DataEncryptor
	integrityCheck domain.IntegrityChecker
	asyncProcessor domain.AsyncProcessor
	metrics        domain.AuditMetrics
	exporter       domain.AuditExporter
	config         *config.Config
	logger         *slog.Logger
}

// NewComprehensiveAuditService creates a new comprehensive audit service
func NewComprehensiveAuditService(
	repo domain.ComprehensiveAuditRepository,
	encryptor domain.DataEncryptor,
	integrityCheck domain.IntegrityChecker,
	asyncProcessor domain.AsyncProcessor,
	metrics domain.AuditMetrics,
	exporter domain.AuditExporter,
	config *config.Config,
	logger *slog.Logger,
) domain.ComprehensiveAuditService {
	return &ComprehensiveAuditServiceImpl{
		repo:           repo,
		encryptor:      encryptor,
		integrityCheck: integrityCheck,
		asyncProcessor: asyncProcessor,
		metrics:        metrics,
		exporter:       exporter,
		config:         config,
		logger:         logger,
	}
}

// toJSON converts a map[string]interface{} to datatypes.JSON
func toJSON(data map[string]interface{}) datatypes.JSON {
	if data == nil {
		return nil
	}
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		// If marshaling fails, return empty JSON object
		return datatypes.JSON("{}")
	}
	return jsonBytes
}

// Authentication event logging implementations

// LogAuthenticationEvent implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogAuthenticationEvent(ctx context.Context, event *domain.AuthEvent) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     event.Action,
		EventCategory: domain.CategoryAuthentication,
		Timestamp:     event.Timestamp,
		UserID:        &event.UserID,
		SessionID:     event.SessionID,
		IPAddress:     event.IPAddress,
		UserAgent:     event.UserAgent,
		Success:       event.Success,
		Action:        event.Action,
		ErrorDetails:  event.FailureReason,
		Metadata: toJSON(map[string]interface{}{
			"email":          event.Email,
			"failure_reason": event.FailureReason,
			"additional_metadata": event.Metadata,
		}),
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationInternal,
		RetentionPolicy:    domain.RetentionPolicyMedium,
	}

	return s.createEvent(ctx, auditEvent)
}

// LogLoginAttempt implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogLoginAttempt(ctx context.Context, userID uint, email, ipAddress string, success bool, reason string) error {
	eventType := domain.EventTypeLoginSuccess
	if !success {
		eventType = domain.EventTypeLoginFailure
	}

	// Default IP address for empty values (required for inet type)
	if ipAddress == "" {
		ipAddress = "0.0.0.0"
	}

	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     eventType,
		EventCategory: domain.CategoryAuthentication,
		Timestamp:     time.Now().UTC(),
		UserID:        &userID,
		IPAddress:     ipAddress,
		Success:       success,
		Action:        "login",
		ErrorDetails:  reason,
		Metadata: toJSON(map[string]interface{}{
			"email":          email,
			"failure_reason": reason,
		}),
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationInternal,
		RetentionPolicy:    domain.RetentionPolicyMedium,
	}

	return s.createEvent(ctx, auditEvent)
}

// LogLogout implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogLogout(ctx context.Context, userID uint, sessionID, ipAddress string) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     domain.EventTypeLogout,
		EventCategory: domain.CategoryAuthentication,
		Timestamp:     time.Now().UTC(),
		UserID:        &userID,
		SessionID:     sessionID,
		IPAddress:     ipAddress,
		Success:       true,
		Action:        "logout",
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationInternal,
		RetentionPolicy:    domain.RetentionPolicyMedium,
	}

	return s.createEvent(ctx, auditEvent)
}

// LogPasswordReset implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogPasswordReset(ctx context.Context, userID uint, ipAddress string) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     domain.EventTypePasswordReset,
		EventCategory: domain.CategoryAuthentication,
		Timestamp:     time.Now().UTC(),
		UserID:        &userID,
		IPAddress:     ipAddress,
		Success:       true,
		Action:        "password_reset",
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationConfidential,
		RetentionPolicy:    domain.RetentionPolicyLong,
	}

	return s.createEvent(ctx, auditEvent)
}

// LogPasswordChangeInitiated logs when a password change process is initiated
func (s *ComprehensiveAuditServiceImpl) LogPasswordChangeInitiated(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error {
	metadata := map[string]interface{}{
		"request_id": requestID,
		"user_agent": userAgent,
		"action":     "password_change_initiated",
	}
	
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:          domain.EventTypePasswordChangeInitiated,
		EventCategory:      domain.CategoryAuthentication,
		Timestamp:          time.Now().UTC(),
		UserID:             &userID,
		IPAddress:          ipAddress,
		UserAgent:          userAgent,
		Success:            true,
		Action:             "password_change_initiate",
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationConfidential,
		RetentionPolicy:    domain.RetentionPolicyLong,
		Metadata:           toJSON(metadata),
	}

	return s.createEvent(ctx, auditEvent)
}

// LogPasswordChangeCompleted logs when a password change process is successfully completed
func (s *ComprehensiveAuditServiceImpl) LogPasswordChangeCompleted(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error {
	metadata := map[string]interface{}{
		"request_id":         requestID,
		"user_agent":         userAgent,
		"action":             "password_change_completed",
		"sessions_invalidated": true,
	}
	
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:          domain.EventTypePasswordChangeCompleted,
		EventCategory:      domain.CategoryAuthentication,
		Timestamp:          time.Now().UTC(),
		UserID:             &userID,
		IPAddress:          ipAddress,
		UserAgent:          userAgent,
		Success:            true,
		Action:             "password_change_complete",
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationConfidential,
		RetentionPolicy:    domain.RetentionPolicyLong,
		Metadata:           toJSON(metadata),
	}

	return s.createEvent(ctx, auditEvent)
}

// LogPasswordChangeFailed logs when a password change process fails
func (s *ComprehensiveAuditServiceImpl) LogPasswordChangeFailed(ctx context.Context, userID *uint, requestID, reason, ipAddress, userAgent string) error {
	metadata := map[string]interface{}{
		"request_id": requestID,
		"user_agent": userAgent,
		"action":     "password_change_failed",
		"reason":     reason,
	}
	
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:          domain.EventTypePasswordChangeFailed,
		EventCategory:      domain.CategoryAuthentication,
		Timestamp:          time.Now().UTC(),
		UserID:             userID,
		IPAddress:          ipAddress,
		UserAgent:          userAgent,
		Success:            false,
		Action:             "password_change_failed",
		ErrorDetails:       reason,
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationConfidential,
		RetentionPolicy:    domain.RetentionPolicyLong,
		Metadata:           toJSON(metadata),
	}

	return s.createEvent(ctx, auditEvent)
}

// LogPasswordChangeCancelled logs when a password change process is cancelled by the user
func (s *ComprehensiveAuditServiceImpl) LogPasswordChangeCancelled(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error {
	metadata := map[string]interface{}{
		"request_id": requestID,
		"user_agent": userAgent,
		"action":     "password_change_cancelled",
	}
	
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:          domain.EventTypePasswordChangeCancelled,
		EventCategory:      domain.CategoryAuthentication,
		Timestamp:          time.Now().UTC(),
		UserID:             &userID,
		IPAddress:          ipAddress,
		UserAgent:          userAgent,
		Success:            true,
		Action:             "password_change_cancel",
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationConfidential,
		RetentionPolicy:    domain.RetentionPolicyLong,
		Metadata:           toJSON(metadata),
	}

	return s.createEvent(ctx, auditEvent)
}

// LogPasswordChangeExpired logs when a password change request expires
func (s *ComprehensiveAuditServiceImpl) LogPasswordChangeExpired(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error {
	metadata := map[string]interface{}{
		"request_id": requestID,
		"user_agent": userAgent,
		"action":     "password_change_expired",
	}
	
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:          domain.EventTypePasswordChangeExpired,
		EventCategory:      domain.CategoryAuthentication,
		Timestamp:          time.Now().UTC(),
		UserID:             &userID,
		IPAddress:          ipAddress,
		UserAgent:          userAgent,
		Success:            false,
		Action:             "password_change_expired",
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationConfidential,
		RetentionPolicy:    domain.RetentionPolicyLong,
		Metadata:           toJSON(metadata),
	}

	return s.createEvent(ctx, auditEvent)
}

// Authorization event logging implementations

// LogAuthorizationEvent implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogAuthorizationEvent(ctx context.Context, event *domain.AuthzEvent) error {
	eventType := domain.EventTypeAccessGranted
	if event.Decision == domain.AuthzDecisionDeny {
		eventType = domain.EventTypeAccessDenied
	}

	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     eventType,
		EventCategory: domain.CategoryAuthorization,
		Timestamp:     event.Timestamp,
		UserID:        &event.UserID,
		SessionID:     event.SessionID,
		IPAddress:     event.IPAddress,
		Success:       event.Decision == domain.AuthzDecisionAllow,
		ResourceType:  "api_endpoint",
		ResourceID:    event.Resource,
		Action:        event.Action,
		Metadata: toJSON(map[string]interface{}{
			"role":           event.Role,
			"decision":       string(event.Decision),
			"policy_applied": event.PolicyApplied,
			"additional_metadata": event.Metadata,
		}),
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationInternal,
		RetentionPolicy:    domain.RetentionPolicyMedium,
	}

	return s.createEvent(ctx, auditEvent)
}

// LogPermissionCheck implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogPermissionCheck(ctx context.Context, userID uint, resource, action string, decision domain.AuthzDecision) error {
	eventType := domain.EventTypePermissionCheck
	if decision == domain.AuthzDecisionDeny {
		eventType = domain.EventTypeAccessDenied
	}

	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     eventType,
		EventCategory: domain.CategoryAuthorization,
		Timestamp:     time.Now().UTC(),
		UserID:        &userID,
		Success:       decision == domain.AuthzDecisionAllow,
		ResourceType:  "api_endpoint",
		ResourceID:    resource,
		Action:        action,
		Metadata: toJSON(map[string]interface{}{
			"decision": string(decision),
		}),
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationInternal,
		RetentionPolicy:    domain.RetentionPolicyMedium,
	}

	return s.createEvent(ctx, auditEvent)
}

// LogAccessDenied implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogAccessDenied(ctx context.Context, userID uint, resource, action, reason string) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     domain.EventTypeAccessDenied,
		EventCategory: domain.CategoryAuthorization,
		Timestamp:     time.Now().UTC(),
		UserID:        &userID,
		Success:       false,
		ResourceType:  "api_endpoint",
		ResourceID:    resource,
		Action:        action,
		ErrorDetails:  reason,
		Metadata: toJSON(map[string]interface{}{
			"denial_reason": reason,
		}),
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationInternal,
		RetentionPolicy:    domain.RetentionPolicyMedium,
	}

	return s.createEvent(ctx, auditEvent)
}

// Data access logging implementations (LGPD compliance)

// LogDataAccessEvent implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogDataAccessEvent(ctx context.Context, event *domain.DataAccessEvent) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     string(event.Operation),
		EventCategory: domain.CategoryDataAccess,
		Timestamp:     event.Timestamp,
		UserID:        &event.UserID,
		SessionID:     event.SessionID,
		IPAddress:     event.IPAddress,
		Success:       true,
		ResourceType:  event.DataType,
		Action:        string(event.Operation),
		Metadata: toJSON(map[string]interface{}{
			"data_subject_id":     event.DataSubjectID,
			"data_type":           event.DataType,
			"fields_accessed":     event.FieldsAccessed,
			"records_count":       event.RecordsCount,
			"purpose":             event.Purpose,
			"consent_id":          event.ConsentID,
			"additional_metadata": event.Metadata,
		}),
		LegalBasis:         event.LegalBasis,
		DataClassification: event.DataClassification,
		RetentionPolicy:    domain.RetentionPolicyLegal, // LGPD compliance requires longer retention
	}

	return s.createEvent(ctx, auditEvent)
}

// LogDataRead implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogDataRead(ctx context.Context, userID, dataSubjectID uint, dataType string, fieldsAccessed []string) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     domain.EventTypeDataRead,
		EventCategory: domain.CategoryDataAccess,
		Timestamp:     time.Now().UTC(),
		UserID:        &userID,
		Success:       true,
		ResourceType:  dataType,
		Action:        "read",
		Metadata: toJSON(map[string]interface{}{
			"data_subject_id": dataSubjectID,
			"fields_accessed": fieldsAccessed,
		}),
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationPII,
		RetentionPolicy:    domain.RetentionPolicyLegal,
	}

	return s.createEvent(ctx, auditEvent)
}

// LogDataWrite implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogDataWrite(ctx context.Context, userID uint, dataType string, recordsAffected int) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     domain.EventTypeDataWrite,
		EventCategory: domain.CategoryDataAccess,
		Timestamp:     time.Now().UTC(),
		UserID:        &userID,
		Success:       true,
		ResourceType:  dataType,
		Action:        "write",
		Metadata: toJSON(map[string]interface{}{
			"records_affected": recordsAffected,
		}),
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationPII,
		RetentionPolicy:    domain.RetentionPolicyLegal,
	}

	return s.createEvent(ctx, auditEvent)
}

// LogDataExport implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogDataExport(ctx context.Context, userID uint, exportType, legalBasis string, recordsCount int) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     domain.EventTypeDataExport,
		EventCategory: domain.CategoryDataAccess,
		Timestamp:     time.Now().UTC(),
		UserID:        &userID,
		Success:       true,
		ResourceType:  "data_export",
		Action:        "export",
		Metadata: toJSON(map[string]interface{}{
			"export_type":    exportType,
			"records_count":  recordsCount,
			"legal_basis":    legalBasis,
		}),
		LegalBasis:         domain.LegalBasis(legalBasis),
		DataClassification: domain.DataClassificationPII,
		RetentionPolicy:    domain.RetentionPolicyLegal,
	}

	return s.createEvent(ctx, auditEvent)
}

// Security event logging implementations

// LogSecurityEvent implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogSecurityEvent(ctx context.Context, event *domain.SecurityEvent) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     string(event.EventType),
		EventCategory: domain.CategoryAuditSecurity,
		Timestamp:     event.Timestamp,
		UserID:        event.UserID,
		SessionID:     event.SessionID,
		IPAddress:     event.IPAddress,
		UserAgent:     event.UserAgent,
		Success:       false, // Security events are typically failures or violations
		Action:        string(event.EventType),
		ErrorDetails:  event.Description,
		Metadata: toJSON(map[string]interface{}{
			"severity":           string(event.Severity),
			"threat_indicators":  event.ThreatIndicators,
			"action_taken":       string(event.ActionTaken),
			"blocked_request":    event.BlockedRequest,
			"additional_metadata": event.Metadata,
		}),
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationConfidential,
		RetentionPolicy:    domain.RetentionPolicyLong,
	}

	return s.createEvent(ctx, auditEvent)
}

// LogSecurityViolation implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogSecurityViolation(ctx context.Context, eventType domain.SecurityEventType, severity domain.SecuritySeverity, description string, userID *uint, ipAddress string) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     domain.EventTypeSecurityViolation,
		EventCategory: domain.CategoryAuditSecurity,
		Timestamp:     time.Now().UTC(),
		UserID:        userID,
		IPAddress:     ipAddress,
		Success:       false,
		Action:        string(eventType),
		ErrorDetails:  description,
		Metadata: toJSON(map[string]interface{}{
			"violation_type": string(eventType),
			"severity":       string(severity),
		}),
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationConfidential,
		RetentionPolicy:    domain.RetentionPolicyLong,
	}

	return s.createEvent(ctx, auditEvent)
}

// LogBruteForceAttempt implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogBruteForceAttempt(ctx context.Context, ipAddress, userAgent string, attemptCount int) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     domain.EventTypeBruteForceDetected,
		EventCategory: domain.CategoryAuditSecurity,
		Timestamp:     time.Now().UTC(),
		IPAddress:     ipAddress,
		UserAgent:     userAgent,
		Success:       false,
		Action:        "brute_force_attempt",
		ErrorDetails:  fmt.Sprintf("Brute force attack detected: %d attempts", attemptCount),
		Metadata: toJSON(map[string]interface{}{
			"attempt_count": attemptCount,
			"severity":      string(domain.SecuritySeverityHigh),
		}),
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationConfidential,
		RetentionPolicy:    domain.RetentionPolicyLong,
	}

	return s.createEvent(ctx, auditEvent)
}

// LogSuspiciousActivity implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogSuspiciousActivity(ctx context.Context, userID *uint, ipAddress, description string, indicators []string) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     domain.EventTypeSuspiciousActivity,
		EventCategory: domain.CategoryAuditSecurity,
		Timestamp:     time.Now().UTC(),
		UserID:        userID,
		IPAddress:     ipAddress,
		Success:       false,
		Action:        "suspicious_activity",
		ErrorDetails:  description,
		Metadata: toJSON(map[string]interface{}{
			"threat_indicators": indicators,
			"severity":          string(domain.SecuritySeverityMedium),
		}),
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationConfidential,
		RetentionPolicy:    domain.RetentionPolicyLong,
	}

	return s.createEvent(ctx, auditEvent)
}

// System event logging implementations

// LogSystemEvent implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogSystemEvent(ctx context.Context, eventType string, description string, metadata map[string]interface{}) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     eventType,
		EventCategory: domain.CategorySystem,
		Timestamp:     time.Now().UTC(),
		IPAddress:     "127.0.0.1", // Default IP for system events
		Success:       true,
		Action:        eventType,
		ErrorDetails:  description,
		Metadata:      toJSON(metadata),
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationInternal,
		RetentionPolicy:    domain.RetentionPolicyMedium,
	}

	return s.createEvent(ctx, auditEvent)
}

// LogUserRegistrationEvent implements domain.ComprehensiveAuditService
func (s *ComprehensiveAuditServiceImpl) LogUserRegistrationEvent(ctx context.Context, userID uint, email, phone, role string) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     "user_registration_success",
		EventCategory: domain.CategoryAuthentication,
		Timestamp:     time.Now().UTC(),
		UserID:        &userID,
		IPAddress:     "127.0.0.1", // Default IP for registration events
		Success:       true,
		Action:        "user_registration",
		ErrorDetails:  fmt.Sprintf("Successfully registered user with email %s", email),
		Metadata: toJSON(map[string]interface{}{
			"email": email,
			"phone": phone,
			"role":  role,
		}),
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationInternal,
		RetentionPolicy:    domain.RetentionPolicyMedium,
	}

	return s.createEvent(ctx, auditEvent)
}

// LogConfigChange implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogConfigChange(ctx context.Context, userID uint, configKey, oldValue, newValue string) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     domain.EventTypeConfigChange,
		EventCategory: domain.CategorySystem,
		Timestamp:     time.Now().UTC(),
		UserID:        &userID,
		Success:       true,
		Action:        "config_change",
		Metadata: toJSON(map[string]interface{}{
			"config_key":  configKey,
			"old_value":   oldValue,
			"new_value":   newValue,
		}),
		LegalBasis:         domain.LegalBasisLegitimateInterests,
		DataClassification: domain.DataClassificationConfidential,
		RetentionPolicy:    domain.RetentionPolicyLong,
	}

	return s.createEvent(ctx, auditEvent)
}

// Compliance event logging implementations

// LogConsentEvent implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogConsentEvent(ctx context.Context, userID uint, consentType, action string, legalBasis domain.LegalBasis) error {
	eventType := domain.EventTypeConsentGranted
	if action == "revoke" {
		eventType = domain.EventTypeConsentRevoked
	}

	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     eventType,
		EventCategory: domain.CategoryCompliance,
		Timestamp:     time.Now().UTC(),
		UserID:        &userID,
		Success:       true,
		Action:        action,
		Metadata: toJSON(map[string]interface{}{
			"consent_type": consentType,
			"action":       action,
		}),
		LegalBasis:         legalBasis,
		DataClassification: domain.DataClassificationPII,
		RetentionPolicy:    domain.RetentionPolicyLegal,
	}

	return s.createEvent(ctx, auditEvent)
}

// LogDataRetentionEvent implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) LogDataRetentionEvent(ctx context.Context, policy domain.RetentionPolicy, recordsAffected int, description string) error {
	auditEvent := &domain.ComprehensiveAuditEvent{
		EventType:     domain.EventTypeDataRetention,
		EventCategory: domain.CategoryCompliance,
		Timestamp:     time.Now().UTC(),
		Success:       true,
		Action:        "data_retention",
		ErrorDetails:  description,
		Metadata: toJSON(map[string]interface{}{
			"retention_policy":  string(policy),
			"records_affected":  recordsAffected,
		}),
		LegalBasis:         domain.LegalBasisLegalObligation,
		DataClassification: domain.DataClassificationInternal,
		RetentionPolicy:    domain.RetentionPolicyLegal,
	}

	return s.createEvent(ctx, auditEvent)
}

// Query operations implementations

// QueryEvents implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) QueryEvents(ctx context.Context, criteria *domain.AuditCriteria) (*domain.AuditResults, error) {
	startTime := time.Now()
	defer func() {
		if s.metrics != nil {
			s.metrics.RecordEventQueryLatency(ctx, time.Since(startTime))
		}
	}()

	return s.repo.Query(ctx, criteria)
}

// ExportEvents implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) ExportEvents(ctx context.Context, criteria *domain.ExportCriteria) (*domain.ExportResult, error) {
	if s.exporter == nil {
		return nil, fmt.Errorf("audit exporter not configured")
	}

	// Query events based on criteria
	results, err := s.QueryEvents(ctx, &criteria.AuditCriteria)
	if err != nil {
		return nil, fmt.Errorf("failed to query events for export: %w", err)
	}

	// Convert events to pointer slice for exporter
	eventPtrs := make([]*domain.ComprehensiveAuditEvent, len(results.Events))
	for i := range results.Events {
		eventPtrs[i] = &results.Events[i]
	}

	// Export based on format
	var data []byte
	switch criteria.Format {
	case domain.ExportFormatJSON:
		data, err = s.exporter.ExportToJSON(ctx, eventPtrs)
	case domain.ExportFormatCSV:
		data, err = s.exporter.ExportToCSV(ctx, eventPtrs)
	case domain.ExportFormatXLSX:
		data, err = s.exporter.ExportToXLSX(ctx, eventPtrs)
	case domain.ExportFormatPDF:
		data, err = s.exporter.ExportToPDF(ctx, eventPtrs, "default")
	default:
		return nil, fmt.Errorf("unsupported export format: %s", criteria.Format)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to export data: %w", err)
	}

	// Create export file
	return s.exporter.CreateExportFile(ctx, criteria.Format, data, criteria.Encryption)
}

// Health and monitoring implementations

// GetHealthStatus implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) GetHealthStatus(ctx context.Context) (map[string]interface{}, error) {
	status := map[string]interface{}{
		"status":     "healthy",
		"timestamp":  time.Now().UTC(),
		"components": map[string]interface{}{},
	}

	components := status["components"].(map[string]interface{})

	// Check repository health
	if s.repo != nil {
		// Try a simple count query to test database connectivity
		_, err := s.repo.Count(ctx, &domain.AuditCriteria{Limit: 1})
		if err != nil {
			components["repository"] = map[string]interface{}{
				"status": "unhealthy",
				"error":  err.Error(),
			}
			status["status"] = "degraded"
		} else {
			components["repository"] = map[string]interface{}{
				"status": "healthy",
			}
		}
	}

	// Check async processor health
	if s.asyncProcessor != nil {
		queueStatus, err := s.asyncProcessor.GetQueueStatus(ctx)
		if err != nil {
			components["async_processor"] = map[string]interface{}{
				"status": "unhealthy",
				"error":  err.Error(),
			}
			status["status"] = "degraded"
		} else {
			components["async_processor"] = map[string]interface{}{
				"status":      "healthy",
				"queue_stats": queueStatus,
			}
		}
	}

	return status, nil
}

// GetMetrics implements domain.ComprehensiveAuditLogger
func (s *ComprehensiveAuditServiceImpl) GetMetrics(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error) {
	if s.metrics == nil {
		return map[string]interface{}{
			"error": "metrics not configured",
		}, nil
	}

	return s.metrics.GetMetrics(ctx, timeRange)
}

// Administrative operations implementations

// GetAuditConfiguration implements domain.ComprehensiveAuditService
func (s *ComprehensiveAuditServiceImpl) GetAuditConfiguration(ctx context.Context) (map[string]interface{}, error) {
	config := map[string]interface{}{
		"encryption_enabled":     s.encryptor != nil,
		"integrity_check_enabled": s.integrityCheck != nil,
		"async_processing_enabled": s.asyncProcessor != nil,
		"metrics_enabled":        s.metrics != nil,
		"export_enabled":         s.exporter != nil,
	}

	if s.config != nil {
		config["validation_config"] = s.config.ValidationConfig
	}

	return config, nil
}

// UpdateRetentionPolicy implements domain.ComprehensiveAuditService
func (s *ComprehensiveAuditServiceImpl) UpdateRetentionPolicy(ctx context.Context, policy domain.RetentionPolicy, eventTypes []string) error {
	// In a real implementation, this would update the retention policy configuration
	// For now, we'll log the change
	return s.LogSystemEvent(ctx, domain.EventTypeConfigChange, 
		fmt.Sprintf("Updated retention policy to %s for event types: %v", policy, eventTypes),
		map[string]interface{}{
			"retention_policy": string(policy),
			"event_types":      eventTypes,
		})
}

// Data management implementations

// ArchiveOldEvents implements domain.ComprehensiveAuditService
func (s *ComprehensiveAuditServiceImpl) ArchiveOldEvents(ctx context.Context, policy domain.RetentionPolicy) (int64, error) {
	var cutoffDate time.Time
	now := time.Now().UTC()

	switch policy {
	case domain.RetentionPolicyShort:
		cutoffDate = now.AddDate(0, 0, -30) // 30 days
	case domain.RetentionPolicyMedium:
		cutoffDate = now.AddDate(-1, 0, 0) // 1 year
	case domain.RetentionPolicyLong:
		cutoffDate = now.AddDate(-7, 0, 0) // 7 years
	default:
		return 0, fmt.Errorf("invalid retention policy: %s", policy)
	}

	criteria := &domain.AuditCriteria{
		EndTime: &cutoffDate,
	}

	err := s.repo.ArchiveEvents(ctx, criteria)
	if err != nil {
		return 0, err
	}

	// Count archived events
	count, err := s.repo.Count(ctx, criteria)
	if err != nil {
		return 0, err
	}

	// Log the archival
	s.LogDataRetentionEvent(ctx, policy, int(count), 
		fmt.Sprintf("Archived %d events older than %v", count, cutoffDate))

	return count, nil
}

// PurgeEvents implements domain.ComprehensiveAuditService
func (s *ComprehensiveAuditServiceImpl) PurgeEvents(ctx context.Context, criteria *domain.AuditCriteria) (int64, error) {
	// This is a dangerous operation - in production, would require additional authorization
	count, err := s.repo.Count(ctx, criteria)
	if err != nil {
		return 0, err
	}

	// Log the purge before doing it
	s.LogDataRetentionEvent(ctx, domain.RetentionPolicyLegal, int(count), 
		fmt.Sprintf("Purging %d audit events", count))

	// Note: Actual purge implementation would depend on specific criteria
	// For now, we return the count that would be purged
	return count, nil
}

// Compliance operations stubs (would be implemented based on specific requirements)

// GenerateLGPDReport implements domain.ComprehensiveAuditService
func (s *ComprehensiveAuditServiceImpl) GenerateLGPDReport(ctx context.Context, dataSubjectID uint, timeRange time.Duration) (*domain.ExportResult, error) {
	// Query all data access events for the subject
	_, err := s.repo.FindDataAccessEvents(ctx, dataSubjectID, timeRange)
	if err != nil {
		return nil, err
	}

	if s.exporter == nil {
		return nil, fmt.Errorf("exporter not configured")
	}

	// Generate compliance report
	return s.exporter.GenerateComplianceReport(ctx, dataSubjectID, timeRange)
}

// TrackDataSubjectRights implements domain.ComprehensiveAuditService
func (s *ComprehensiveAuditServiceImpl) TrackDataSubjectRights(ctx context.Context, dataSubjectID uint) (map[string]interface{}, error) {
	return s.repo.GetUserActivitySummary(ctx, dataSubjectID, 24*time.Hour)
}

// Security operations stubs

// DetectAnomalies implements domain.ComprehensiveAuditService
func (s *ComprehensiveAuditServiceImpl) DetectAnomalies(ctx context.Context, timeRange time.Duration) ([]*domain.ComprehensiveAuditEvent, error) {
	// Simple anomaly detection - look for failed logins
	return s.repo.FindFailedLogins(ctx, timeRange)
}

// GenerateSecurityReport implements domain.ComprehensiveAuditService
func (s *ComprehensiveAuditServiceImpl) GenerateSecurityReport(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error) {
	// Find security events
	securityEvents, err := s.repo.FindSecurityEvents(ctx, "", 100, 0)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"time_range":      timeRange.String(),
		"security_events": len(securityEvents),
		"events":          securityEvents,
	}, nil
}

// Health and monitoring

// PerformHealthCheck implements domain.ComprehensiveAuditService
func (s *ComprehensiveAuditServiceImpl) PerformHealthCheck(ctx context.Context) error {
	status, err := s.GetHealthStatus(ctx)
	if err != nil {
		return err
	}

	if status["status"] != "healthy" {
		return fmt.Errorf("audit service health check failed: %v", status)
	}

	return nil
}

// GetSystemMetrics implements domain.ComprehensiveAuditService
func (s *ComprehensiveAuditServiceImpl) GetSystemMetrics(ctx context.Context) (map[string]interface{}, error) {
	if s.metrics == nil {
		return map[string]interface{}{
			"error": "metrics not configured",
		}, nil
	}

	return s.metrics.GetMetrics(ctx, time.Hour)
}

// Private helper methods

// createEvent creates and processes an audit event
func (s *ComprehensiveAuditServiceImpl) createEvent(ctx context.Context, event *domain.ComprehensiveAuditEvent) error {
	startTime := time.Now()
	defer func() {
		if s.metrics != nil {
			s.metrics.RecordEventProcessingTime(ctx, time.Since(startTime))
			s.metrics.IncrementEventCount(ctx, event.EventType)
		}
	}()

	// Encrypt sensitive fields if encryptor is available
	if s.encryptor != nil && event.Metadata != nil {
		// Convert datatypes.JSON back to map for encryptor
		var metadataMap map[string]interface{}
		if err := json.Unmarshal(event.Metadata, &metadataMap); err == nil {
			encryptedFields, err := s.encryptor.EncryptFields(ctx, metadataMap, []string{"email", "phone", "personal_data"})
			if err != nil {
				// Only log if logger is available
				if s.logger != nil {
					s.logger.Error("Failed to encrypt sensitive fields", "error", err)
				}
			} else {
				event.EncryptedFields = toJSON(encryptedFields)
			}
		}
	}

	// Use async processing if available
	if s.asyncProcessor != nil {
		return s.asyncProcessor.ProcessEventAsync(ctx, event)
	}

	// Fallback to synchronous processing
	return s.repo.Create(ctx, event)
}