package mocks

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
)

// MockComprehensiveAuditService provides a mock implementation of domain.ComprehensiveAuditService
type MockComprehensiveAuditService struct {
	// Track method calls for verification
	LoggedEvents []MockAuditEvent
	
	// Function fields for configurable behavior
	LogAuthenticationEventFunc func(ctx context.Context, event *domain.AuthEvent) error
	LogLoginAttemptFunc        func(ctx context.Context, userID uint, email, ipAddress string, success bool, reason string) error
	LogLogoutFunc              func(ctx context.Context, userID uint, sessionID, ipAddress string) error
	LogPasswordResetFunc       func(ctx context.Context, userID uint, ipAddress string) error
	
	// Password change event logging functions (CB-183)
	LogPasswordChangeInitiatedFunc func(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error
	LogPasswordChangeCompletedFunc func(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error
	LogPasswordChangeFailedFunc    func(ctx context.Context, userID *uint, requestID, reason, ipAddress, userAgent string) error
	LogPasswordChangeCancelledFunc func(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error
	LogPasswordChangeExpiredFunc   func(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error
	
	LogSystemEventFunc         func(ctx context.Context, eventType string, description string, metadata map[string]interface{}) error
	LogUserRegistrationEventFunc func(ctx context.Context, userID uint, email, phone, role string) error
	LogConfigChangeFunc        func(ctx context.Context, userID uint, configKey, oldValue, newValue string) error
	
	// Other methods can be added as needed
}

// MockAuditEvent represents a logged audit event for testing validation
type MockAuditEvent struct {
	EventType   string
	UserID      uint
	Success     bool
	Description string
	Metadata    map[string]interface{}
	Timestamp   time.Time
}

// NewMockComprehensiveAuditService creates a new mock audit service
func NewMockComprehensiveAuditService() *MockComprehensiveAuditService {
	return &MockComprehensiveAuditService{
		LoggedEvents: make([]MockAuditEvent, 0),
	}
}

// LogAuthenticationEvent implements domain.ComprehensiveAuditService
func (m *MockComprehensiveAuditService) LogAuthenticationEvent(ctx context.Context, event *domain.AuthEvent) error {
	if m.LogAuthenticationEventFunc != nil {
		return m.LogAuthenticationEventFunc(ctx, event)
	}
	return nil
}

// LogLoginAttempt implements domain.ComprehensiveAuditService
func (m *MockComprehensiveAuditService) LogLoginAttempt(ctx context.Context, userID uint, email, ipAddress string, success bool, reason string) error {
	// Track the call
	m.LoggedEvents = append(m.LoggedEvents, MockAuditEvent{
		EventType:   "login_attempt",
		UserID:      userID,
		Success:     success,
		Description: reason,
		Metadata: map[string]interface{}{
			"email":      email,
			"ip_address": ipAddress,
		},
		Timestamp: time.Now(),
	})
	
	if m.LogLoginAttemptFunc != nil {
		return m.LogLoginAttemptFunc(ctx, userID, email, ipAddress, success, reason)
	}
	return nil
}

// LogLogout implements domain.ComprehensiveAuditService
func (m *MockComprehensiveAuditService) LogLogout(ctx context.Context, userID uint, sessionID, ipAddress string) error {
	if m.LogLogoutFunc != nil {
		return m.LogLogoutFunc(ctx, userID, sessionID, ipAddress)
	}
	return nil
}

// LogPasswordReset implements domain.ComprehensiveAuditService
func (m *MockComprehensiveAuditService) LogPasswordReset(ctx context.Context, userID uint, ipAddress string) error {
	if m.LogPasswordResetFunc != nil {
		return m.LogPasswordResetFunc(ctx, userID, ipAddress)
	}
	return nil
}

// LogPasswordChangeInitiated implements domain.ComprehensiveAuditService
func (m *MockComprehensiveAuditService) LogPasswordChangeInitiated(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error {
	// Track the call
	m.LoggedEvents = append(m.LoggedEvents, MockAuditEvent{
		EventType:   "password_change_initiated",
		UserID:      userID,
		Success:     true,
		Description: "Password change initiated",
		Metadata: map[string]interface{}{
			"request_id":  requestID,
			"ip_address":  ipAddress,
			"user_agent":  userAgent,
		},
		Timestamp: time.Now(),
	})
	
	if m.LogPasswordChangeInitiatedFunc != nil {
		return m.LogPasswordChangeInitiatedFunc(ctx, userID, requestID, ipAddress, userAgent)
	}
	return nil
}

// LogPasswordChangeCompleted implements domain.ComprehensiveAuditService
func (m *MockComprehensiveAuditService) LogPasswordChangeCompleted(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error {
	// Track the call
	m.LoggedEvents = append(m.LoggedEvents, MockAuditEvent{
		EventType:   "password_change_completed",
		UserID:      userID,
		Success:     true,
		Description: "Password change completed successfully",
		Metadata: map[string]interface{}{
			"request_id":  requestID,
			"ip_address":  ipAddress,
			"user_agent":  userAgent,
		},
		Timestamp: time.Now(),
	})
	
	if m.LogPasswordChangeCompletedFunc != nil {
		return m.LogPasswordChangeCompletedFunc(ctx, userID, requestID, ipAddress, userAgent)
	}
	return nil
}

// LogPasswordChangeFailed implements domain.ComprehensiveAuditService
func (m *MockComprehensiveAuditService) LogPasswordChangeFailed(ctx context.Context, userID *uint, requestID, reason, ipAddress, userAgent string) error {
	// Track the call
	var trackUserID uint
	if userID != nil {
		trackUserID = *userID
	}
	
	m.LoggedEvents = append(m.LoggedEvents, MockAuditEvent{
		EventType:   "password_change_failed",
		UserID:      trackUserID,
		Success:     false,
		Description: reason,
		Metadata: map[string]interface{}{
			"request_id":  requestID,
			"ip_address":  ipAddress,
			"user_agent":  userAgent,
			"reason":      reason,
		},
		Timestamp: time.Now(),
	})
	
	if m.LogPasswordChangeFailedFunc != nil {
		return m.LogPasswordChangeFailedFunc(ctx, userID, requestID, reason, ipAddress, userAgent)
	}
	return nil
}

// LogPasswordChangeCancelled implements domain.ComprehensiveAuditService
func (m *MockComprehensiveAuditService) LogPasswordChangeCancelled(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error {
	// Track the call
	m.LoggedEvents = append(m.LoggedEvents, MockAuditEvent{
		EventType:   "password_change_cancelled",
		UserID:      userID,
		Success:     true,
		Description: "Password change cancelled by user",
		Metadata: map[string]interface{}{
			"request_id":  requestID,
			"ip_address":  ipAddress,
			"user_agent":  userAgent,
		},
		Timestamp: time.Now(),
	})
	
	if m.LogPasswordChangeCancelledFunc != nil {
		return m.LogPasswordChangeCancelledFunc(ctx, userID, requestID, ipAddress, userAgent)
	}
	return nil
}

// LogPasswordChangeExpired implements domain.ComprehensiveAuditService
func (m *MockComprehensiveAuditService) LogPasswordChangeExpired(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error {
	// Track the call
	m.LoggedEvents = append(m.LoggedEvents, MockAuditEvent{
		EventType:   "password_change_expired",
		UserID:      userID,
		Success:     false,
		Description: "Password change request expired",
		Metadata: map[string]interface{}{
			"request_id":  requestID,
			"ip_address":  ipAddress,
			"user_agent":  userAgent,
		},
		Timestamp: time.Now(),
	})
	
	if m.LogPasswordChangeExpiredFunc != nil {
		return m.LogPasswordChangeExpiredFunc(ctx, userID, requestID, ipAddress, userAgent)
	}
	return nil
}

// LogSystemEvent implements domain.ComprehensiveAuditService
func (m *MockComprehensiveAuditService) LogSystemEvent(ctx context.Context, eventType string, description string, metadata map[string]interface{}) error {
	// Track the call
	m.LoggedEvents = append(m.LoggedEvents, MockAuditEvent{
		EventType:   eventType,
		Success:     true, // System events are typically successful
		Description: description,
		Metadata:    metadata,
		Timestamp:   time.Now(),
	})
	
	if m.LogSystemEventFunc != nil {
		return m.LogSystemEventFunc(ctx, eventType, description, metadata)
	}
	return nil
}

// LogUserRegistrationEvent implements domain.ComprehensiveAuditService
func (m *MockComprehensiveAuditService) LogUserRegistrationEvent(ctx context.Context, userID uint, email, phone, role string) error {
	// Track the call
	m.LoggedEvents = append(m.LoggedEvents, MockAuditEvent{
		EventType:   "user_registration_success",
		UserID:      userID,
		Success:     true,
		Description: "User registration",
		Timestamp:   time.Now(),
	})
	
	if m.LogUserRegistrationEventFunc != nil {
		return m.LogUserRegistrationEventFunc(ctx, userID, email, phone, role)
	}
	return nil
}

// LogConfigChange implements domain.ComprehensiveAuditService
func (m *MockComprehensiveAuditService) LogConfigChange(ctx context.Context, userID uint, configKey, oldValue, newValue string) error {
	if m.LogConfigChangeFunc != nil {
		return m.LogConfigChangeFunc(ctx, userID, configKey, oldValue, newValue)
	}
	return nil
}

// Stub implementations for other required methods
func (m *MockComprehensiveAuditService) LogAuthorizationEvent(ctx context.Context, event *domain.AuthzEvent) error {
	return nil
}

func (m *MockComprehensiveAuditService) LogPermissionCheck(ctx context.Context, userID uint, resource, action string, decision domain.AuthzDecision) error {
	return nil
}

func (m *MockComprehensiveAuditService) LogAccessDenied(ctx context.Context, userID uint, resource, action, reason string) error {
	return nil
}

func (m *MockComprehensiveAuditService) LogDataAccessEvent(ctx context.Context, event *domain.DataAccessEvent) error {
	return nil
}

func (m *MockComprehensiveAuditService) LogDataRead(ctx context.Context, userID, dataSubjectID uint, dataType string, fieldsAccessed []string) error {
	return nil
}

func (m *MockComprehensiveAuditService) LogDataWrite(ctx context.Context, userID uint, dataType string, recordsAffected int) error {
	return nil
}

func (m *MockComprehensiveAuditService) LogDataExport(ctx context.Context, userID uint, exportType, legalBasis string, recordsCount int) error {
	return nil
}

func (m *MockComprehensiveAuditService) LogSecurityEvent(ctx context.Context, event *domain.SecurityEvent) error {
	return nil
}

func (m *MockComprehensiveAuditService) LogSecurityViolation(ctx context.Context, eventType domain.SecurityEventType, severity domain.SecuritySeverity, description string, userID *uint, ipAddress string) error {
	return nil
}

func (m *MockComprehensiveAuditService) LogBruteForceAttempt(ctx context.Context, ipAddress, userAgent string, attemptCount int) error {
	return nil
}

func (m *MockComprehensiveAuditService) LogSuspiciousActivity(ctx context.Context, userID *uint, ipAddress, description string, indicators []string) error {
	return nil
}

func (m *MockComprehensiveAuditService) LogConsentEvent(ctx context.Context, userID uint, consentType, action string, legalBasis domain.LegalBasis) error {
	return nil
}

func (m *MockComprehensiveAuditService) LogDataRetentionEvent(ctx context.Context, policy domain.RetentionPolicy, recordsAffected int, description string) error {
	return nil
}

func (m *MockComprehensiveAuditService) QueryEvents(ctx context.Context, criteria *domain.AuditCriteria) (*domain.AuditResults, error) {
	return &domain.AuditResults{}, nil
}

func (m *MockComprehensiveAuditService) ExportEvents(ctx context.Context, criteria *domain.ExportCriteria) (*domain.ExportResult, error) {
	return &domain.ExportResult{}, nil
}

func (m *MockComprehensiveAuditService) GetHealthStatus(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{"status": "healthy"}, nil
}

func (m *MockComprehensiveAuditService) GetMetrics(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}

func (m *MockComprehensiveAuditService) GetAuditConfiguration(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}

func (m *MockComprehensiveAuditService) UpdateRetentionPolicy(ctx context.Context, policy domain.RetentionPolicy, eventTypes []string) error {
	return nil
}

func (m *MockComprehensiveAuditService) ArchiveOldEvents(ctx context.Context, policy domain.RetentionPolicy) (int64, error) {
	return 0, nil
}

func (m *MockComprehensiveAuditService) PurgeEvents(ctx context.Context, criteria *domain.AuditCriteria) (int64, error) {
	return 0, nil
}

func (m *MockComprehensiveAuditService) DetectAnomalies(ctx context.Context, timeRange time.Duration) ([]*domain.ComprehensiveAuditEvent, error) {
	return []*domain.ComprehensiveAuditEvent{}, nil
}

func (m *MockComprehensiveAuditService) GenerateSecurityReport(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}

func (m *MockComprehensiveAuditService) GenerateLGPDReport(ctx context.Context, dataSubjectID uint, timeRange time.Duration) (*domain.ExportResult, error) {
	return &domain.ExportResult{}, nil
}

func (m *MockComprehensiveAuditService) TrackDataSubjectRights(ctx context.Context, dataSubjectID uint) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}

func (m *MockComprehensiveAuditService) PerformHealthCheck(ctx context.Context) error {
	return nil
}

func (m *MockComprehensiveAuditService) GetSystemMetrics(ctx context.Context) (map[string]interface{}, error) {
	return map[string]interface{}{}, nil
}

// Helper methods for testing

// GetEventCount returns the number of logged events
func (m *MockComprehensiveAuditService) GetEventCount() int {
	return len(m.LoggedEvents)
}

// GetEventsOfType returns all logged events of a specific type
func (m *MockComprehensiveAuditService) GetEventsOfType(eventType string) []MockAuditEvent {
	var events []MockAuditEvent
	for _, event := range m.LoggedEvents {
		if event.EventType == eventType {
			events = append(events, event)
		}
	}
	return events
}

// Reset clears all logged events
func (m *MockComprehensiveAuditService) Reset() {
	m.LoggedEvents = m.LoggedEvents[:0]
}