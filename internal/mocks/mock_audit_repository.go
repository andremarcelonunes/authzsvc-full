package mocks

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
)

// MockAuditRepository implements domain.ComprehensiveAuditRepository interface for testing
type MockAuditRepository struct {
	CreateFunc                  func(ctx context.Context, event *domain.ComprehensiveAuditEvent) error
	CreateBatchFunc             func(ctx context.Context, events []*domain.ComprehensiveAuditEvent) error
	FindByIDFunc                func(ctx context.Context, id uint64) (*domain.ComprehensiveAuditEvent, error)
	QueryFunc                   func(ctx context.Context, criteria *domain.AuditCriteria) (*domain.AuditResults, error)
	CountFunc                   func(ctx context.Context, criteria *domain.AuditCriteria) (int64, error)
	FindByUserIDFunc            func(ctx context.Context, userID uint, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error)
	FindByEventTypeFunc         func(ctx context.Context, eventType string, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error)
	FindByTimeRangeFunc         func(ctx context.Context, startTime, endTime time.Time, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error)
	FindDataAccessEventsFunc    func(ctx context.Context, dataSubjectID uint, timeRange time.Duration) ([]*domain.ComprehensiveAuditEvent, error)
	FindByLegalBasisFunc        func(ctx context.Context, legalBasis domain.LegalBasis, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error)
	FindSecurityEventsFunc      func(ctx context.Context, severity domain.SecuritySeverity, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error)
	FindFailedLoginsFunc        func(ctx context.Context, timeRange time.Duration) ([]*domain.ComprehensiveAuditEvent, error)
	GetUserActivitySummaryFunc  func(ctx context.Context, userID uint, timeRange time.Duration) (map[string]interface{}, error)
	ArchiveEventsFunc           func(ctx context.Context, criteria *domain.AuditCriteria) error
	DeleteEventsFunc            func(ctx context.Context, criteria *domain.AuditCriteria) (int64, error)
	GetStatisticsFunc           func(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error)
	GetIntegrityStatusFunc      func(ctx context.Context) (map[string]interface{}, error)
	ValidateIntegrityFunc       func(ctx context.Context, eventID uint64) (bool, error)
	
	// Additional interface methods
	FindBySessionFunc           func(ctx context.Context, sessionID string, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error)
	FindByCorrelationIDFunc     func(ctx context.Context, correlationID uuid.UUID) ([]*domain.ComprehensiveAuditEvent, error)
	FindSuspiciousActivityFunc  func(ctx context.Context, ipAddress string, timeWindow time.Duration) ([]*domain.ComprehensiveAuditEvent, error)
	DeleteOldEventsFunc         func(ctx context.Context, retentionPolicy domain.RetentionPolicy, olderThan time.Time) (int64, error)
	GetEventStatisticsFunc      func(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error)
}

// NewMockAuditRepository creates a new MockAuditRepository with default behaviors
func NewMockAuditRepository() *MockAuditRepository {
	return &MockAuditRepository{}
}

// Create creates a new audit event
func (m *MockAuditRepository) Create(ctx context.Context, event *domain.ComprehensiveAuditEvent) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, event)
	}
	// Default behavior: success, assign ID
	if event.ID == 0 {
		event.ID = 1
	}
	return nil
}

// CreateBatch creates multiple audit events in a batch
func (m *MockAuditRepository) CreateBatch(ctx context.Context, events []*domain.ComprehensiveAuditEvent) error {
	if m.CreateBatchFunc != nil {
		return m.CreateBatchFunc(ctx, events)
	}
	// Default behavior: success, assign IDs
	for i, event := range events {
		if event.ID == 0 {
			event.ID = uint64(i + 1)
		}
	}
	return nil
}

// FindByID finds an audit event by ID
func (m *MockAuditRepository) FindByID(ctx context.Context, id uint64) (*domain.ComprehensiveAuditEvent, error) {
	if m.FindByIDFunc != nil {
		return m.FindByIDFunc(ctx, id)
	}
	// Default behavior: not found
	return nil, domain.ErrAuditEventNotFound
}

// Query queries audit events with criteria
func (m *MockAuditRepository) Query(ctx context.Context, criteria *domain.AuditCriteria) (*domain.AuditResults, error) {
	if m.QueryFunc != nil {
		return m.QueryFunc(ctx, criteria)
	}
	// Default behavior: empty results
	return &domain.AuditResults{
		Events:     []domain.ComprehensiveAuditEvent{},
		Total:      0,
		HasMore:    false,
	}, nil
}

// Count counts audit events matching criteria
func (m *MockAuditRepository) Count(ctx context.Context, criteria *domain.AuditCriteria) (int64, error) {
	if m.CountFunc != nil {
		return m.CountFunc(ctx, criteria)
	}
	// Default behavior: zero count
	return 0, nil
}

// FindByUser finds audit events by user ID (interface matches FindByUser)
func (m *MockAuditRepository) FindByUser(ctx context.Context, userID uint, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
	if m.FindByUserIDFunc != nil {
		return m.FindByUserIDFunc(ctx, userID, limit, offset)
	}
	// Default behavior: empty results
	return []*domain.ComprehensiveAuditEvent{}, nil
}

// FindByEventType finds audit events by event type
func (m *MockAuditRepository) FindByEventType(ctx context.Context, eventType string, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
	if m.FindByEventTypeFunc != nil {
		return m.FindByEventTypeFunc(ctx, eventType, limit, offset)
	}
	// Default behavior: empty results
	return []*domain.ComprehensiveAuditEvent{}, nil
}

// FindByTimeRange finds audit events in time range
func (m *MockAuditRepository) FindByTimeRange(ctx context.Context, startTime, endTime time.Time, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
	if m.FindByTimeRangeFunc != nil {
		return m.FindByTimeRangeFunc(ctx, startTime, endTime, limit, offset)
	}
	// Default behavior: empty results
	return []*domain.ComprehensiveAuditEvent{}, nil
}

// FindDataAccessEvents finds data access events for LGPD compliance
func (m *MockAuditRepository) FindDataAccessEvents(ctx context.Context, dataSubjectID uint, timeRange time.Duration) ([]*domain.ComprehensiveAuditEvent, error) {
	if m.FindDataAccessEventsFunc != nil {
		return m.FindDataAccessEventsFunc(ctx, dataSubjectID, timeRange)
	}
	// Default behavior: empty results
	return []*domain.ComprehensiveAuditEvent{}, nil
}

// FindByLegalBasis finds events by legal basis
func (m *MockAuditRepository) FindByLegalBasis(ctx context.Context, legalBasis domain.LegalBasis, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
	if m.FindByLegalBasisFunc != nil {
		return m.FindByLegalBasisFunc(ctx, legalBasis, limit, offset)
	}
	// Default behavior: empty results
	return []*domain.ComprehensiveAuditEvent{}, nil
}

// FindSecurityEvents finds security events
func (m *MockAuditRepository) FindSecurityEvents(ctx context.Context, severity domain.SecuritySeverity, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
	if m.FindSecurityEventsFunc != nil {
		return m.FindSecurityEventsFunc(ctx, severity, limit, offset)
	}
	// Default behavior: empty results
	return []*domain.ComprehensiveAuditEvent{}, nil
}

// FindFailedLogins finds failed login attempts
func (m *MockAuditRepository) FindFailedLogins(ctx context.Context, timeRange time.Duration) ([]*domain.ComprehensiveAuditEvent, error) {
	if m.FindFailedLoginsFunc != nil {
		return m.FindFailedLoginsFunc(ctx, timeRange)
	}
	// Default behavior: empty results
	return []*domain.ComprehensiveAuditEvent{}, nil
}

// GetUserActivitySummary gets user activity summary
func (m *MockAuditRepository) GetUserActivitySummary(ctx context.Context, userID uint, timeRange time.Duration) (map[string]interface{}, error) {
	if m.GetUserActivitySummaryFunc != nil {
		return m.GetUserActivitySummaryFunc(ctx, userID, timeRange)
	}
	// Default behavior: empty summary
	return map[string]interface{}{
		"user_id":       userID,
		"total_events":  0,
		"login_count":   0,
		"data_access":   0,
	}, nil
}

// ArchiveEvents archives old events
func (m *MockAuditRepository) ArchiveEvents(ctx context.Context, criteria *domain.AuditCriteria) error {
	if m.ArchiveEventsFunc != nil {
		return m.ArchiveEventsFunc(ctx, criteria)
	}
	// Default behavior: success
	return nil
}

// DeleteEvents deletes events (dangerous operation)
func (m *MockAuditRepository) DeleteEvents(ctx context.Context, criteria *domain.AuditCriteria) (int64, error) {
	if m.DeleteEventsFunc != nil {
		return m.DeleteEventsFunc(ctx, criteria)
	}
	// Default behavior: zero deleted
	return 0, nil
}

// GetStatistics gets audit statistics
func (m *MockAuditRepository) GetStatistics(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error) {
	if m.GetStatisticsFunc != nil {
		return m.GetStatisticsFunc(ctx, timeRange)
	}
	// Default behavior: basic stats
	return map[string]interface{}{
		"total_events":      0,
		"success_rate":      0.0,
		"most_active_users": []interface{}{},
	}, nil
}

// GetIntegrityStatus gets integrity check status
func (m *MockAuditRepository) GetIntegrityStatus(ctx context.Context) (map[string]interface{}, error) {
	if m.GetIntegrityStatusFunc != nil {
		return m.GetIntegrityStatusFunc(ctx)
	}
	// Default behavior: healthy status
	return map[string]interface{}{
		"status":           "healthy",
		"verified_events":  0,
		"integrity_errors": 0,
	}, nil
}

// ValidateIntegrity validates event integrity
func (m *MockAuditRepository) ValidateIntegrity(ctx context.Context, eventID uint64) (bool, error) {
	if m.ValidateIntegrityFunc != nil {
		return m.ValidateIntegrityFunc(ctx, eventID)
	}
	// Default behavior: valid integrity
	return true, nil
}

// FindBySession finds audit events by session ID
func (m *MockAuditRepository) FindBySession(ctx context.Context, sessionID string, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
	if m.FindBySessionFunc != nil {
		return m.FindBySessionFunc(ctx, sessionID, limit, offset)
	}
	// Default behavior: empty results
	return []*domain.ComprehensiveAuditEvent{}, nil
}

// FindByCorrelationID finds audit events by correlation ID
func (m *MockAuditRepository) FindByCorrelationID(ctx context.Context, correlationID uuid.UUID) ([]*domain.ComprehensiveAuditEvent, error) {
	if m.FindByCorrelationIDFunc != nil {
		return m.FindByCorrelationIDFunc(ctx, correlationID)
	}
	// Default behavior: empty results
	return []*domain.ComprehensiveAuditEvent{}, nil
}

// FindSuspiciousActivity finds suspicious activity events
func (m *MockAuditRepository) FindSuspiciousActivity(ctx context.Context, ipAddress string, timeWindow time.Duration) ([]*domain.ComprehensiveAuditEvent, error) {
	if m.FindSuspiciousActivityFunc != nil {
		return m.FindSuspiciousActivityFunc(ctx, ipAddress, timeWindow)
	}
	// Default behavior: empty results
	return []*domain.ComprehensiveAuditEvent{}, nil
}

// DeleteOldEvents deletes old events based on retention policy
func (m *MockAuditRepository) DeleteOldEvents(ctx context.Context, retentionPolicy domain.RetentionPolicy, olderThan time.Time) (int64, error) {
	if m.DeleteOldEventsFunc != nil {
		return m.DeleteOldEventsFunc(ctx, retentionPolicy, olderThan)
	}
	// Default behavior: zero deleted
	return 0, nil
}

// GetEventStatistics gets event statistics
func (m *MockAuditRepository) GetEventStatistics(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error) {
	if m.GetEventStatisticsFunc != nil {
		return m.GetEventStatisticsFunc(ctx, timeRange)
	}
	// Default behavior: basic stats
	return map[string]interface{}{
		"total_events":      0,
		"success_rate":      0.0,
		"most_active_users": []interface{}{},
	}, nil
}

// Compile-time interface compliance verification
var _ domain.ComprehensiveAuditRepository = (*MockAuditRepository)(nil)