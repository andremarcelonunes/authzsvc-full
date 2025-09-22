package repositories

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
	"gorm.io/gorm"
)

// ComprehensiveAuditRepositoryImpl implements domain.ComprehensiveAuditRepository using GORM
type ComprehensiveAuditRepositoryImpl struct {
	db *gorm.DB
}

// NewComprehensiveAuditRepository creates a new audit repository
func NewComprehensiveAuditRepository(db *gorm.DB) domain.ComprehensiveAuditRepository {
	return &ComprehensiveAuditRepositoryImpl{db: db}
}

// Create implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) Create(ctx context.Context, event *domain.ComprehensiveAuditEvent) error {
	// Set timestamp if not already set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	
	// Ensure correlation ID is set
	if event.CorrelationID == uuid.Nil {
		event.SetCorrelationID()
	}
	
	return r.db.WithContext(ctx).Create(event).Error
}

// CreateBatch implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) CreateBatch(ctx context.Context, events []*domain.ComprehensiveAuditEvent) error {
	if len(events) == 0 {
		return nil
	}
	
	// Set timestamps and correlation IDs for all events
	now := time.Now().UTC()
	for _, event := range events {
		if event.Timestamp.IsZero() {
			event.Timestamp = now
		}
		if event.CorrelationID == uuid.Nil {
			event.SetCorrelationID()
		}
	}
	
	// Use batch insert for better performance
	return r.db.WithContext(ctx).CreateInBatches(events, 100).Error
}

// FindByID implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) FindByID(ctx context.Context, id uint64) (*domain.ComprehensiveAuditEvent, error) {
	var event domain.ComprehensiveAuditEvent
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&event).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, fmt.Errorf("audit event with id %d not found", id)
		}
		return nil, err
	}
	return &event, nil
}

// Query implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) Query(ctx context.Context, criteria *domain.AuditCriteria) (*domain.AuditResults, error) {
	query := r.db.WithContext(ctx).Model(&domain.ComprehensiveAuditEvent{})
	
	// Apply filters
	query = r.applyFilters(query, criteria)
	
	// Get total count
	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, fmt.Errorf("failed to count audit events: %w", err)
	}
	
	// Apply pagination and ordering
	query = r.applyPagination(query, criteria)
	
	// Execute query
	var events []domain.ComprehensiveAuditEvent
	if err := query.Find(&events).Error; err != nil {
		return nil, fmt.Errorf("failed to query audit events: %w", err)
	}
	
	// Calculate pagination info
	pageSize := criteria.Limit
	if pageSize == 0 {
		pageSize = 50 // default page size
	}
	
	page := (criteria.Offset / pageSize) + 1
	totalPages := int((total + int64(pageSize) - 1) / int64(pageSize))
	hasMore := criteria.Offset+len(events) < int(total)
	
	return &domain.AuditResults{
		Events:     events,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
		TotalPages: totalPages,
		HasMore:    hasMore,
	}, nil
}

// Count implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) Count(ctx context.Context, criteria *domain.AuditCriteria) (int64, error) {
	query := r.db.WithContext(ctx).Model(&domain.ComprehensiveAuditEvent{})
	query = r.applyFilters(query, criteria)
	
	var count int64
	err := query.Count(&count).Error
	return count, err
}

// FindByUser implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) FindByUser(ctx context.Context, userID uint, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
	var events []*domain.ComprehensiveAuditEvent
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&events).Error
	return events, err
}

// FindBySession implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) FindBySession(ctx context.Context, sessionID string, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
	var events []*domain.ComprehensiveAuditEvent
	err := r.db.WithContext(ctx).
		Where("session_id = ?", sessionID).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&events).Error
	return events, err
}

// FindByCorrelationID implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) FindByCorrelationID(ctx context.Context, correlationID uuid.UUID) ([]*domain.ComprehensiveAuditEvent, error) {
	var events []*domain.ComprehensiveAuditEvent
	err := r.db.WithContext(ctx).
		Where("correlation_id = ?", correlationID).
		Order("timestamp ASC").
		Find(&events).Error
	return events, err
}

// FindByTimeRange implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) FindByTimeRange(ctx context.Context, startTime, endTime time.Time, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
	var events []*domain.ComprehensiveAuditEvent
	err := r.db.WithContext(ctx).
		Where("timestamp BETWEEN ? AND ?", startTime, endTime).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&events).Error
	return events, err
}

// FindSecurityEvents implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) FindSecurityEvents(ctx context.Context, severity domain.SecuritySeverity, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
	var events []*domain.ComprehensiveAuditEvent
	query := r.db.WithContext(ctx).
		Where("event_category = ?", domain.CategoryAuditSecurity)
	
	if severity != "" {
		// Security events store severity in metadata
		query = query.Where("metadata->>'severity' = ?", string(severity))
	}
	
	err := query.
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&events).Error
	return events, err
}

// FindFailedLogins implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) FindFailedLogins(ctx context.Context, timeWindow time.Duration) ([]*domain.ComprehensiveAuditEvent, error) {
	var events []*domain.ComprehensiveAuditEvent
	since := time.Now().UTC().Add(-timeWindow)
	
	err := r.db.WithContext(ctx).
		Where("event_type IN (?, ?)", domain.EventTypeLoginFailure, domain.EventTypeLoginAttempt).
		Where("success = ?", false).
		Where("timestamp >= ?", since).
		Order("timestamp DESC").
		Find(&events).Error
	return events, err
}

// FindSuspiciousActivity implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) FindSuspiciousActivity(ctx context.Context, ipAddress string, timeWindow time.Duration) ([]*domain.ComprehensiveAuditEvent, error) {
	var events []*domain.ComprehensiveAuditEvent
	since := time.Now().UTC().Add(-timeWindow)
	
	err := r.db.WithContext(ctx).
		Where("ip_address = ?", ipAddress).
		Where("event_type IN (?, ?, ?)", 
			domain.EventTypeSuspiciousActivity, 
			domain.EventTypeSecurityViolation,
			domain.EventTypeBruteForceDetected).
		Where("timestamp >= ?", since).
		Order("timestamp DESC").
		Find(&events).Error
	return events, err
}

// FindDataAccessEvents implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) FindDataAccessEvents(ctx context.Context, dataSubjectID uint, timeWindow time.Duration) ([]*domain.ComprehensiveAuditEvent, error) {
	var events []*domain.ComprehensiveAuditEvent
	since := time.Now().UTC().Add(-timeWindow)
	
	err := r.db.WithContext(ctx).
		Where("event_category = ?", domain.CategoryDataAccess).
		Where("metadata->>'data_subject_id' = ?", fmt.Sprintf("%d", dataSubjectID)).
		Where("timestamp >= ?", since).
		Order("timestamp DESC").
		Find(&events).Error
	return events, err
}

// FindByLegalBasis implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) FindByLegalBasis(ctx context.Context, legalBasis domain.LegalBasis, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
	var events []*domain.ComprehensiveAuditEvent
	err := r.db.WithContext(ctx).
		Where("legal_basis = ?", legalBasis).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&events).Error
	return events, err
}

// DeleteOldEvents implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) DeleteOldEvents(ctx context.Context, retentionPolicy domain.RetentionPolicy, olderThan time.Time) (int64, error) {
	result := r.db.WithContext(ctx).
		Where("retention_policy = ? AND timestamp < ?", retentionPolicy, olderThan).
		Delete(&domain.ComprehensiveAuditEvent{})
	
	return result.RowsAffected, result.Error
}

// ArchiveEvents implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) ArchiveEvents(ctx context.Context, criteria *domain.AuditCriteria) error {
	// In a production system, this would move events to an archive table
	// For now, we'll mark them as archived in metadata
	query := r.db.WithContext(ctx).Model(&domain.ComprehensiveAuditEvent{})
	query = r.applyFilters(query, criteria)
	
	return query.Update("metadata", gorm.Expr("COALESCE(metadata, '{}') || '{\"archived\": true}'")).Error
}

// GetEventStatistics implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) GetEventStatistics(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error) {
	since := time.Now().UTC().Add(-timeRange)
	
	var stats []struct {
		EventType string `json:"event_type"`
		Count     int64  `json:"count"`
	}
	
	err := r.db.WithContext(ctx).
		Model(&domain.ComprehensiveAuditEvent{}).
		Select("event_type, count(*) as count").
		Where("timestamp >= ?", since).
		Group("event_type").
		Scan(&stats).Error
	
	if err != nil {
		return nil, err
	}
	
	result := map[string]interface{}{
		"time_range":     timeRange.String(),
		"since":          since,
		"event_counts":   stats,
		"total_events":   0,
	}
	
	// Calculate total
	var total int64
	for _, stat := range stats {
		total += stat.Count
	}
	result["total_events"] = total
	
	return result, nil
}

// GetUserActivitySummary implements domain.ComprehensiveAuditRepository
func (r *ComprehensiveAuditRepositoryImpl) GetUserActivitySummary(ctx context.Context, userID uint, timeRange time.Duration) (map[string]interface{}, error) {
	since := time.Now().UTC().Add(-timeRange)
	
	var stats []struct {
		EventCategory string `json:"event_category"`
		Count         int64  `json:"count"`
	}
	
	err := r.db.WithContext(ctx).
		Model(&domain.ComprehensiveAuditEvent{}).
		Select("event_category, count(*) as count").
		Where("user_id = ? AND timestamp >= ?", userID, since).
		Group("event_category").
		Scan(&stats).Error
	
	if err != nil {
		return nil, err
	}
	
	// Get last activity
	var lastActivity time.Time
	r.db.WithContext(ctx).
		Model(&domain.ComprehensiveAuditEvent{}).
		Select("MAX(timestamp)").
		Where("user_id = ?", userID).
		Scan(&lastActivity)
	
	return map[string]interface{}{
		"user_id":       userID,
		"time_range":    timeRange.String(),
		"since":         since,
		"activity_counts": stats,
		"last_activity": lastActivity,
	}, nil
}

// applyFilters applies search criteria filters to the query
func (r *ComprehensiveAuditRepositoryImpl) applyFilters(query *gorm.DB, criteria *domain.AuditCriteria) *gorm.DB {
	if criteria == nil {
		return query
	}
	
	// Time range filters
	if criteria.StartTime != nil {
		query = query.Where("timestamp >= ?", *criteria.StartTime)
	}
	if criteria.EndTime != nil {
		query = query.Where("timestamp <= ?", *criteria.EndTime)
	}
	
	// Event type filters
	if len(criteria.EventTypes) > 0 {
		query = query.Where("event_type IN ?", criteria.EventTypes)
	}
	
	// Event category filters
	if len(criteria.EventCategories) > 0 {
		query = query.Where("event_category IN ?", criteria.EventCategories)
	}
	
	// Success filter
	if criteria.Success != nil {
		query = query.Where("success = ?", *criteria.Success)
	}
	
	// User filters
	if len(criteria.UserIDs) > 0 {
		query = query.Where("user_id IN ?", criteria.UserIDs)
	}
	
	// Session filters
	if len(criteria.SessionIDs) > 0 {
		query = query.Where("session_id IN ?", criteria.SessionIDs)
	}
	
	// IP address filters
	if len(criteria.IPAddresses) > 0 {
		query = query.Where("ip_address IN ?", criteria.IPAddresses)
	}
	
	// Resource filters
	if len(criteria.ResourceTypes) > 0 {
		query = query.Where("resource_type IN ?", criteria.ResourceTypes)
	}
	
	if len(criteria.ResourceIDs) > 0 {
		query = query.Where("resource_id IN ?", criteria.ResourceIDs)
	}
	
	if len(criteria.Actions) > 0 {
		query = query.Where("action IN ?", criteria.Actions)
	}
	
	// Compliance filters
	if len(criteria.LegalBases) > 0 {
		query = query.Where("legal_basis IN ?", criteria.LegalBases)
	}
	
	if len(criteria.DataClassifications) > 0 {
		query = query.Where("data_classification IN ?", criteria.DataClassifications)
	}
	
	// Security filters
	if criteria.SecurityEvents {
		query = query.Where("event_category = ?", domain.CategoryAuditSecurity)
	}
	
	if criteria.MinSeverity != nil {
		// This would require more complex logic to compare severity levels
		query = query.Where("metadata->>'severity' >= ?", string(*criteria.MinSeverity))
	}
	
	return query
}

// applyPagination applies pagination and ordering to the query
func (r *ComprehensiveAuditRepositoryImpl) applyPagination(query *gorm.DB, criteria *domain.AuditCriteria) *gorm.DB {
	// Apply ordering
	orderBy := "timestamp"
	orderDirection := "DESC"
	
	if criteria.OrderBy != "" {
		// Sanitize order by field
		allowedFields := []string{"timestamp", "event_type", "event_category", "user_id", "success"}
		for _, field := range allowedFields {
			if criteria.OrderBy == field {
				orderBy = field
				break
			}
		}
	}
	
	if criteria.OrderDirection != "" {
		direction := strings.ToUpper(criteria.OrderDirection)
		if direction == "ASC" || direction == "DESC" {
			orderDirection = direction
		}
	}
	
	query = query.Order(fmt.Sprintf("%s %s", orderBy, orderDirection))
	
	// Apply pagination
	if criteria.Limit > 0 {
		query = query.Limit(criteria.Limit)
	} else {
		query = query.Limit(50) // Default limit
	}
	
	if criteria.Offset > 0 {
		query = query.Offset(criteria.Offset)
	}
	
	return query
}