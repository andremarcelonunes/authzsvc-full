package repositories

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
	"gorm.io/gorm"
)

// SecurityViolationRepositoryImpl implements domain.SecurityViolationRepository using GORM
type SecurityViolationRepositoryImpl struct {
	db *gorm.DB
}

// NewSecurityViolationRepository creates a new security violation repository
func NewSecurityViolationRepository(db *gorm.DB) domain.SecurityViolationRepository {
	return &SecurityViolationRepositoryImpl{
		db: db,
	}
}

// CreateViolation stores a security violation in the database
func (r *SecurityViolationRepositoryImpl) CreateViolation(ctx context.Context, violation *domain.SecurityViolation) error {
	return r.db.WithContext(ctx).Create(violation).Error
}

// RecordViolation is an alias for CreateViolation
func (r *SecurityViolationRepositoryImpl) RecordViolation(ctx context.Context, violation *domain.SecurityViolation) error {
	return r.CreateViolation(ctx, violation)
}

// GetViolationByID retrieves a violation by its ID
func (r *SecurityViolationRepositoryImpl) GetViolationByID(ctx context.Context, violationID string) (*domain.SecurityViolation, error) {
	var violation domain.SecurityViolation
	err := r.db.WithContext(ctx).Where("id = ?", violationID).First(&violation).Error
	if err == gorm.ErrRecordNotFound {
		return nil, domain.ErrViolationNotFound
	}
	return &violation, err
}

// GetViolationsByUser retrieves violations for a specific user
func (r *SecurityViolationRepositoryImpl) GetViolationsByUser(ctx context.Context, userID uint, limit int, offset int) ([]domain.SecurityViolation, error) {
	var violations []domain.SecurityViolation
	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&violations).Error
	return violations, err
}

// GetViolationsByIP retrieves violations for a specific IP address
func (r *SecurityViolationRepositoryImpl) GetViolationsByIP(ctx context.Context, ipAddress string, limit int, offset int) ([]domain.SecurityViolation, error) {
	var violations []domain.SecurityViolation
	err := r.db.WithContext(ctx).
		Where("ip_address = ?", ipAddress).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&violations).Error
	return violations, err
}

// GetViolationsByType retrieves violations by threat type
func (r *SecurityViolationRepositoryImpl) GetViolationsByType(ctx context.Context, threatType domain.ThreatType, limit int, offset int) ([]domain.SecurityViolation, error) {
	var violations []domain.SecurityViolation
	err := r.db.WithContext(ctx).
		Where("type = ?", threatType).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&violations).Error
	return violations, err
}

// GetViolationsByTimeRange retrieves violations within a time range
func (r *SecurityViolationRepositoryImpl) GetViolationsByTimeRange(ctx context.Context, startTime, endTime time.Time) ([]domain.SecurityViolation, error) {
	var violations []domain.SecurityViolation
	err := r.db.WithContext(ctx).
		Where("timestamp BETWEEN ? AND ?", startTime, endTime).
		Order("timestamp DESC").
		Find(&violations).Error
	return violations, err
}

// DeleteOldViolations removes violations older than the specified time
func (r *SecurityViolationRepositoryImpl) DeleteOldViolations(ctx context.Context, olderThan time.Time) (int64, error) {
	result := r.db.WithContext(ctx).Where("timestamp < ?", olderThan).Delete(&domain.SecurityViolation{})
	return result.RowsAffected, result.Error
}

// GetViolationStats returns violation statistics for the given time range
func (r *SecurityViolationRepositoryImpl) GetViolationStats(ctx context.Context, timeRange time.Duration) (*domain.ViolationStats, error) {
	since := time.Now().Add(-timeRange)
	
	var totalCount int64
	err := r.db.WithContext(ctx).Model(&domain.SecurityViolation{}).
		Where("timestamp >= ?", since).
		Count(&totalCount).Error
	if err != nil {
		return nil, err
	}

	// Get violations by type
	var typeResults []struct {
		Type  domain.ThreatType
		Count int
	}
	err = r.db.WithContext(ctx).Model(&domain.SecurityViolation{}).
		Select("type, COUNT(*) as count").
		Where("timestamp >= ?", since).
		Group("type").
		Find(&typeResults).Error
	if err != nil {
		return nil, err
	}

	// Get violations by severity
	var severityResults []struct {
		Severity domain.ValidationSeverity
		Count    int
	}
	err = r.db.WithContext(ctx).Model(&domain.SecurityViolation{}).
		Select("severity, COUNT(*) as count").
		Where("timestamp >= ?", since).
		Group("severity").
		Find(&severityResults).Error
	if err != nil {
		return nil, err
	}

	// Build statistics
	stats := &domain.ViolationStats{
		TotalViolations:      int(totalCount),
		ViolationsByType:     make(map[domain.ThreatType]int),
		ViolationsBySeverity: make(map[domain.ValidationSeverity]int),
	}

	for _, result := range typeResults {
		stats.ViolationsByType[result.Type] = result.Count
	}

	for _, result := range severityResults {
		stats.ViolationsBySeverity[result.Severity] = result.Count
	}

	return stats, nil
}

// GetTopThreats returns the most common threats in the specified time window
func (r *SecurityViolationRepositoryImpl) GetTopThreats(ctx context.Context, timeWindow time.Duration, limit int) ([]domain.ThreatSummary, error) {
	since := time.Now().Add(-timeWindow)
	
	var results []struct {
		Type         domain.ThreatType
		Count        int
		AvgSeverity  string
		FirstSeen    time.Time
		LastSeen     time.Time
		UniqueUsers  int
		UniqueIPs    int
	}
	
	err := r.db.WithContext(ctx).Model(&domain.SecurityViolation{}).
		Select(`type, 
				COUNT(*) as count, 
				MIN(timestamp) as first_seen,
				MAX(timestamp) as last_seen,
				COUNT(DISTINCT user_id) as unique_users,
				COUNT(DISTINCT ip_address) as unique_ips,
				(array_agg(severity::text ORDER BY severity DESC))[1] as avg_severity`).
		Where("timestamp >= ?", since).
		Group("type").
		Order("count DESC").
		Limit(limit).
		Find(&results).Error
	
	if err != nil {
		return nil, err
	}

	var threats []domain.ThreatSummary
	for _, result := range results {
		severity := domain.SeverityError // default
		switch result.AvgSeverity {
		case "info":
			severity = domain.SeverityInfo
		case "warning":
			severity = domain.SeverityWarning
		case "error":
			severity = domain.SeverityError
		case "critical":
			severity = domain.SeverityCritical
		}
		
		threats = append(threats, domain.ThreatSummary{
			Type:        result.Type,
			Count:       result.Count,
			Severity:    severity,
			FirstSeen:   result.FirstSeen,
			LastSeen:    result.LastSeen,
			UniqueUsers: result.UniqueUsers,
			UniqueIPs:   result.UniqueIPs,
		})
	}

	return threats, nil
}

// GetUserThreatProfile returns threat profile for a specific user
func (r *SecurityViolationRepositoryImpl) GetUserThreatProfile(ctx context.Context, userID uint) (*domain.UserThreatProfile, error) {
	var profile domain.UserThreatProfile
	profile.UserID = userID

	// Get total violations count
	var totalCount int64
	err := r.db.WithContext(ctx).Model(&domain.SecurityViolation{}).
		Where("user_id = ?", userID).
		Count(&totalCount).Error
	if err != nil {
		return nil, err
	}
	profile.TotalViolations = int(totalCount)

	// Get max risk score
	var maxRisk struct {
		MaxRisk float64
	}
	err = r.db.WithContext(ctx).Model(&domain.SecurityViolation{}).
		Select("MAX(risk_score) as max_risk").
		Where("user_id = ?", userID).
		First(&maxRisk).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	profile.RiskScore = maxRisk.MaxRisk

	// Determine threat level based on risk score
	if profile.RiskScore >= 8.0 {
		profile.ThreatLevel = domain.ThreatCritical
	} else if profile.RiskScore >= 6.0 {
		profile.ThreatLevel = domain.ThreatHigh
	} else if profile.RiskScore >= 4.0 {
		profile.ThreatLevel = domain.ThreatMedium
	} else if profile.RiskScore >= 2.0 {
		profile.ThreatLevel = domain.ThreatLow
	} else {
		profile.ThreatLevel = domain.ThreatNone
	}

	// Get violations by type
	var typeResults []struct {
		Type  domain.ThreatType
		Count int
	}
	err = r.db.WithContext(ctx).Model(&domain.SecurityViolation{}).
		Select("type, COUNT(*) as count").
		Where("user_id = ?", userID).
		Group("type").
		Find(&typeResults).Error
	if err != nil {
		return nil, err
	}

	profile.ViolationsByType = make(map[domain.ThreatType]int)
	for _, result := range typeResults {
		profile.ViolationsByType[result.Type] = result.Count
	}

	// Get first and last violation timestamps
	var timestamps struct {
		FirstViolation *time.Time
		LastViolation  *time.Time
	}
	err = r.db.WithContext(ctx).Model(&domain.SecurityViolation{}).
		Select("MIN(timestamp) as first_violation, MAX(timestamp) as last_violation").
		Where("user_id = ?", userID).
		First(&timestamps).Error
	if err != nil && err != gorm.ErrRecordNotFound {
		return nil, err
	}
	profile.FirstViolation = timestamps.FirstViolation
	profile.LastViolation = timestamps.LastViolation

	// Get recent violations (last 10)
	var recentViolations []domain.SecurityViolation
	err = r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("timestamp DESC").
		Limit(10).
		Find(&recentViolations).Error
	if err != nil {
		return nil, err
	}
	profile.RecentViolations = recentViolations

	// Generate recommendations based on violation types
	profile.Recommendations = []string{}
	if profile.ViolationsByType[domain.ThreatXSS] > 0 {
		profile.Recommendations = append(profile.Recommendations, "Review and validate all user inputs for XSS prevention")
	}
	if profile.ViolationsByType[domain.ThreatSQLInjection] > 0 {
		profile.Recommendations = append(profile.Recommendations, "Use parameterized queries to prevent SQL injection")
	}
	if profile.ViolationsByType[domain.ThreatBruteForce] > 0 {
		profile.Recommendations = append(profile.Recommendations, "Consider implementing account lockout and stronger authentication")
	}

	// Set other fields
	profile.IsBlocked = false // This would need to be checked against a separate blocking system
	profile.BlockedUntil = nil
	profile.GeneratedAt = time.Now()

	return &profile, nil
}