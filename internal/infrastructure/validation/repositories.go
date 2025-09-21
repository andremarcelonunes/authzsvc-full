package validation

import (
	"context"
	"log/slog"
	"time"

	"github.com/you/authzsvc/domain"
)

// MockSecurityViolationRepository is a simple in-memory implementation for CB-182
type MockSecurityViolationRepository struct {
	logger *slog.Logger
}

// NewMockSecurityViolationRepository creates a new mock security violation repository
func NewMockSecurityViolationRepository() domain.SecurityViolationRepository {
	return &MockSecurityViolationRepository{
		logger: slog.Default(),
	}
}

// CreateViolation logs the security violation (in production, this would store to database)
func (r *MockSecurityViolationRepository) CreateViolation(ctx context.Context, violation *domain.SecurityViolation) error {
	r.logger.WarnContext(ctx, "Security violation recorded",
		slog.String("type", string(violation.Type)),
		slog.String("severity", string(violation.Severity)),
		slog.String("description", violation.Description),
		slog.String("field_name", violation.FieldName),
		slog.String("pattern", violation.Pattern),
		slog.Bool("blocked", violation.Blocked),
		slog.Float64("risk_score", violation.RiskScore),
		slog.Time("timestamp", violation.Timestamp),
	)
	return nil
}


// DeleteOldViolations deletes old violations (mock implementation does nothing)
func (r *MockSecurityViolationRepository) DeleteOldViolations(ctx context.Context, olderThan time.Time) (int64, error) {
	r.logger.InfoContext(ctx, "Mock: Old violations would be deleted", slog.Time("older_than", olderThan))
	return 0, nil
}

// GetViolationStats returns violation statistics (mock implementation returns zeros)
func (r *MockSecurityViolationRepository) GetViolationStats(ctx context.Context, timeRange time.Duration) (*domain.ViolationStats, error) {
	return &domain.ViolationStats{
		TotalViolations: 0,
		ViolationsByType: make(map[domain.ThreatType]int),
		ViolationsBySeverity: make(map[domain.ValidationSeverity]int),
	}, nil
}

// Implement missing methods from SecurityViolationRepository interface

// RecordViolation is an alias for CreateViolation 
func (r *MockSecurityViolationRepository) RecordViolation(ctx context.Context, violation *domain.SecurityViolation) error {
	return r.CreateViolation(ctx, violation)
}

// GetViolationByID returns a violation by ID (mock implementation returns nil)
func (r *MockSecurityViolationRepository) GetViolationByID(ctx context.Context, violationID string) (*domain.SecurityViolation, error) {
	return nil, nil
}

// GetViolationsByUser returns violations for a user (updated signature)
func (r *MockSecurityViolationRepository) GetViolationsByUser(ctx context.Context, userID uint, limit int, offset int) ([]domain.SecurityViolation, error) {
	return []domain.SecurityViolation{}, nil
}

// GetViolationsByIP returns violations for an IP address (updated signature)
func (r *MockSecurityViolationRepository) GetViolationsByIP(ctx context.Context, ipAddress string, limit int, offset int) ([]domain.SecurityViolation, error) {
	return []domain.SecurityViolation{}, nil
}

// GetViolationsByType returns violations by threat type
func (r *MockSecurityViolationRepository) GetViolationsByType(ctx context.Context, threatType domain.ThreatType, limit int, offset int) ([]domain.SecurityViolation, error) {
	return []domain.SecurityViolation{}, nil
}

// GetViolationsByTimeRange returns violations in a time range (updated signature)
func (r *MockSecurityViolationRepository) GetViolationsByTimeRange(ctx context.Context, startTime, endTime time.Time) ([]domain.SecurityViolation, error) {
	return []domain.SecurityViolation{}, nil
}

// GetTopThreats returns top threats (mock implementation returns empty slice)
func (r *MockSecurityViolationRepository) GetTopThreats(ctx context.Context, timeWindow time.Duration, limit int) ([]domain.ThreatSummary, error) {
	return []domain.ThreatSummary{}, nil
}

// GetUserThreatProfile returns threat profile for a user (mock implementation returns empty profile)
func (r *MockSecurityViolationRepository) GetUserThreatProfile(ctx context.Context, userID uint) (*domain.UserThreatProfile, error) {
	return &domain.UserThreatProfile{
		UserID: userID,
		TotalViolations: 0,
		RiskScore: 0.0,
		LastViolation: nil,
	}, nil
}