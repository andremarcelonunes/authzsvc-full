package mocks

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
)

// MockAuditMetrics implements domain.AuditMetrics interface for testing
type MockAuditMetrics struct {
	RecordEventProcessingTimeFunc    func(ctx context.Context, duration time.Duration)
	RecordEventWriteLatencyFunc      func(ctx context.Context, latency time.Duration)
	RecordEventQueryLatencyFunc      func(ctx context.Context, latency time.Duration)
	IncrementEventCountFunc          func(ctx context.Context, eventType string)
	IncrementSecurityEventCountFunc  func(ctx context.Context, severity domain.SecuritySeverity)
	RecordEventBatchSizeFunc         func(ctx context.Context, size int)
	RecordDataAccessCountFunc        func(ctx context.Context, dataType string, operation domain.DataOperation)
	RecordConsentEventFunc           func(ctx context.Context, consentType string)
	RecordSystemHealthFunc           func(ctx context.Context, component string, healthy bool)
	RecordErrorRateFunc              func(ctx context.Context, errorType string, rate float64)
	GetMetricsFunc                   func(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error)
	GetComplianceReportFunc          func(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error)
}

// NewMockAuditMetrics creates a new MockAuditMetrics with default behaviors
func NewMockAuditMetrics() *MockAuditMetrics {
	return &MockAuditMetrics{}
}

// RecordEventProcessingTime records event processing time
func (m *MockAuditMetrics) RecordEventProcessingTime(ctx context.Context, duration time.Duration) {
	if m.RecordEventProcessingTimeFunc != nil {
		m.RecordEventProcessingTimeFunc(ctx, duration)
	}
	// Default behavior: no-op
}

// RecordEventWriteLatency records event write latency
func (m *MockAuditMetrics) RecordEventWriteLatency(ctx context.Context, latency time.Duration) {
	if m.RecordEventWriteLatencyFunc != nil {
		m.RecordEventWriteLatencyFunc(ctx, latency)
	}
	// Default behavior: no-op
}

// RecordEventQueryLatency records event query latency
func (m *MockAuditMetrics) RecordEventQueryLatency(ctx context.Context, latency time.Duration) {
	if m.RecordEventQueryLatencyFunc != nil {
		m.RecordEventQueryLatencyFunc(ctx, latency)
	}
	// Default behavior: no-op
}

// IncrementEventCount increments event count
func (m *MockAuditMetrics) IncrementEventCount(ctx context.Context, eventType string) {
	if m.IncrementEventCountFunc != nil {
		m.IncrementEventCountFunc(ctx, eventType)
	}
	// Default behavior: no-op
}

// IncrementSecurityEventCount increments security event count
func (m *MockAuditMetrics) IncrementSecurityEventCount(ctx context.Context, severity domain.SecuritySeverity) {
	if m.IncrementSecurityEventCountFunc != nil {
		m.IncrementSecurityEventCountFunc(ctx, severity)
	}
	// Default behavior: no-op
}

// RecordEventBatchSize records event batch size
func (m *MockAuditMetrics) RecordEventBatchSize(ctx context.Context, size int) {
	if m.RecordEventBatchSizeFunc != nil {
		m.RecordEventBatchSizeFunc(ctx, size)
	}
	// Default behavior: no-op
}

// RecordDataAccessCount records data access count
func (m *MockAuditMetrics) RecordDataAccessCount(ctx context.Context, dataType string, operation domain.DataOperation) {
	if m.RecordDataAccessCountFunc != nil {
		m.RecordDataAccessCountFunc(ctx, dataType, operation)
	}
	// Default behavior: no-op
}

// RecordConsentEvent records consent event
func (m *MockAuditMetrics) RecordConsentEvent(ctx context.Context, consentType string) {
	if m.RecordConsentEventFunc != nil {
		m.RecordConsentEventFunc(ctx, consentType)
	}
	// Default behavior: no-op
}

// RecordSystemHealth records system health
func (m *MockAuditMetrics) RecordSystemHealth(ctx context.Context, component string, healthy bool) {
	if m.RecordSystemHealthFunc != nil {
		m.RecordSystemHealthFunc(ctx, component, healthy)
	}
	// Default behavior: no-op
}

// RecordErrorRate records error rate
func (m *MockAuditMetrics) RecordErrorRate(ctx context.Context, errorType string, rate float64) {
	if m.RecordErrorRateFunc != nil {
		m.RecordErrorRateFunc(ctx, errorType, rate)
	}
	// Default behavior: no-op
}

// GetMetrics gets metrics
func (m *MockAuditMetrics) GetMetrics(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error) {
	if m.GetMetricsFunc != nil {
		return m.GetMetricsFunc(ctx, timeRange)
	}
	// Default behavior: empty metrics
	return map[string]interface{}{
		"time_range":           timeRange.String(),
		"total_events":         0,
		"event_processing_avg": "0ms",
		"error_rate":           0.0,
	}, nil
}

// GetComplianceReport gets compliance report
func (m *MockAuditMetrics) GetComplianceReport(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error) {
	if m.GetComplianceReportFunc != nil {
		return m.GetComplianceReportFunc(ctx, timeRange)
	}
	// Default behavior: empty compliance report
	return map[string]interface{}{
		"time_range":      timeRange.String(),
		"data_access_count": 0,
		"consent_events":  0,
		"lgpd_compliance": true,
	}, nil
}

// Compile-time interface compliance verification
var _ domain.AuditMetrics = (*MockAuditMetrics)(nil)