package mocks

import (
	"context"

	"github.com/you/authzsvc/domain"
)

// MockAsyncProcessor implements domain.AsyncProcessor interface for testing
type MockAsyncProcessor struct {
	ProcessEventAsyncFunc        func(ctx context.Context, event *domain.ComprehensiveAuditEvent) error
	ProcessEventsAsyncFunc       func(ctx context.Context, events []*domain.ComprehensiveAuditEvent) error
	GetQueueStatusFunc           func(ctx context.Context) (map[string]interface{}, error)
	GetProcessingStatisticsFunc  func(ctx context.Context) (map[string]interface{}, error)
	GetFailedEventsFunc          func(ctx context.Context, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error)
	RetryFailedEventsFunc        func(ctx context.Context, maxRetries int) error
}

// NewMockAsyncProcessor creates a new MockAsyncProcessor with default behaviors
func NewMockAsyncProcessor() *MockAsyncProcessor {
	return &MockAsyncProcessor{}
}

// ProcessEventAsync processes an event asynchronously
func (m *MockAsyncProcessor) ProcessEventAsync(ctx context.Context, event *domain.ComprehensiveAuditEvent) error {
	if m.ProcessEventAsyncFunc != nil {
		return m.ProcessEventAsyncFunc(ctx, event)
	}
	// Default behavior: success
	return nil
}

// ProcessEventsAsync processes multiple events asynchronously
func (m *MockAsyncProcessor) ProcessEventsAsync(ctx context.Context, events []*domain.ComprehensiveAuditEvent) error {
	if m.ProcessEventsAsyncFunc != nil {
		return m.ProcessEventsAsyncFunc(ctx, events)
	}
	// Default behavior: success
	return nil
}

// GetQueueStatus gets current queue status
func (m *MockAsyncProcessor) GetQueueStatus(ctx context.Context) (map[string]interface{}, error) {
	if m.GetQueueStatusFunc != nil {
		return m.GetQueueStatusFunc(ctx)
	}
	// Default behavior: healthy queue status
	return map[string]interface{}{
		"event_queue_length":    0,
		"event_queue_capacity":  1000,
		"batch_queue_length":    0,
		"batch_queue_capacity":  100,
		"failed_events_count":   0,
		"status":                "healthy",
	}, nil
}

// GetProcessingStatistics gets processing statistics
func (m *MockAsyncProcessor) GetProcessingStatistics(ctx context.Context) (map[string]interface{}, error) {
	if m.GetProcessingStatisticsFunc != nil {
		return m.GetProcessingStatisticsFunc(ctx)
	}
	// Default behavior: basic statistics
	return map[string]interface{}{
		"processor_type":    "mock_async",
		"workers_active":    true,
		"events_processed":  0,
		"processing_rate":   0.0,
	}, nil
}

// GetFailedEvents gets failed events
func (m *MockAsyncProcessor) GetFailedEvents(ctx context.Context, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
	if m.GetFailedEventsFunc != nil {
		return m.GetFailedEventsFunc(ctx, limit, offset)
	}
	// Default behavior: no failed events
	return []*domain.ComprehensiveAuditEvent{}, nil
}

// RetryFailedEvents retries failed events
func (m *MockAsyncProcessor) RetryFailedEvents(ctx context.Context, maxRetries int) error {
	if m.RetryFailedEventsFunc != nil {
		return m.RetryFailedEventsFunc(ctx, maxRetries)
	}
	// Default behavior: success
	return nil
}

// Compile-time interface compliance verification
var _ domain.AsyncProcessor = (*MockAsyncProcessor)(nil)