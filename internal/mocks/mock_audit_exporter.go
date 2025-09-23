package mocks

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
)

// MockAuditExporter implements domain.AuditExporter interface for testing
type MockAuditExporter struct {
	ExportToJSONFunc               func(ctx context.Context, events []*domain.ComprehensiveAuditEvent) ([]byte, error)
	ExportToCSVFunc                func(ctx context.Context, events []*domain.ComprehensiveAuditEvent) ([]byte, error)
	ExportToXLSXFunc               func(ctx context.Context, events []*domain.ComprehensiveAuditEvent) ([]byte, error)
	ExportToPDFFunc                func(ctx context.Context, events []*domain.ComprehensiveAuditEvent, template string) ([]byte, error)
	CreateExportFileFunc           func(ctx context.Context, format domain.ExportFormat, data []byte, encryption bool) (*domain.ExportResult, error)
	GetExportStatusFunc            func(ctx context.Context, exportID string) (*domain.ExportResult, error)
	CleanupExpiredExportsFunc      func(ctx context.Context) error
	ExportForComplianceFunc        func(ctx context.Context, criteria *domain.ExportCriteria, regulation string) (*domain.ExportResult, error)
	GenerateComplianceReportFunc   func(ctx context.Context, userID uint, timeRange time.Duration) (*domain.ExportResult, error)
}

// NewMockAuditExporter creates a new MockAuditExporter with default behaviors
func NewMockAuditExporter() *MockAuditExporter {
	return &MockAuditExporter{}
}

// ExportToJSON exports events to JSON format
func (m *MockAuditExporter) ExportToJSON(ctx context.Context, events []*domain.ComprehensiveAuditEvent) ([]byte, error) {
	if m.ExportToJSONFunc != nil {
		return m.ExportToJSONFunc(ctx, events)
	}
	// Default behavior: return mock JSON
	return []byte(`{"events": [{"id": 1, "event_type": "mock_event"}]}`), nil
}

// ExportToCSV exports events to CSV format
func (m *MockAuditExporter) ExportToCSV(ctx context.Context, events []*domain.ComprehensiveAuditEvent) ([]byte, error) {
	if m.ExportToCSVFunc != nil {
		return m.ExportToCSVFunc(ctx, events)
	}
	// Default behavior: return mock CSV
	return []byte("id,event_type,timestamp\n1,mock_event,2023-01-01T00:00:00Z\n"), nil
}

// ExportToXLSX exports events to XLSX format
func (m *MockAuditExporter) ExportToXLSX(ctx context.Context, events []*domain.ComprehensiveAuditEvent) ([]byte, error) {
	if m.ExportToXLSXFunc != nil {
		return m.ExportToXLSXFunc(ctx, events)
	}
	// Default behavior: return mock XLSX (binary data simulated)
	return []byte("mock_xlsx_data"), nil
}

// ExportToPDF exports events to PDF format
func (m *MockAuditExporter) ExportToPDF(ctx context.Context, events []*domain.ComprehensiveAuditEvent, template string) ([]byte, error) {
	if m.ExportToPDFFunc != nil {
		return m.ExportToPDFFunc(ctx, events, template)
	}
	// Default behavior: return mock PDF (binary data simulated)
	return []byte("mock_pdf_data"), nil
}

// CreateExportFile creates an export file
func (m *MockAuditExporter) CreateExportFile(ctx context.Context, format domain.ExportFormat, data []byte, encryption bool) (*domain.ExportResult, error) {
	if m.CreateExportFileFunc != nil {
		return m.CreateExportFileFunc(ctx, format, data, encryption)
	}
	// Default behavior: return mock export result
	return &domain.ExportResult{
		ExportID:     "mock_export_123",
		Format:       format,
		RecordsCount: 1,
		FileSize:     int64(len(data)),
		FilePath:     "/tmp/mock_export.json",
		DownloadURL:  "/exports/mock_export_123",
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Checksum:     "mock_checksum",
		Encrypted:    encryption,
		CreatedAt:    time.Now(),
		Status:       domain.ExportStatusCompleted,
		Metadata: map[string]interface{}{
			"format": string(format),
			"size":   len(data),
		},
	}, nil
}

// GetExportStatus gets export status
func (m *MockAuditExporter) GetExportStatus(ctx context.Context, exportID string) (*domain.ExportResult, error) {
	if m.GetExportStatusFunc != nil {
		return m.GetExportStatusFunc(ctx, exportID)
	}
	// Default behavior: return completed status
	return &domain.ExportResult{
		ExportID: exportID,
		Status:   domain.ExportStatusCompleted,
	}, nil
}

// CleanupExpiredExports cleans up expired exports
func (m *MockAuditExporter) CleanupExpiredExports(ctx context.Context) error {
	if m.CleanupExpiredExportsFunc != nil {
		return m.CleanupExpiredExportsFunc(ctx)
	}
	// Default behavior: success
	return nil
}

// ExportForCompliance exports for compliance
func (m *MockAuditExporter) ExportForCompliance(ctx context.Context, criteria *domain.ExportCriteria, regulation string) (*domain.ExportResult, error) {
	if m.ExportForComplianceFunc != nil {
		return m.ExportForComplianceFunc(ctx, criteria, regulation)
	}
	// Default behavior: return mock compliance export
	return &domain.ExportResult{
		ExportID: "compliance_export_123",
		Format:   criteria.Format,
		Status:   domain.ExportStatusCompleted,
		Metadata: map[string]interface{}{
			"regulation": regulation,
			"compliance": true,
		},
	}, nil
}

// GenerateComplianceReport generates compliance report
func (m *MockAuditExporter) GenerateComplianceReport(ctx context.Context, userID uint, timeRange time.Duration) (*domain.ExportResult, error) {
	if m.GenerateComplianceReportFunc != nil {
		return m.GenerateComplianceReportFunc(ctx, userID, timeRange)
	}
	// Default behavior: return mock compliance report
	return &domain.ExportResult{
		ExportID: "compliance_report_123",
		Format:   domain.ExportFormatPDF,
		Status:   domain.ExportStatusCompleted,
		Metadata: map[string]interface{}{
			"user_id":    userID,
			"time_range": timeRange.String(),
			"report_type": "lgpd_compliance",
		},
	}, nil
}

// Compile-time interface compliance verification
var _ domain.AuditExporter = (*MockAuditExporter)(nil)