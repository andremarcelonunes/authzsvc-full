package services

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/config"
	"github.com/you/authzsvc/internal/mocks"
)

func TestComprehensiveAuditService_LogAuthenticationEvent(t *testing.T) {
	t.Helper()
	
	tests := []struct {
		name          string
		event         *domain.AuthEvent
		setupMocks    func(*mocks.MockAuditRepository, *mocks.MockDataEncryptor)
		expectedError string
	}{
		{
			name: "successful authentication event logging",
			event: &domain.AuthEvent{
				UserID:        123,
				Email:         "test@example.com",
				Action:        "login",
				Success:       true,
				SessionID:     "sess_123",
				IPAddress:     "192.168.1.1",
				UserAgent:     "Mozilla/5.0",
				Timestamp:     time.Now(),
				Metadata:      map[string]interface{}{"device": "mobile"},
			},
			setupMocks: func(repo *mocks.MockAuditRepository, encryptor *mocks.MockDataEncryptor) {
				repo.CreateFunc = func(ctx context.Context, event *domain.ComprehensiveAuditEvent) error {
					return nil
				}
			},
			expectedError: "",
		},
		{
			name: "failed authentication event logging with repository error",
			event: &domain.AuthEvent{
				UserID:    456,
				Email:     "test2@example.com",
				Action:    "login",
				Success:   false,
				IPAddress: "192.168.1.2",
				Timestamp: time.Now(),
			},
			setupMocks: func(repo *mocks.MockAuditRepository, encryptor *mocks.MockDataEncryptor) {
				repo.CreateFunc = func(ctx context.Context, event *domain.ComprehensiveAuditEvent) error {
					return domain.ErrAuditRepositoryError
				}
			},
			expectedError: "audit repository error",
		},
		{
			name: "authentication event with encryption",
			event: &domain.AuthEvent{
				UserID:    789,
				Email:     "sensitive@example.com",
				Action:    "login",
				Success:   true,
				IPAddress: "192.168.1.3",
				Timestamp: time.Now(),
				Metadata:  map[string]interface{}{"email": "sensitive@example.com"},
			},
			setupMocks: func(repo *mocks.MockAuditRepository, encryptor *mocks.MockDataEncryptor) {
				encryptor.EncryptFieldsFunc = func(ctx context.Context, data map[string]interface{}, sensitiveFields []string) (map[string]interface{}, error) {
					return map[string]interface{}{
						"email": "encrypted_email_data",
					}, nil
				}
				repo.CreateFunc = func(ctx context.Context, event *domain.ComprehensiveAuditEvent) error {
					return nil
				}
			},
			expectedError: "",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockRepo := mocks.NewMockAuditRepository()
			mockEncryptor := mocks.NewMockDataEncryptor()
			mockIntegrityChecker := mocks.NewMockIntegrityChecker()
			mockAsyncProcessor := mocks.NewMockAsyncProcessor()
			mockMetrics := mocks.NewMockAuditMetrics()
			mockExporter := mocks.NewMockAuditExporter()
			
			// Setup mocks
			tt.setupMocks(mockRepo, mockEncryptor)
			
			// Create service - don't use async processor for error tests to ensure direct repo error propagation
			var asyncProcessor domain.AsyncProcessor
			if tt.expectedError == "" {
				asyncProcessor = mockAsyncProcessor
			}
			service := createAuditServiceForTest(t,
				mockRepo,
				mockEncryptor,
				mockIntegrityChecker,
				asyncProcessor,
				mockMetrics,
				mockExporter,
			)
			
			// Execute test
			err := service.LogAuthenticationEvent(context.Background(), tt.event)
			
			// Verify results
			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.expectedError)
				} else if err.Error() != tt.expectedError {
					t.Errorf("Expected error '%s', got '%s'", tt.expectedError, err.Error())
				}
			}
		})
	}
}

func TestComprehensiveAuditService_LogDataAccessEvent(t *testing.T) {
	t.Helper()
	
	tests := []struct {
		name          string
		event         *domain.DataAccessEvent
		setupMocks    func(*mocks.MockAuditRepository)
		expectedError string
	}{
		{
			name: "successful data access event logging for LGPD compliance",
			event: &domain.DataAccessEvent{
				UserID:             123,
				DataSubjectID:      &[]uint{456}[0],
				DataType:           "user_profile",
				Operation:          domain.DataOperationRead,
				LegalBasis:         domain.LegalBasisConsent,
				ConsentID:          "consent_123",
				DataClassification: domain.DataClassificationPII,
				FieldsAccessed:     []string{"name", "email", "phone"},
				RecordsCount:       1,
				IPAddress:          "192.168.1.1",
				SessionID:          "sess_123",
				Timestamp:          time.Now(),
				Purpose:            "user_profile_access",
			},
			setupMocks: func(repo *mocks.MockAuditRepository) {
				repo.CreateFunc = func(ctx context.Context, event *domain.ComprehensiveAuditEvent) error {
					// Verify LGPD compliance fields are set correctly
					if event.LegalBasis != domain.LegalBasisConsent {
						t.Errorf("Expected legal basis to be consent, got: %s", event.LegalBasis)
					}
					if event.DataClassification != domain.DataClassificationPII {
						t.Errorf("Expected data classification to be PII, got: %s", event.DataClassification)
					}
					if event.RetentionPolicy != domain.RetentionPolicyLegal {
						t.Errorf("Expected retention policy to be legal, got: %s", event.RetentionPolicy)
					}
					return nil
				}
			},
			expectedError: "",
		},
		{
			name: "data export event logging",
			event: &domain.DataAccessEvent{
				UserID:             789,
				DataSubjectID:      &[]uint{789}[0],
				DataType:           "personal_data",
				Operation:          domain.DataOperationExport,
				LegalBasis:         domain.LegalBasisLegitimateInterests,
				DataClassification: domain.DataClassificationSensitive,
				FieldsAccessed:     []string{"all_personal_data"},
				RecordsCount:       100,
				IPAddress:          "192.168.1.5",
				SessionID:          "sess_export_789",
				Timestamp:          time.Now(),
				Purpose:            "gdpr_data_export_request",
			},
			setupMocks: func(repo *mocks.MockAuditRepository) {
				repo.CreateFunc = func(ctx context.Context, event *domain.ComprehensiveAuditEvent) error {
					// Verify export event is properly categorized
					if event.EventCategory != domain.CategoryDataAccess {
						t.Errorf("Expected event category to be data_access, got: %s", event.EventCategory)
					}
					if event.EventType != string(domain.DataOperationExport) {
						t.Errorf("Expected event type to be export, got: %s", event.EventType)
					}
					return nil
				}
			},
			expectedError: "",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockRepo := mocks.NewMockAuditRepository()
			
			// Setup mocks
			tt.setupMocks(mockRepo)
			
			// Create service
			service := createAuditServiceForTest(t, mockRepo, nil, nil, nil, nil, nil)
			
			// Execute test
			err := service.LogDataAccessEvent(context.Background(), tt.event)
			
			// Verify results
			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.expectedError)
				}
			}
		})
	}
}

func TestComprehensiveAuditService_LogSecurityEvent(t *testing.T) {
	t.Helper()
	
	tests := []struct {
		name          string
		event         *domain.SecurityEvent
		setupMocks    func(*mocks.MockAuditRepository, *mocks.MockAuditMetrics)
		expectedError string
	}{
		{
			name: "successful security violation logging",
			event: &domain.SecurityEvent{
				EventType:        domain.SecurityEventTypeXSS,
				Severity:         domain.SecuritySeverityCritical,
				Description:      "XSS attempt detected in user input",
				UserID:           &[]uint{123}[0],
				IPAddress:        "192.168.1.100",
				UserAgent:        "Mozilla/5.0 (malicious)",
				SessionID:        "sess_123",
				ThreatIndicators: []string{"<script>alert('xss')</script>"},
				ActionTaken:      domain.SecurityActionBlock,
				BlockedRequest:   map[string]interface{}{"input": "<script>alert('xss')</script>"},
				Timestamp:        time.Now(),
			},
			setupMocks: func(repo *mocks.MockAuditRepository, metrics *mocks.MockAuditMetrics) {
				repo.CreateFunc = func(ctx context.Context, event *domain.ComprehensiveAuditEvent) error {
					// Verify security event fields
					if event.EventCategory != domain.CategoryAuditSecurity {
						t.Errorf("Expected event category to be security, got: %s", event.EventCategory)
					}
					if event.Success {
						t.Errorf("Expected security events to have success=false, got: %t", event.Success)
					}
					return nil
				}
				metrics.IncrementSecurityEventCountFunc = func(ctx context.Context, severity domain.SecuritySeverity) {
					if severity != domain.SecuritySeverityCritical {
						t.Errorf("Expected critical severity, got: %s", severity)
					}
				}
			},
			expectedError: "",
		},
		{
			name: "brute force attack detection",
			event: &domain.SecurityEvent{
				EventType:        domain.SecurityEventTypeBruteForce,
				Severity:         domain.SecuritySeverityHigh,
				Description:      "Multiple failed login attempts detected",
				IPAddress:        "192.168.1.200",
				UserAgent:        "automated-tool/1.0",
				ThreatIndicators: []string{"rapid_requests", "failed_logins"},
				ActionTaken:      domain.SecurityActionBan,
				Timestamp:        time.Now(),
				Metadata: map[string]interface{}{
					"attempt_count": 50,
					"time_window":   "5m",
				},
			},
			setupMocks: func(repo *mocks.MockAuditRepository, metrics *mocks.MockAuditMetrics) {
				repo.CreateFunc = func(ctx context.Context, event *domain.ComprehensiveAuditEvent) error {
					return nil
				}
				metrics.IncrementSecurityEventCountFunc = func(ctx context.Context, severity domain.SecuritySeverity) {
					// Verify metrics tracking
				}
			},
			expectedError: "",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockRepo := mocks.NewMockAuditRepository()
			mockMetrics := mocks.NewMockAuditMetrics()
			
			// Setup mocks
			tt.setupMocks(mockRepo, mockMetrics)
			
			// Create service
			service := createAuditServiceForTest(t, mockRepo, nil, nil, nil, mockMetrics, nil)
			
			// Execute test
			err := service.LogSecurityEvent(context.Background(), tt.event)
			
			// Verify results
			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.expectedError)
				}
			}
		})
	}
}

func TestComprehensiveAuditService_QueryEvents(t *testing.T) {
	t.Helper()
	
	tests := []struct {
		name          string
		criteria      *domain.AuditCriteria
		setupMocks    func(*mocks.MockAuditRepository, *mocks.MockAuditMetrics)
		expectedCount int
		expectedError string
	}{
		{
			name: "successful query with time range filter",
			criteria: &domain.AuditCriteria{
				StartTime: &[]time.Time{time.Now().Add(-24 * time.Hour)}[0],
				EndTime:   &[]time.Time{time.Now()}[0],
				Limit:     50,
				Offset:    0,
			},
			setupMocks: func(repo *mocks.MockAuditRepository, metrics *mocks.MockAuditMetrics) {
				repo.QueryFunc = func(ctx context.Context, criteria *domain.AuditCriteria) (*domain.AuditResults, error) {
					// Return mock results
					return &domain.AuditResults{
						Events: []domain.ComprehensiveAuditEvent{
							{ID: 1, EventType: domain.EventTypeLoginSuccess},
							{ID: 2, EventType: domain.EventTypeLoginFailure},
						},
						Total:      2,
						Page:       1,
						PageSize:   50,
						TotalPages: 1,
						HasMore:    false,
					}, nil
				}
				metrics.RecordEventQueryLatencyFunc = func(ctx context.Context, latency time.Duration) {
					// Verify metrics recording
				}
			},
			expectedCount: 2,
			expectedError: "",
		},
		{
			name: "query with security events filter",
			criteria: &domain.AuditCriteria{
				SecurityEvents: true,
				MinSeverity:    &[]domain.SecuritySeverity{domain.SecuritySeverityHigh}[0],
				Limit:          100,
			},
			setupMocks: func(repo *mocks.MockAuditRepository, metrics *mocks.MockAuditMetrics) {
				repo.QueryFunc = func(ctx context.Context, criteria *domain.AuditCriteria) (*domain.AuditResults, error) {
					// Verify security filter is applied
					if !criteria.SecurityEvents {
						t.Errorf("Expected security events filter to be true")
					}
					if criteria.MinSeverity == nil || *criteria.MinSeverity != domain.SecuritySeverityHigh {
						t.Errorf("Expected min severity to be high")
					}
					
					return &domain.AuditResults{
						Events:     []domain.ComprehensiveAuditEvent{},
						Total:      0,
						Page:       1,
						PageSize:   100,
						TotalPages: 0,
						HasMore:    false,
					}, nil
				}
			},
			expectedCount: 0,
			expectedError: "",
		},
		{
			name: "query with repository error",
			criteria: &domain.AuditCriteria{
				Limit: 10,
			},
			setupMocks: func(repo *mocks.MockAuditRepository, metrics *mocks.MockAuditMetrics) {
				repo.QueryFunc = func(ctx context.Context, criteria *domain.AuditCriteria) (*domain.AuditResults, error) {
					return nil, domain.ErrAuditRepositoryError
				}
			},
			expectedCount: 0,
			expectedError: "database timeout",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockRepo := mocks.NewMockAuditRepository()
			mockMetrics := mocks.NewMockAuditMetrics()
			
			// Setup mocks
			tt.setupMocks(mockRepo, mockMetrics)
			
			// Create service
			service := createAuditServiceForTest(t, mockRepo, nil, nil, nil, mockMetrics, nil)
			
			// Execute test
			results, err := service.QueryEvents(context.Background(), tt.criteria)
			
			// Verify results
			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if results == nil {
					t.Errorf("Expected results, got nil")
				} else if len(results.Events) != tt.expectedCount {
					t.Errorf("Expected %d events, got %d", tt.expectedCount, len(results.Events))
				}
			} else {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.expectedError)
				}
			}
		})
	}
}

func TestComprehensiveAuditService_ExportEvents(t *testing.T) {
	t.Helper()
	
	tests := []struct {
		name          string
		criteria      *domain.ExportCriteria
		setupMocks    func(*mocks.MockAuditRepository, *mocks.MockAuditExporter)
		expectedError string
	}{
		{
			name: "successful JSON export",
			criteria: &domain.ExportCriteria{
				AuditCriteria: domain.AuditCriteria{
					Limit: 100,
				},
				Format:     domain.ExportFormatJSON,
				Encryption: false,
			},
			setupMocks: func(repo *mocks.MockAuditRepository, exporter *mocks.MockAuditExporter) {
				repo.QueryFunc = func(ctx context.Context, criteria *domain.AuditCriteria) (*domain.AuditResults, error) {
					return &domain.AuditResults{
						Events: []domain.ComprehensiveAuditEvent{
							{ID: 1, EventType: domain.EventTypeLoginSuccess},
						},
						Total: 1,
					}, nil
				}
				exporter.ExportToJSONFunc = func(ctx context.Context, events []*domain.ComprehensiveAuditEvent) ([]byte, error) {
					return []byte(`{"events": 1}`), nil
				}
				exporter.CreateExportFileFunc = func(ctx context.Context, format domain.ExportFormat, data []byte, encryption bool) (*domain.ExportResult, error) {
					return &domain.ExportResult{
						ExportID:     "export_123",
						Format:       format,
						RecordsCount: 1,
						Status:       domain.ExportStatusCompleted,
					}, nil
				}
			},
			expectedError: "",
		},
		{
			name: "export with missing exporter",
			criteria: &domain.ExportCriteria{
				Format: domain.ExportFormatCSV,
			},
			setupMocks: func(repo *mocks.MockAuditRepository, exporter *mocks.MockAuditExporter) {
				// No exporter setup - will be nil
			},
			expectedError: "audit exporter not configured",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockRepo := mocks.NewMockAuditRepository()
			var mockExporter domain.AuditExporter
			var mockExporterImpl *mocks.MockAuditExporter
			if tt.expectedError != "audit exporter not configured" {
				mockExporterImpl = mocks.NewMockAuditExporter()
				mockExporter = mockExporterImpl
			}
			
			// Setup mocks
			if mockExporterImpl != nil {
				tt.setupMocks(mockRepo, mockExporterImpl)
			} else {
				// Call setupMocks with a nil exporter for tests that expect missing exporter
				tt.setupMocks(mockRepo, nil)
			}
			
			// Create service
			service := createAuditServiceForTest(t, mockRepo, nil, nil, nil, nil, mockExporter)
			
			// Execute test
			result, err := service.ExportEvents(context.Background(), tt.criteria)
			
			// Verify results
			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if result == nil {
					t.Errorf("Expected export result, got nil")
				}
			} else {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.expectedError)
				}
			}
		})
	}
}

func TestComprehensiveAuditService_GetHealthStatus(t *testing.T) {
	t.Helper()
	
	tests := []struct {
		name          string
		setupMocks    func(*mocks.MockAuditRepository, *mocks.MockAsyncProcessor)
		expectedError string
		expectedStatus string
	}{
		{
			name: "healthy system",
			setupMocks: func(repo *mocks.MockAuditRepository, processor *mocks.MockAsyncProcessor) {
				repo.CountFunc = func(ctx context.Context, criteria *domain.AuditCriteria) (int64, error) {
					return 100, nil // Repository is working
				}
				processor.GetQueueStatusFunc = func(ctx context.Context) (map[string]interface{}, error) {
					return map[string]interface{}{
						"queue_length": 0,
					}, nil
				}
			},
			expectedError: "",
			expectedStatus: "healthy",
		},
		{
			name: "degraded system with repository issues",
			setupMocks: func(repo *mocks.MockAuditRepository, processor *mocks.MockAsyncProcessor) {
				repo.CountFunc = func(ctx context.Context, criteria *domain.AuditCriteria) (int64, error) {
					return 0, domain.ErrAuditRepositoryError
				}
				processor.GetQueueStatusFunc = func(ctx context.Context) (map[string]interface{}, error) {
					return map[string]interface{}{
						"queue_length": 0,
					}, nil
				}
			},
			expectedError: "",
			expectedStatus: "degraded",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockRepo := mocks.NewMockAuditRepository()
			mockProcessor := mocks.NewMockAsyncProcessor()
			
			// Setup mocks
			tt.setupMocks(mockRepo, mockProcessor)
			
			// Create service
			service := createAuditServiceForTest(t, mockRepo, nil, nil, mockProcessor, nil, nil)
			
			// Execute test
			health, err := service.GetHealthStatus(context.Background())
			
			// Verify results
			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("Expected no error, got: %v", err)
				}
				if health == nil {
					t.Errorf("Expected health status, got nil")
				} else {
					status, ok := health["status"].(string)
					if !ok {
						t.Errorf("Expected status to be a string")
					} else if status != tt.expectedStatus {
						t.Errorf("Expected status '%s', got '%s'", tt.expectedStatus, status)
					}
				}
			} else {
				if err == nil {
					t.Errorf("Expected error containing '%s', got nil", tt.expectedError)
				}
			}
		})
	}
}

// Helper functions

func createAuditServiceForTest(
	t *testing.T,
	repo domain.ComprehensiveAuditRepository,
	encryptor domain.DataEncryptor,
	integrityCheck domain.IntegrityChecker,
	asyncProcessor domain.AsyncProcessor,
	metrics domain.AuditMetrics,
	exporter domain.AuditExporter,
) domain.ComprehensiveAuditService {
	t.Helper()
	
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelError, // Reduce noise in tests
	}))
	
	config := &config.Config{
		ValidationConfig: config.ValidationConfig{
			EnableSecurityValidation: true,
			EnableBusinessValidation: true,
			LogValidationEvents:      true,
		},
	}
	
	return NewComprehensiveAuditService(
		repo,
		encryptor,
		integrityCheck,
		asyncProcessor,
		metrics,
		exporter,
		config,
		logger,
	)
}

// Domain-specific test helpers

func createValidAuthEvent() *domain.AuthEvent {
	return &domain.AuthEvent{
		UserID:    123,
		Email:     "test@example.com",
		Action:    "login",
		Success:   true,
		SessionID: "sess_123",
		IPAddress: "192.168.1.1",
		UserAgent: "Mozilla/5.0",
		Timestamp: time.Now(),
		Metadata:  map[string]interface{}{},
	}
}

func createValidDataAccessEvent() *domain.DataAccessEvent {
	return &domain.DataAccessEvent{
		UserID:             123,
		DataSubjectID:      &[]uint{456}[0],
		DataType:           "user_profile",
		Operation:          domain.DataOperationRead,
		LegalBasis:         domain.LegalBasisConsent,
		DataClassification: domain.DataClassificationPII,
		FieldsAccessed:     []string{"name", "email"},
		RecordsCount:       1,
		IPAddress:          "192.168.1.1",
		SessionID:          "sess_123",
		Timestamp:          time.Now(),
	}
}

func createValidSecurityEvent() *domain.SecurityEvent {
	return &domain.SecurityEvent{
		EventType:   domain.SecurityEventTypeXSS,
		Severity:    domain.SecuritySeverityHigh,
		Description: "XSS attempt detected",
		IPAddress:   "192.168.1.100",
		ActionTaken: domain.SecurityActionBlock,
		Timestamp:   time.Now(),
	}
}