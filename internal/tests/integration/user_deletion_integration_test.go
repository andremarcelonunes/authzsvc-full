package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/services"
)

// TestUserDeletionIntegration tests the complete LGPD user deletion workflow
func TestUserDeletionIntegration(t *testing.T) {
	t.Log("=== Testing LGPD User Deletion Integration ===")

	// Test deletion request creation
	t.Run("RequestDeletion", func(t *testing.T) {
		// Create mock services for testing
		userRepo := &MockExtendedUserRepository{}
		deletionRepo := &MockDeletionRequestRepository{}
		complianceChecker := &MockLGPDComplianceChecker{}
		auditService := &MockComprehensiveAuditLogger{}
		cascadeDeletor := &MockCascadeDeletor{}

		// Setup user repository mock
		testUser := &domain.User{
			ID:       123,
			Email:    "test@example.com",
			IsActive: true,
		}
		userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
			if id == 123 {
				return testUser, nil
			}
			return nil, domain.ErrUserNotFound
		}

		// Setup compliance checker mock
		complianceChecker.CanDeleteUserFunc = func(ctx context.Context, userID uint) (bool, string, error) {
			return true, "", nil
		}
		complianceChecker.GetRetentionRequirementsFunc = func(ctx context.Context, userID uint) ([]domain.DataRetentionPolicy, error) {
			return []domain.DataRetentionPolicy{}, nil
		}

		// Setup deletion repository mock
		deletionRepo.CreateFunc = func(ctx context.Context, request *domain.DeletionRequest) error {
			// Simulate successful creation
			request.ID = uuid.New()
			return nil
		}

		// Create deletion service
		deletionService := services.NewUserDeletionService(
			userRepo,
			deletionRepo,
			nil, // exportRepo not needed for this test
			nil, // auditRepo not needed for this test
			cascadeDeletor,
			complianceChecker,
			auditService,
			nil, // sessionRepo not needed for this test
			nil, // config will use defaults
		)

		// Test deletion request
		ctx := context.Background()
		request, err := deletionService.RequestDeletion(
			ctx,
			123,
			domain.DeletionTypeFullDelete,
			"User requested account deletion for LGPD compliance",
		)

		// Verify results
		if err != nil {
			t.Fatalf("Failed to create deletion request: %v", err)
		}

		if request == nil {
			t.Fatal("Deletion request should not be nil")
		}

		if request.UserID != 123 {
			t.Errorf("Expected UserID 123, got %d", request.UserID)
		}

		if request.RequestType != domain.DeletionTypeFullDelete {
			t.Errorf("Expected deletion type %s, got %s", domain.DeletionTypeFullDelete, request.RequestType)
		}

		if request.Status != domain.DeletionStatusScheduled {
			t.Errorf("Expected status %s, got %s", domain.DeletionStatusScheduled, request.Status)
		}

		t.Logf("✓ Deletion request created successfully: ID=%s", request.ID)
	})

	// Test compliance blocking
	t.Run("DeletionBlocked", func(t *testing.T) {
		userRepo := &MockExtendedUserRepository{}
		deletionRepo := &MockDeletionRequestRepository{}
		complianceChecker := &MockLGPDComplianceChecker{}
		auditService := &MockComprehensiveAuditLogger{}
		cascadeDeletor := &MockCascadeDeletor{}

		// Setup user repository mock
		testUser := &domain.User{
			ID:       456,
			Email:    "blocked@example.com",
			IsActive: true,
		}
		userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
			if id == 456 {
				return testUser, nil
			}
			return nil, domain.ErrUserNotFound
		}

		// Setup compliance checker to block deletion
		complianceChecker.CanDeleteUserFunc = func(ctx context.Context, userID uint) (bool, string, error) {
			return false, "User has active legal hold", nil
		}

		// Create deletion service
		deletionService := services.NewUserDeletionService(
			userRepo,
			deletionRepo,
			nil,
			nil,
			cascadeDeletor,
			complianceChecker,
			auditService,
			nil,
			nil,
		)

		// Test blocked deletion request
		ctx := context.Background()
		_, err := deletionService.RequestDeletion(
			ctx,
			456,
			domain.DeletionTypeFullDelete,
			"User requested deletion",
		)

		// Verify deletion was blocked
		if err == nil {
			t.Fatal("Expected deletion to be blocked, but it succeeded")
		}

		expectedError := "deletion blocked: User has active legal hold"
		if err.Error() != expectedError {
			t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
		}

		t.Logf("✓ Deletion correctly blocked: %v", err)
	})
}

// Mock implementations for testing

type MockExtendedUserRepository struct {
	FindByIDFunc   func(ctx context.Context, id uint) (*domain.User, error)
	SoftDeleteFunc func(ctx context.Context, userID uint) error
	HardDeleteFunc func(ctx context.Context, userID uint) error
}

func (m *MockExtendedUserRepository) FindByID(ctx context.Context, id uint) (*domain.User, error) {
	if m.FindByIDFunc != nil {
		return m.FindByIDFunc(ctx, id)
	}
	return nil, domain.ErrUserNotFound
}

func (m *MockExtendedUserRepository) SoftDelete(ctx context.Context, userID uint) error {
	if m.SoftDeleteFunc != nil {
		return m.SoftDeleteFunc(ctx, userID)
	}
	return nil
}

func (m *MockExtendedUserRepository) HardDelete(ctx context.Context, userID uint) error {
	if m.HardDeleteFunc != nil {
		return m.HardDeleteFunc(ctx, userID)
	}
	return nil
}

// Implement other required methods with no-op defaults
func (m *MockExtendedUserRepository) Create(ctx context.Context, user *domain.User) error { return nil }
func (m *MockExtendedUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) { return nil, domain.ErrUserNotFound }
func (m *MockExtendedUserRepository) FindByPhone(ctx context.Context, phone string) (*domain.User, error) { return nil, domain.ErrUserNotFound }
func (m *MockExtendedUserRepository) Update(ctx context.Context, user *domain.User) error { return nil }
func (m *MockExtendedUserRepository) ActivatePhone(ctx context.Context, userID uint) error { return nil }
func (m *MockExtendedUserRepository) Anonymize(ctx context.Context, userID uint, anonymousData *domain.AnonymizedUser) error { return nil }
func (m *MockExtendedUserRepository) Deactivate(ctx context.Context, userID uint, reason string) error { return nil }
func (m *MockExtendedUserRepository) Reactivate(ctx context.Context, userID uint) error { return nil }
func (m *MockExtendedUserRepository) IsDeleted(ctx context.Context, userID uint) (bool, error) { return false, nil }
func (m *MockExtendedUserRepository) FindUsersForDeletion(ctx context.Context, beforeDate time.Time) ([]*domain.User, error) { return nil, nil }

type MockDeletionRequestRepository struct {
	CreateFunc        func(ctx context.Context, request *domain.DeletionRequest) error
	CreateExportFunc  func(ctx context.Context, export *domain.UserDataExport) error
	GetExportByIDFunc func(ctx context.Context, id string) (*domain.UserDataExport, error)
	SearchExportsFunc func(ctx context.Context, criteria domain.ExportSearchCriteria) ([]*domain.UserDataExport, error)
	UpdateExportFunc  func(ctx context.Context, export *domain.UserDataExport) error
	SearchFunc        func(ctx context.Context, criteria domain.DeletionSearchCriteria) ([]*domain.DeletionRequest, error)
}

func (m *MockDeletionRequestRepository) Create(ctx context.Context, request *domain.DeletionRequest) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, request)
	}
	return nil
}

func (m *MockDeletionRequestRepository) CreateExport(ctx context.Context, export *domain.UserDataExport) error {
	if m.CreateExportFunc != nil {
		return m.CreateExportFunc(ctx, export)
	}
	return nil
}

func (m *MockDeletionRequestRepository) GetExportByID(ctx context.Context, id string) (*domain.UserDataExport, error) {
	if m.GetExportByIDFunc != nil {
		return m.GetExportByIDFunc(ctx, id)
	}
	return nil, domain.ErrNotFound
}

func (m *MockDeletionRequestRepository) SearchExports(ctx context.Context, criteria domain.ExportSearchCriteria) ([]*domain.UserDataExport, error) {
	if m.SearchExportsFunc != nil {
		return m.SearchExportsFunc(ctx, criteria)
	}
	return []*domain.UserDataExport{}, nil
}

func (m *MockDeletionRequestRepository) UpdateExport(ctx context.Context, export *domain.UserDataExport) error {
	if m.UpdateExportFunc != nil {
		return m.UpdateExportFunc(ctx, export)
	}
	return nil
}

func (m *MockDeletionRequestRepository) Search(ctx context.Context, criteria domain.DeletionSearchCriteria) ([]*domain.DeletionRequest, error) {
	if m.SearchFunc != nil {
		return m.SearchFunc(ctx, criteria)
	}
	return []*domain.DeletionRequest{}, nil
}

func (m *MockDeletionRequestRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.DeletionRequest, error) { return nil, domain.ErrNotFound }
func (m *MockDeletionRequestRepository) FindByUserID(ctx context.Context, userID uint) ([]*domain.DeletionRequest, error) { return nil, nil }
func (m *MockDeletionRequestRepository) Update(ctx context.Context, request *domain.DeletionRequest) error { return nil }
func (m *MockDeletionRequestRepository) ListPending(ctx context.Context, limit int) ([]*domain.DeletionRequest, error) { return nil, nil }
func (m *MockDeletionRequestRepository) ListScheduled(ctx context.Context, beforeTime time.Time) ([]*domain.DeletionRequest, error) { return nil, nil }

type MockLGPDComplianceChecker struct {
	CanDeleteUserFunc           func(ctx context.Context, userID uint) (bool, string, error)
	GetRetentionRequirementsFunc func(ctx context.Context, userID uint) ([]domain.DataRetentionPolicy, error)
}

func (m *MockLGPDComplianceChecker) CanDeleteUser(ctx context.Context, userID uint) (bool, string, error) {
	if m.CanDeleteUserFunc != nil {
		return m.CanDeleteUserFunc(ctx, userID)
	}
	return true, "", nil
}

func (m *MockLGPDComplianceChecker) GetRetentionRequirements(ctx context.Context, userID uint) ([]domain.DataRetentionPolicy, error) {
	if m.GetRetentionRequirementsFunc != nil {
		return m.GetRetentionRequirementsFunc(ctx, userID)
	}
	return []domain.DataRetentionPolicy{}, nil
}

func (m *MockLGPDComplianceChecker) ValidateDeletionRequest(ctx context.Context, request *domain.DeletionRequest) error { return nil }
func (m *MockLGPDComplianceChecker) IsAnonymizationSufficient(ctx context.Context, userID uint) (bool, error) { return true, nil }
func (m *MockLGPDComplianceChecker) GenerateComplianceReport(ctx context.Context, userID uint) (map[string]interface{}, error) { return nil, nil }

type MockComprehensiveAuditLogger struct{}

func (m *MockComprehensiveAuditLogger) LogAuthenticationEvent(ctx context.Context, event *domain.AuthEvent) error { return nil }
func (m *MockComprehensiveAuditLogger) LogLoginAttempt(ctx context.Context, userID uint, email, ipAddress string, success bool, reason string) error { return nil }
func (m *MockComprehensiveAuditLogger) LogLogout(ctx context.Context, userID uint, sessionID, ipAddress string) error { return nil }
func (m *MockComprehensiveAuditLogger) LogPasswordReset(ctx context.Context, userID uint, ipAddress string) error { return nil }
func (m *MockComprehensiveAuditLogger) LogPasswordChangeInitiated(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error { return nil }
func (m *MockComprehensiveAuditLogger) LogPasswordChangeCompleted(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error { return nil }
func (m *MockComprehensiveAuditLogger) LogPasswordChangeFailed(ctx context.Context, userID *uint, requestID, reason, ipAddress, userAgent string) error { return nil }
func (m *MockComprehensiveAuditLogger) LogPasswordChangeCancelled(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error { return nil }
func (m *MockComprehensiveAuditLogger) LogPasswordChangeExpired(ctx context.Context, userID uint, requestID, ipAddress, userAgent string) error { return nil }
func (m *MockComprehensiveAuditLogger) LogAuthorizationEvent(ctx context.Context, event *domain.AuthzEvent) error { return nil }
func (m *MockComprehensiveAuditLogger) LogPermissionCheck(ctx context.Context, userID uint, resource, action string, decision domain.AuthzDecision) error { return nil }
func (m *MockComprehensiveAuditLogger) LogAccessDenied(ctx context.Context, userID uint, resource, action, reason string) error { return nil }
func (m *MockComprehensiveAuditLogger) LogDataAccessEvent(ctx context.Context, event *domain.DataAccessEvent) error { return nil }
func (m *MockComprehensiveAuditLogger) LogDataRead(ctx context.Context, userID, dataSubjectID uint, dataType string, fieldsAccessed []string) error { return nil }
func (m *MockComprehensiveAuditLogger) LogDataWrite(ctx context.Context, userID uint, dataType string, recordsAffected int) error { return nil }
func (m *MockComprehensiveAuditLogger) LogDataExport(ctx context.Context, userID uint, exportType, legalBasis string, recordsCount int) error { return nil }
func (m *MockComprehensiveAuditLogger) LogSecurityEvent(ctx context.Context, event *domain.SecurityEvent) error { return nil }
func (m *MockComprehensiveAuditLogger) LogSecurityViolation(ctx context.Context, eventType domain.SecurityEventType, severity domain.SecuritySeverity, description string, userID *uint, ipAddress string) error { return nil }
func (m *MockComprehensiveAuditLogger) LogBruteForceAttempt(ctx context.Context, ipAddress, userAgent string, attemptCount int) error { return nil }
func (m *MockComprehensiveAuditLogger) LogSuspiciousActivity(ctx context.Context, userID *uint, ipAddress, description string, indicators []string) error { return nil }
func (m *MockComprehensiveAuditLogger) LogSystemEvent(ctx context.Context, eventType string, description string, metadata map[string]interface{}) error { return nil }
func (m *MockComprehensiveAuditLogger) LogUserRegistrationEvent(ctx context.Context, userID uint, email, phone, role string) error { return nil }
func (m *MockComprehensiveAuditLogger) LogConfigChange(ctx context.Context, userID uint, configKey, oldValue, newValue string) error { return nil }
func (m *MockComprehensiveAuditLogger) LogConsentEvent(ctx context.Context, userID uint, consentType, action string, legalBasis domain.LegalBasis) error { return nil }
func (m *MockComprehensiveAuditLogger) LogDataRetentionEvent(ctx context.Context, policy domain.RetentionPolicy, recordsAffected int, description string) error { return nil }
func (m *MockComprehensiveAuditLogger) QueryEvents(ctx context.Context, criteria *domain.AuditCriteria) (*domain.AuditResults, error) { return nil, nil }
func (m *MockComprehensiveAuditLogger) ExportEvents(ctx context.Context, criteria *domain.ExportCriteria) (*domain.ExportResult, error) { return nil, nil }
func (m *MockComprehensiveAuditLogger) GetHealthStatus(ctx context.Context) (map[string]interface{}, error) { return nil, nil }
func (m *MockComprehensiveAuditLogger) GetMetrics(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error) { return nil, nil }

type MockCascadeDeletor struct{}

func (m *MockCascadeDeletor) DeleteUserSessions(ctx context.Context, userID uint) (int, error) { return 1, nil }
func (m *MockCascadeDeletor) DeleteUserOTPRequests(ctx context.Context, userID uint) (int, error) { return 0, nil }
func (m *MockCascadeDeletor) DeletePasswordHistory(ctx context.Context, userID uint) (int, error) { return 0, nil }
func (m *MockCascadeDeletor) DeleteOrAnonymizeAuditLogs(ctx context.Context, userID uint, anonymize bool) (int, error) { return 5, nil }
func (m *MockCascadeDeletor) DeleteUserPolicies(ctx context.Context, userID uint) (int, error) { return 0, nil }
func (m *MockCascadeDeletor) DeleteUserTokens(ctx context.Context, userID uint) (int, error) { return 0, nil }
func (m *MockCascadeDeletor) GetUserDataSummary(ctx context.Context, userID uint) (map[string]int, error) {
	return map[string]int{
		"sessions":    1,
		"audit_logs": 5,
		"tokens":     0,
	}, nil
}