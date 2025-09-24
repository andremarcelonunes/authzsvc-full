package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

func TestUserDeletionService_RequestDeletion(t *testing.T) {
	tests := []struct {
		name           string
		userID         uint
		requestType    domain.DeletionRequestType
		reason         string
		setupMocks     func(*testDeletionServiceMocks)
		expectedError  string
		validateResult func(t *testing.T, request *domain.DeletionRequest, err error)
	}{
		{
			name:        "successful full deletion request",
			userID:      123,
			requestType: domain.DeletionTypeFullDelete,
			reason:      "User requested account deletion for LGPD compliance",
			setupMocks: func(mocks *testDeletionServiceMocks) {
				setupSuccessfulDeletionRequest(t, mocks, 123)
			},
			expectedError: "",
			validateResult: func(t *testing.T, request *domain.DeletionRequest, err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if request == nil {
					t.Fatal("request should not be nil")
				}
				if request.UserID != 123 {
					t.Errorf("expected UserID 123, got %d", request.UserID)
				}
				if request.RequestType != domain.DeletionTypeFullDelete {
					t.Errorf("expected request type %s, got %s", domain.DeletionTypeFullDelete, request.RequestType)
				}
				if request.Status != domain.DeletionStatusScheduled {
					t.Errorf("expected status %s, got %s", domain.DeletionStatusScheduled, request.Status)
				}
				if request.Reason != "User requested account deletion for LGPD compliance" {
					t.Errorf("expected reason to match, got %s", request.Reason)
				}
			},
		},
		{
			name:        "user not found",
			userID:      999,
			requestType: domain.DeletionTypeFullDelete,
			reason:      "Test deletion",
			setupMocks: func(mocks *testDeletionServiceMocks) {
				mocks.userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
					return nil, domain.ErrUserNotFound
				}
			},
			expectedError: "user not found",
			validateResult: func(t *testing.T, request *domain.DeletionRequest, err error) {
				t.Helper()
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if request != nil {
					t.Error("request should be nil when error occurs")
				}
			},
		},
		{
			name:        "deletion blocked by compliance check",
			userID:      456,
			requestType: domain.DeletionTypeFullDelete,
			reason:      "Test deletion",
			setupMocks: func(mocks *testDeletionServiceMocks) {
				setupDeletionBlockedByCompliance(t, mocks, 456)
			},
			expectedError: "deletion blocked: User has active legal hold",
			validateResult: func(t *testing.T, request *domain.DeletionRequest, err error) {
				t.Helper()
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if request != nil {
					t.Error("request should be nil when blocked")
				}
			},
		},
		{
			name:        "successful soft deletion request",
			userID:      789,
			requestType: domain.DeletionTypeSoftDelete,
			reason:      "Temporary deactivation",
			setupMocks: func(mocks *testDeletionServiceMocks) {
				setupSuccessfulDeletionRequest(t, mocks, 789)
			},
			expectedError: "",
			validateResult: func(t *testing.T, request *domain.DeletionRequest, err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if request.RequestType != domain.DeletionTypeSoftDelete {
					t.Errorf("expected request type %s, got %s", domain.DeletionTypeSoftDelete, request.RequestType)
				}
			},
		},
		{
			name:        "successful anonymization request",
			userID:      101,
			requestType: domain.DeletionTypeAnonymization,
			reason:      "LGPD compliance with retention requirements",
			setupMocks: func(mocks *testDeletionServiceMocks) {
				setupSuccessfulDeletionRequest(t, mocks, 101)
			},
			expectedError: "",
			validateResult: func(t *testing.T, request *domain.DeletionRequest, err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if request.RequestType != domain.DeletionTypeAnonymization {
					t.Errorf("expected request type %s, got %s", domain.DeletionTypeAnonymization, request.RequestType)
				}
			},
		},
		{
			name:        "repository create failure",
			userID:      555,
			requestType: domain.DeletionTypeFullDelete,
			reason:      "Test deletion",
			setupMocks: func(mocks *testDeletionServiceMocks) {
				// Setup successful user lookup and compliance check
				mocks.userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
					return &domain.User{ID: id, Email: "test@example.com", IsActive: true}, nil
				}
				mocks.complianceChecker.CanDeleteUserFunc = func(ctx context.Context, userID uint) (bool, string, error) {
					return true, "", nil
				}
				mocks.complianceChecker.GetRetentionRequirementsFunc = func(ctx context.Context, userID uint) ([]domain.DataRetentionPolicy, error) {
					return []domain.DataRetentionPolicy{}, nil
				}
				// Setup repository create failure
				mocks.deletionRepo.CreateFunc = func(ctx context.Context, request *domain.DeletionRequest) error {
					return errors.New("database connection failed")
				}
			},
			expectedError: "failed to create deletion request: database connection failed",
			validateResult: func(t *testing.T, request *domain.DeletionRequest, err error) {
				t.Helper()
				if err == nil {
					t.Fatal("expected error but got none")
				}
				if request != nil {
					t.Error("request should be nil when create fails")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mocks := createDeletionServiceMocks(t)
			
			// Setup mocks for this test
			tt.setupMocks(mocks)
			
			// Create service
			service := createDeletionServiceForTest(t, mocks)
			
			// Execute test
			ctx := context.Background()
			result, err := service.RequestDeletion(ctx, tt.userID, tt.requestType, tt.reason)
			
			// Validate error
			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error containing '%s', got none", tt.expectedError)
				}
				if !containsString(err.Error(), tt.expectedError) {
					t.Errorf("expected error to contain '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			
			// Run custom validation
			if tt.validateResult != nil {
				tt.validateResult(t, result, err)
			}
		})
	}
}

func TestUserDeletionService_ProcessDeletionRequest(t *testing.T) {
	tests := []struct {
		name          string
		requestID     uuid.UUID
		setupMocks    func(*testDeletionServiceMocks, uuid.UUID)
		expectedError string
	}{
		{
			name:      "successful full deletion processing",
			requestID: uuid.New(),
			setupMocks: func(mocks *testDeletionServiceMocks, requestID uuid.UUID) {
				setupSuccessfulFullDeletionProcessing(t, mocks, requestID)
			},
			expectedError: "",
		},
		{
			name:      "request not found",
			requestID: uuid.New(),
			setupMocks: func(mocks *testDeletionServiceMocks, requestID uuid.UUID) {
				mocks.deletionRepo.FindByIDFunc = func(ctx context.Context, id uuid.UUID) (*domain.DeletionRequest, error) {
					return nil, domain.ErrNotFound
				}
			},
			expectedError: "record not found",
		},
		{
			name:      "user hard delete failure",
			requestID: uuid.New(),
			setupMocks: func(mocks *testDeletionServiceMocks, requestID uuid.UUID) {
				// Setup request found but user deletion fails
				request := &domain.DeletionRequest{
					ID:          requestID,
					UserID:      123,
					RequestType: domain.DeletionTypeFullDelete,
					Status:      domain.DeletionStatusScheduled,
				}
				mocks.deletionRepo.FindByIDFunc = func(ctx context.Context, id uuid.UUID) (*domain.DeletionRequest, error) {
					return request, nil
				}
				mocks.userRepo.HardDeleteFunc = func(ctx context.Context, userID uint) error {
					return errors.New("database constraint violation")
				}
				// Other mocks with defaults
				mocks.cascadeDeletor.DeleteUserSessionsFunc = func(ctx context.Context, userID uint) (int, error) {
					return 1, nil
				}
				mocks.cascadeDeletor.GetUserDataSummaryFunc = func(ctx context.Context, userID uint) (map[string]int, error) {
					return map[string]int{"sessions": 1}, nil
				}
				mocks.deletionRepo.UpdateFunc = func(ctx context.Context, request *domain.DeletionRequest) error {
					return nil
				}
			},
			expectedError: "failed to delete user: database constraint violation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mocks := createDeletionServiceMocks(t)
			
			// Setup mocks for this test
			tt.setupMocks(mocks, tt.requestID)
			
			// Create service
			service := createDeletionServiceForTest(t, mocks)
			
			// Execute test
			ctx := context.Background()
			err := service.ProcessDeletionRequest(ctx, tt.requestID)
			
			// Validate error
			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error containing '%s', got none", tt.expectedError)
				}
				if !containsString(err.Error(), tt.expectedError) {
					t.Errorf("expected error to contain '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else if err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

func TestUserDeletionService_GetDeletionStatus(t *testing.T) {
	requestID := uuid.New()
	
	tests := []struct {
		name          string
		setupMocks    func(*testDeletionServiceMocks)
		expectedError string
		validateResult func(t *testing.T, request *domain.DeletionRequest)
	}{
		{
			name: "successful status retrieval",
			setupMocks: func(mocks *testDeletionServiceMocks) {
				expectedRequest := &domain.DeletionRequest{
					ID:          requestID,
					UserID:      123,
					RequestType: domain.DeletionTypeFullDelete,
					Status:      domain.DeletionStatusCompleted,
					Reason:      "User requested deletion",
				}
				mocks.deletionRepo.FindByIDFunc = func(ctx context.Context, id uuid.UUID) (*domain.DeletionRequest, error) {
					return expectedRequest, nil
				}
			},
			expectedError: "",
			validateResult: func(t *testing.T, request *domain.DeletionRequest) {
				t.Helper()
				if request == nil {
					t.Fatal("request should not be nil")
				}
				if request.Status != domain.DeletionStatusCompleted {
					t.Errorf("expected status %s, got %s", domain.DeletionStatusCompleted, request.Status)
				}
			},
		},
		{
			name: "request not found",
			setupMocks: func(mocks *testDeletionServiceMocks) {
				mocks.deletionRepo.FindByIDFunc = func(ctx context.Context, id uuid.UUID) (*domain.DeletionRequest, error) {
					return nil, domain.ErrNotFound
				}
			},
			expectedError: "record not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mocks := createDeletionServiceMocks(t)
			
			// Setup mocks for this test
			tt.setupMocks(mocks)
			
			// Create service
			service := createDeletionServiceForTest(t, mocks)
			
			// Execute test
			ctx := context.Background()
			result, err := service.GetDeletionStatus(ctx, requestID)
			
			// Validate error
			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error containing '%s', got none", tt.expectedError)
				}
				if !containsString(err.Error(), tt.expectedError) {
					t.Errorf("expected error to contain '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
			
			// Run custom validation
			if tt.validateResult != nil {
				tt.validateResult(t, result)
			}
		})
	}
}

func TestUserDeletionService_CancelDeletionRequest(t *testing.T) {
	requestID := uuid.New()
	
	tests := []struct {
		name          string
		setupMocks    func(*testDeletionServiceMocks)
		expectedError string
	}{
		{
			name: "successful cancellation",
			setupMocks: func(mocks *testDeletionServiceMocks) {
				request := &domain.DeletionRequest{
					ID:          requestID,
					UserID:      123,
					Status:      domain.DeletionStatusScheduled,
				}
				mocks.deletionRepo.FindByIDFunc = func(ctx context.Context, id uuid.UUID) (*domain.DeletionRequest, error) {
					return request, nil
				}
				mocks.deletionRepo.UpdateFunc = func(ctx context.Context, req *domain.DeletionRequest) error {
					// Verify status was changed to cancelled
					if req.Status != domain.DeletionStatusCancelled {
						t.Errorf("expected status to be cancelled, got %s", req.Status)
					}
					return nil
				}
			},
			expectedError: "",
		},
		{
			name: "request not found",
			setupMocks: func(mocks *testDeletionServiceMocks) {
				mocks.deletionRepo.FindByIDFunc = func(ctx context.Context, id uuid.UUID) (*domain.DeletionRequest, error) {
					return nil, domain.ErrNotFound
				}
			},
			expectedError: "record not found",
		},
		{
			name: "cannot cancel completed request",
			setupMocks: func(mocks *testDeletionServiceMocks) {
				request := &domain.DeletionRequest{
					ID:     requestID,
					Status: domain.DeletionStatusCompleted,
				}
				mocks.deletionRepo.FindByIDFunc = func(ctx context.Context, id uuid.UUID) (*domain.DeletionRequest, error) {
					return request, nil
				}
			},
			expectedError: "cannot cancel request with status: completed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mocks := createDeletionServiceMocks(t)
			
			// Setup mocks for this test
			tt.setupMocks(mocks)
			
			// Create service
			service := createDeletionServiceForTest(t, mocks)
			
			// Execute test
			ctx := context.Background()
			err := service.CancelDeletionRequest(ctx, requestID, "Test cancellation")
			
			// Validate error
			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error containing '%s', got none", tt.expectedError)
				}
				if !containsString(err.Error(), tt.expectedError) {
					t.Errorf("expected error to contain '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else if err != nil {
				t.Fatalf("expected no error, got: %v", err)
			}
		})
	}
}

// Test helper structs and functions

type testDeletionServiceMocks struct {
	userRepo           *mocks.MockExtendedUserRepository
	deletionRepo       *mocks.MockDeletionRequestRepository
	exportRepo         *mocks.MockDataExportRepository
	auditRepo          *mocks.MockDeletionAuditRepository
	cascadeDeletor     *mocks.MockDataCascadeDeletor
	complianceChecker  *mocks.MockLGPDComplianceChecker
	auditService       *mocks.MockComprehensiveAuditService
	sessionRepo        *mocks.MockSessionRepository
}

func createDeletionServiceMocks(t *testing.T) *testDeletionServiceMocks {
	t.Helper()
	
	return &testDeletionServiceMocks{
		userRepo:          mocks.NewMockExtendedUserRepository(),
		deletionRepo:      mocks.NewMockDeletionRequestRepository(),
		exportRepo:        mocks.NewMockDataExportRepository(),
		auditRepo:         mocks.NewMockDeletionAuditRepository(),
		cascadeDeletor:    mocks.NewMockDataCascadeDeletor(),
		complianceChecker: mocks.NewMockLGPDComplianceChecker(),
		auditService:      mocks.NewMockComprehensiveAuditService(),
		sessionRepo:       mocks.NewMockSessionRepository(),
	}
}

func createDeletionServiceForTest(t *testing.T, mocks *testDeletionServiceMocks) *UserDeletionService {
	t.Helper()
	
	config := DefaultUserDeletionConfig()
	
	return NewUserDeletionService(
		mocks.userRepo,
		mocks.deletionRepo,
		mocks.exportRepo,
		mocks.auditRepo,
		mocks.cascadeDeletor,
		mocks.complianceChecker,
		mocks.auditService,
		mocks.sessionRepo,
		config,
	)
}

func setupSuccessfulDeletionRequest(t *testing.T, mocks *testDeletionServiceMocks, userID uint) {
	t.Helper()
	
	// Mock user exists and is active
	mocks.userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
		if id == userID {
			return &domain.User{ID: id, Email: "test@example.com", IsActive: true}, nil
		}
		return nil, domain.ErrUserNotFound
	}
	
	// Mock compliance check allows deletion
	mocks.complianceChecker.CanDeleteUserFunc = func(ctx context.Context, id uint) (bool, string, error) {
		return true, "", nil
	}
	
	mocks.complianceChecker.GetRetentionRequirementsFunc = func(ctx context.Context, id uint) ([]domain.DataRetentionPolicy, error) {
		return []domain.DataRetentionPolicy{}, nil
	}
	
	// Mock deletion request creation succeeds
	mocks.deletionRepo.CreateFunc = func(ctx context.Context, request *domain.DeletionRequest) error {
		// Simulate database ID assignment
		if request.ID == uuid.Nil {
			request.ID = uuid.New()
		}
		return nil
	}
}

func setupDeletionBlockedByCompliance(t *testing.T, mocks *testDeletionServiceMocks, userID uint) {
	t.Helper()
	
	// Mock user exists and is active
	mocks.userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
		if id == userID {
			return &domain.User{ID: id, Email: "blocked@example.com", IsActive: true}, nil
		}
		return nil, domain.ErrUserNotFound
	}
	
	// Mock compliance check blocks deletion
	mocks.complianceChecker.CanDeleteUserFunc = func(ctx context.Context, id uint) (bool, string, error) {
		return false, "User has active legal hold", nil
	}
}

func setupSuccessfulFullDeletionProcessing(t *testing.T, mocks *testDeletionServiceMocks, requestID uuid.UUID) {
	t.Helper()
	
	request := &domain.DeletionRequest{
		ID:          requestID,
		UserID:      123,
		RequestType: domain.DeletionTypeFullDelete,
		Status:      domain.DeletionStatusScheduled,
	}
	
	// Mock request found
	mocks.deletionRepo.FindByIDFunc = func(ctx context.Context, id uuid.UUID) (*domain.DeletionRequest, error) {
		return request, nil
	}
	
	// Mock successful cascade deletion
	mocks.cascadeDeletor.DeleteUserSessionsFunc = func(ctx context.Context, userID uint) (int, error) {
		return 1, nil
	}
	
	mocks.cascadeDeletor.GetUserDataSummaryFunc = func(ctx context.Context, userID uint) (map[string]int, error) {
		return map[string]int{
			"sessions":    1,
			"audit_logs": 5,
		}, nil
	}
	
	// Mock successful user hard delete
	mocks.userRepo.HardDeleteFunc = func(ctx context.Context, userID uint) error {
		return nil
	}
	
	// Mock successful request update
	mocks.deletionRepo.UpdateFunc = func(ctx context.Context, req *domain.DeletionRequest) error {
		return nil
	}
}

// Helper functions are imported from existing test utilities in the package