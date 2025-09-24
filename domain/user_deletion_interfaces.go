package domain

import (
	"context"
	"time"
	"github.com/google/uuid"
)

// UserDeletionService handles LGPD-compliant user deletion operations
type UserDeletionService interface {
	// Request deletion/anonymization
	RequestDeletion(ctx context.Context, userID uint, requestType DeletionRequestType, reason string) (*DeletionRequest, error)
	ProcessDeletionRequest(ctx context.Context, requestID uuid.UUID) error
	GetDeletionStatus(ctx context.Context, requestID uuid.UUID) (*DeletionRequest, error)
	CancelDeletionRequest(ctx context.Context, requestID uuid.UUID, reason string) error
	
	// Data export for portability
	ExportUserData(ctx context.Context, userID uint, format string) (*UserDataExport, error)
	GetExportStatus(ctx context.Context, exportID uuid.UUID) (*UserDataExport, error)
	
	// Anonymization operations
	AnonymizeUser(ctx context.Context, userID uint, retainForLegal bool) error
	GetAnonymizedUserData(ctx context.Context, anonymousID string) (*AnonymizedUser, error)
	
	// Compliance queries
	GetRetentionPolicy(ctx context.Context, dataType string) (*DataRetentionPolicy, error)
	ListPendingDeletions(ctx context.Context, olderThan time.Duration) ([]*DeletionRequest, error)
	GetDeletionAuditLog(ctx context.Context, userID uint) ([]*DeletionAuditLog, error)
}

// ExtendedUserRepository adds deletion capabilities to UserRepository
type ExtendedUserRepository interface {
	UserRepository // Inherit existing methods
	
	// Soft delete (retains data but marks as deleted)
	SoftDelete(ctx context.Context, userID uint) error
	
	// Hard delete (permanent deletion)
	HardDelete(ctx context.Context, userID uint) error
	
	// Anonymize user data
	Anonymize(ctx context.Context, userID uint, anonymousData *AnonymizedUser) error
	
	// Deactivate user (sets is_active = false)
	Deactivate(ctx context.Context, userID uint, reason string) error
	
	// Reactivate user (for cases where deletion was cancelled)
	Reactivate(ctx context.Context, userID uint) error
	
	// Check if user has been deleted
	IsDeleted(ctx context.Context, userID uint) (bool, error)
	
	// Find users scheduled for deletion
	FindUsersForDeletion(ctx context.Context, beforeDate time.Time) ([]*User, error)
}

// DeletionRequestRepository handles deletion request persistence
type DeletionRequestRepository interface {
	Create(ctx context.Context, request *DeletionRequest) error
	FindByID(ctx context.Context, id uuid.UUID) (*DeletionRequest, error)
	FindByUserID(ctx context.Context, userID uint) ([]*DeletionRequest, error)
	Update(ctx context.Context, request *DeletionRequest) error
	ListPending(ctx context.Context, limit int) ([]*DeletionRequest, error)
	ListScheduled(ctx context.Context, beforeTime time.Time) ([]*DeletionRequest, error)
	Search(ctx context.Context, criteria DeletionSearchCriteria) ([]*DeletionRequest, error)
	
	// Export methods
	CreateExport(ctx context.Context, export *UserDataExport) error
	GetExportByID(ctx context.Context, id string) (*UserDataExport, error)
	SearchExports(ctx context.Context, criteria ExportSearchCriteria) ([]*UserDataExport, error)
	UpdateExport(ctx context.Context, export *UserDataExport) error
}

// DataExportRepository handles data export records
type DataExportRepository interface {
	Create(ctx context.Context, export *UserDataExport) error
	FindByID(ctx context.Context, id uuid.UUID) (*UserDataExport, error)
	FindByUserID(ctx context.Context, userID uint) ([]*UserDataExport, error)
	Update(ctx context.Context, export *UserDataExport) error
	DeleteExpired(ctx context.Context, beforeTime time.Time) error
}

// DeletionAuditRepository handles deletion audit logs
type DeletionAuditRepository interface {
	Create(ctx context.Context, log *DeletionAuditLog) error
	FindByRequestID(ctx context.Context, requestID uuid.UUID) ([]*DeletionAuditLog, error)
	FindByUserID(ctx context.Context, userID uint) ([]*DeletionAuditLog, error)
	// Audit logs should never be deleted, only archived
}

// DataCascadeDeletor handles cascade deletion of related data
type DataCascadeDeletor interface {
	// Delete all user sessions
	DeleteUserSessions(ctx context.Context, userID uint) (int, error)
	
	// Delete all OTP requests
	DeleteUserOTPRequests(ctx context.Context, userID uint) (int, error)
	
	// Delete password change history
	DeletePasswordHistory(ctx context.Context, userID uint) (int, error)
	
	// Delete audit logs (if allowed by policy)
	DeleteOrAnonymizeAuditLogs(ctx context.Context, userID uint, anonymize bool) (int, error)
	
	// Delete user policies/permissions
	DeleteUserPolicies(ctx context.Context, userID uint) (int, error)
	
	// Delete refresh tokens
	DeleteUserTokens(ctx context.Context, userID uint) (int, error)
	
	// Get summary of all related data
	GetUserDataSummary(ctx context.Context, userID uint) (map[string]int, error)
}

// LGPDComplianceChecker validates LGPD compliance for deletion operations
type LGPDComplianceChecker interface {
	// Check if user can be deleted (no legal holds, etc.)
	CanDeleteUser(ctx context.Context, userID uint) (bool, string, error)
	
	// Check retention requirements
	GetRetentionRequirements(ctx context.Context, userID uint) ([]DataRetentionPolicy, error)
	
	// Validate deletion request
	ValidateDeletionRequest(ctx context.Context, request *DeletionRequest) error
	
	// Check if anonymization is sufficient
	IsAnonymizationSufficient(ctx context.Context, userID uint) (bool, error)
	
	// Generate compliance report
	GenerateComplianceReport(ctx context.Context, userID uint) (map[string]interface{}, error)
}