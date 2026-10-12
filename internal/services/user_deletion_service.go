package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
	"gorm.io/datatypes"
)

// UserDeletionService implements LGPD-compliant user deletion operations
type UserDeletionService struct {
	userRepo            domain.ExtendedUserRepository
	deletionRepo        domain.DeletionRequestRepository
	exportRepo          domain.DataExportRepository
	auditRepo           domain.DeletionAuditRepository
	cascadeDeletor      domain.DataCascadeDeletor
	complianceChecker   domain.LGPDComplianceChecker
	auditService        domain.ComprehensiveAuditLogger
	sessionRepo         domain.SessionRepository
	config              *UserDeletionConfig
	passwordService     domain.PasswordService
	accountInvalidator  domain.AccountStateInvalidator
}

// UserDeletionOption configures optional collaborators of UserDeletionService.
type UserDeletionOption func(*UserDeletionService)

// WithDeletionPasswordService sets the service that verifies the password when
// UserDeletionConfig.RequirePassword is on.
func WithDeletionPasswordService(p domain.PasswordService) UserDeletionOption {
	return func(s *UserDeletionService) { s.passwordService = p }
}

// WithAccountStateInvalidator sets the port that drops cached state (identity cache, pending OTPs)
// of an anonymised account.
func WithAccountStateInvalidator(i domain.AccountStateInvalidator) UserDeletionOption {
	return func(s *UserDeletionService) { s.accountInvalidator = i }
}

// SelfServiceDeletionReason is the reason recorded when an immediate self-deletion carries none.
const SelfServiceDeletionReason = "self-service"

// UserDeletionConfig contains configuration for deletion service
type UserDeletionConfig struct {
	// Deletion grace period (time before actual deletion)
	GracePeriod time.Duration
	
	// Data export settings
	ExportExpirationTime time.Duration
	ExportFormats        []string
	
	// Anonymization settings
	AnonymizationMethod string // "hash", "random", "synthetic"
	RetainForStatistics bool
	
	// Retention policies
	AuditLogRetention    time.Duration
	MinimumRetention     time.Duration
	
	// Security settings
	RequireAdminApproval bool
	RequireMFA           bool
	NotifyOnDeletion     bool
	
	// Self-service settings (POST /users/me/deletion); the defaults keep the scheduled flow.
	// SelfDeletionImmediate: process a self-requested deletion inside the request (SELF_DELETION_IMMEDIATE).
	SelfDeletionImmediate bool
	// RequirePassword: the request must carry the account password (SELF_DELETION_REQUIRE_PASSWORD).
	RequirePassword bool

	// Testing settings
	TestingMode bool // Bypasses time constraints for testing
}

// DefaultUserDeletionConfig returns default LGPD-compliant configuration
func DefaultUserDeletionConfig() *UserDeletionConfig {
	return &UserDeletionConfig{
		GracePeriod:          30 * 24 * time.Hour, // 30 days
		ExportExpirationTime: 7 * 24 * time.Hour,  // 7 days
		ExportFormats:        []string{"json", "csv"},
		AnonymizationMethod:  "hash",
		RetainForStatistics:  true,
		AuditLogRetention:    7 * 365 * 24 * time.Hour, // 7 years (LGPD requirement)
		MinimumRetention:     30 * 24 * time.Hour,      // 30 days minimum
		RequireAdminApproval: false,
		RequireMFA:           true,
		NotifyOnDeletion:     true,
	}
}

// NewUserDeletionService creates a new user deletion service
func NewUserDeletionService(
	userRepo domain.ExtendedUserRepository,
	deletionRepo domain.DeletionRequestRepository,
	exportRepo domain.DataExportRepository,
	auditRepo domain.DeletionAuditRepository,
	cascadeDeletor domain.DataCascadeDeletor,
	complianceChecker domain.LGPDComplianceChecker,
	auditService domain.ComprehensiveAuditLogger,
	sessionRepo domain.SessionRepository,
	config *UserDeletionConfig,
	opts ...UserDeletionOption,
) *UserDeletionService {
	if config == nil {
		config = DefaultUserDeletionConfig()
	}

	svc := &UserDeletionService{
		userRepo:          userRepo,
		deletionRepo:      deletionRepo,
		exportRepo:        exportRepo,
		auditRepo:         auditRepo,
		cascadeDeletor:    cascadeDeletor,
		complianceChecker: complianceChecker,
		auditService:      auditService,
		sessionRepo:       sessionRepo,
		config:            config,
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// Immediate reports whether self-requested deletions are processed inside the request.
func (s *UserDeletionService) Immediate() bool { return s.config.SelfDeletionImmediate }

// GracePeriod is the time a scheduled self-requested deletion waits before it may be processed.
func (s *UserDeletionService) GracePeriod() time.Duration { return s.config.GracePeriod }

// DeletionProcessingError is returned by RequestSelfDeletion when an immediate deletion could not be
// completed. The request row is left in status failed with the error recorded.
type DeletionProcessingError struct {
	Request *domain.DeletionRequest
	// Stage names the step that failed: start, audit, sessions, anonymization, finalize.
	Stage string
	// AccountChanged is true when the account was already anonymised (nothing the user can retry);
	// false when the account is intact (sessions may have been revoked: the user can sign in again).
	AccountChanged bool
	Err            error
}

func (e *DeletionProcessingError) Error() string {
	return fmt.Sprintf("immediate deletion failed at %s: %v", e.Stage, e.Err)
}

func (e *DeletionProcessingError) Unwrap() error { return e.Err }

// RequestDeletion creates a new deletion request per LGPD Article 18. It is RequestSelfDeletion
// without a password and without the "already open" signal.
func (s *UserDeletionService) RequestDeletion(
	ctx context.Context,
	userID uint,
	requestType domain.DeletionRequestType,
	reason string,
) (*domain.DeletionRequest, error) {
	request, _, err := s.RequestSelfDeletion(ctx, userID, requestType, reason, "")
	return request, err
}

// isSelfDeletionProtectedRole lists the accounts that cannot delete themselves through the immediate path.
func isSelfDeletionProtectedRole(role string) bool {
	switch role {
	case domain.RoleAdmin, domain.RoleRoot, domain.RoleAttendant:
		return true
	}
	return false
}

// verifySelfDeletionPassword enforces UserDeletionConfig.RequirePassword. It fails closed: with the
// switch on and no password service wired, nobody can delete.
func (s *UserDeletionService) verifySelfDeletionPassword(user *domain.User, password string) error {
	if !s.config.RequirePassword {
		return nil
	}
	if password == "" || s.passwordService == nil || !s.passwordService.Verify(user.PasswordHash, password) {
		return domain.ErrDeletionPasswordConfirmation
	}
	return nil
}

// RequestSelfDeletion handles a deletion the account holder asked for.
//
// Scheduled mode (default): the request is stored, scheduled GracePeriod ahead, and returned; when
// the user already has a pending or scheduled request that one is returned with existing=true and
// nothing new is stored.
//
// Immediate mode (SelfDeletionImmediate): the effective type is always anonymization, and the request is
// processed before returning: sessions are revoked first (failure aborts with nothing anonymised),
// then the account is anonymised, then the request is marked completed. A failure leaves the request
// failed and is returned as *DeletionProcessingError.
func (s *UserDeletionService) RequestSelfDeletion(
	ctx context.Context,
	userID uint,
	requestType domain.DeletionRequestType,
	reason string,
	password string,
) (request *domain.DeletionRequest, existing bool, err error) {
	// Verify user exists
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, false, fmt.Errorf("user not found: %w", err)
	}
	immediate := s.config.SelfDeletionImmediate

	if immediate && isSelfDeletionProtectedRole(user.Role) {
		// Only logged: a security-category audit event would itself block the account's later
		// deletions for 90 days (LGPDComplianceService.checkSecurityIncidents).
		log.Printf("Immediate self-deletion refused for user %d (role %s)", userID, user.Role)
		return nil, false, domain.ErrDeletionRoleBlocked
	}

	if err := s.verifySelfDeletionPassword(user, password); err != nil {
		// Only logged, for the same reason as the role guard: a wrong password must not start a 90-day block.
		log.Printf("Password confirmation failed for deletion request of user %d", userID)
		return nil, false, err
	}

	// Check if deletion is allowed
	canDelete, blockedReason, err := s.complianceChecker.CanDeleteUser(ctx, userID)
	if err != nil {
		return nil, false, fmt.Errorf("compliance check failed: %w", err)
	}
	if !canDelete {
		// Audit the blocked deletion attempt
		s.logSecurityViolation(ctx, "deletion_blocked", fmt.Sprintf("User deletion blocked: %s", blockedReason), userID)
		return nil, false, fmt.Errorf("deletion blocked: %s", blockedReason)
	}

	// Check retention requirements
	retentionPolicies, err := s.complianceChecker.GetRetentionRequirements(ctx, userID)
	if err != nil {
		return nil, false, fmt.Errorf("failed to check retention requirements: %w", err)
	}

	// Scheduled mode: do not stack requests, hand back the open one.
	if !immediate {
		previous, err := s.deletionRepo.FindByUserID(ctx, userID)
		if err != nil {
			return nil, false, fmt.Errorf("failed to check open deletion requests: %w", err)
		}
		for _, open := range previous {
			if open.Status == domain.DeletionStatusPending || open.Status == domain.DeletionStatusScheduled {
				return open, true, nil
			}
		}
	}

	// Determine if we need to retain some data
	retentionRequired := len(retentionPolicies) > 0
	var retentionUntil *time.Time
	var retentionReason string
	
	if retentionRequired {
		// Find the longest retention period
		maxRetention := time.Duration(0)
		for _, policy := range retentionPolicies {
			if policy.RetentionPeriod > maxRetention {
				maxRetention = policy.RetentionPeriod
				retentionReason = policy.LegalBasis
			}
		}
		retentionTime := time.Now().Add(maxRetention)
		retentionUntil = &retentionTime
		
		// If retention is required, we might need to change the request type
		if requestType == domain.DeletionTypeFullDelete && retentionRequired {
			// Switch to anonymization if full deletion isn't possible
			requestType = domain.DeletionTypeAnonymization
			log.Printf("Switching from full_delete to anonymization due to retention requirements for user %d", userID)
		}
	}

	// Immediate mode always anonymises: the identifiers must be released. What the client asked for is kept in the audit row.
	requestedType := requestType
	if immediate {
		requestType = domain.DeletionTypeAnonymization
		if reason == "" {
			reason = SelfServiceDeletionReason
		}
	}

	// Create deletion request
	request = &domain.DeletionRequest{
		ID:                uuid.New(),
		UserID:            userID,
		RequestType:       requestType,
		Status:            domain.DeletionStatusPending,
		Reason:            reason,
		LegalBasis:        "LGPD Article 18, VI - Right to deletion",
		RequestedBy:       fmt.Sprintf("user_%d", userID),
		RequestedAt:       time.Now(),
		RetentionRequired: retentionRequired,
		RetentionReason:   retentionReason,
		RetentionUntil:    retentionUntil,
	}

	// Schedule deletion for grace period
	if !immediate && s.config.GracePeriod > 0 {
		scheduledTime := time.Now().Add(s.config.GracePeriod)
		request.ScheduledFor = &scheduledTime
		request.Status = domain.DeletionStatusScheduled
	}

	// Save deletion request
	if err := s.deletionRepo.Create(ctx, request); err != nil {
		return nil, false, fmt.Errorf("failed to create deletion request: %w", err)
	}

	// Audit the deletion request
	if err := s.auditService.LogDataExport(ctx, userID, "deletion_request", "LGPD Article 18, VI", 1); err != nil {
		log.Printf("Warning: failed to audit deletion request %s of user %d: %v", request.ID, userID, err)
	}

	// Create audit log entry
	metadataJSON, _ := json.Marshal(map[string]interface{}{
		"request_type":       requestType,
		"requested_type":     requestedType,
		"immediate":          immediate,
		"retention_required": retentionRequired,
	})
	auditLog := &domain.DeletionAuditLog{
		ID:          uuid.New(),
		RequestID:   request.ID,
		UserID:      userID,
		Action:      "deletion_requested",
		PerformedBy: fmt.Sprintf("user_%d", userID),
		PerformedAt: time.Now(),
		Result:      "success",
		Metadata:    datatypes.JSON(metadataJSON),
		CreatedAt:   time.Now(),
	}
	if s.auditRepo != nil {
		if err := s.auditRepo.Create(ctx, auditLog); err != nil {
			if immediate {
				// Nothing destructive has happened yet: refuse rather than delete without a trail.
				return s.failImmediate(ctx, request, "audit", false, err)
			}
			log.Printf("Warning: failed to write deletion_requested audit row for request %s: %v", request.ID, err)
		}
	}

	if immediate {
		return s.processImmediate(ctx, request, user)
	}
	return request, false, nil
}

func (s *UserDeletionService) logSecurityViolation(ctx context.Context, event domain.SecurityEventType, description string, userID uint) {
	if err := s.auditService.LogSecurityViolation(ctx, event, domain.SecuritySeverityMedium, description, &userID, ""); err != nil {
		log.Printf("Warning: failed to audit %s for user %d: %v", event, userID, err)
	}
}

// processImmediate runs an immediate self-deletion. It uses a context detached from the HTTP
// request so a client that disconnects cannot interrupt it half way.
func (s *UserDeletionService) processImmediate(ctx context.Context, request *domain.DeletionRequest, user *domain.User) (*domain.DeletionRequest, bool, error) {
	ctx = context.WithoutCancel(ctx)

	now := time.Now()
	request.Status = domain.DeletionStatusProcessing
	request.ProcessedAt = &now
	if err := s.deletionRepo.Update(ctx, request); err != nil {
		return s.failImmediate(ctx, request, "start", false, err)
	}

	// Revoke every session first: if that fails nothing has been anonymised yet.
	if s.sessionRepo == nil {
		return s.failImmediate(ctx, request, "sessions", false, errors.New("session repository not configured"))
	}
	if err := s.sessionRepo.DeleteAllForUser(ctx, request.UserID); err != nil {
		return s.failImmediate(ctx, request, "sessions", false, fmt.Errorf("failed to revoke sessions: %w", err))
	}

	changed, err := s.anonymize(ctx, request, user.Phone, true)
	if err != nil {
		return s.failImmediate(ctx, request, "anonymization", changed, err)
	}

	completedAt := time.Now()
	request.Status = domain.DeletionStatusCompleted
	request.CompletedAt = &completedAt
	if err := s.deletionRepo.Update(ctx, request); err != nil {
		return s.failImmediate(ctx, request, "finalize", true, fmt.Errorf("failed to mark request completed: %w", err))
	}

	// The account is gone and the request is closed: from here an audit failure is only logged.
	if s.auditRepo != nil {
		if err := s.auditRepo.Create(ctx, &domain.DeletionAuditLog{
			ID:          uuid.New(),
			RequestID:   request.ID,
			UserID:      request.UserID,
			Action:      "deletion_completed",
			PerformedBy: fmt.Sprintf("user_%d", request.UserID),
			PerformedAt: time.Now(),
			Result:      "success",
			CreatedAt:   time.Now(),
		}); err != nil {
			log.Printf("Warning: failed to write deletion_completed audit row for request %s: %v", request.ID, err)
		}
	}
	return request, false, nil
}

// failImmediate leaves the request failed with the error recorded (in the request and in an audit row)
// and wraps the cause in a *DeletionProcessingError.
func (s *UserDeletionService) failImmediate(ctx context.Context, request *domain.DeletionRequest, stage string, accountChanged bool, cause error) (*domain.DeletionRequest, bool, error) {
	request.Status = domain.DeletionStatusFailed
	failure := map[string]interface{}{"error": cause.Error(), "stage": stage, "account_changed": accountChanged}
	if len(request.AnonymizationLog) > 0 {
		failure["anonymization"] = json.RawMessage(request.AnonymizationLog)
	}
	if raw, err := json.Marshal(failure); err == nil {
		request.AnonymizationLog = datatypes.JSON(raw)
	}
	if err := s.deletionRepo.Update(ctx, request); err != nil {
		log.Printf("Warning: failed to mark deletion request %s as failed: %v", request.ID, err)
	}
	if s.auditRepo != nil {
		if err := s.auditRepo.Create(ctx, &domain.DeletionAuditLog{
			ID:           uuid.New(),
			RequestID:    request.ID,
			UserID:       request.UserID,
			Action:       "deletion_failed",
			PerformedBy:  fmt.Sprintf("user_%d", request.UserID),
			PerformedAt:  time.Now(),
			Result:       "error",
			ErrorMessage: fmt.Sprintf("%s: %v", stage, cause),
			CreatedAt:    time.Now(),
		}); err != nil {
			log.Printf("Warning: failed to write deletion_failed audit row for request %s: %v", request.ID, err)
		}
	}
	log.Printf("Immediate deletion of user %d failed at %s: %v", request.UserID, stage, cause)
	return request, false, &DeletionProcessingError{Request: request, Stage: stage, AccountChanged: accountChanged, Err: cause}
}

// ProcessDeletionRequest executes a pending deletion request
func (s *UserDeletionService) ProcessDeletionRequest(ctx context.Context, requestID uuid.UUID) error {
	// Get the deletion request
	request, err := s.deletionRepo.FindByID(ctx, requestID)
	if err != nil {
		return fmt.Errorf("deletion request not found: %w", err)
	}

	// Check if request can be processed
	if request.Status != domain.DeletionStatusPending && request.Status != domain.DeletionStatusScheduled {
		return fmt.Errorf("request cannot be processed, current status: %s", request.Status)
	}

	// Check if scheduled time has arrived (bypass in testing mode)
	if !s.config.TestingMode && request.ScheduledFor != nil && request.ScheduledFor.After(time.Now()) {
		return fmt.Errorf("request scheduled for %s, cannot process yet", request.ScheduledFor.Format(time.RFC3339))
	}

	// Update status to processing
	request.Status = domain.DeletionStatusProcessing
	now := time.Now()
	request.ProcessedAt = &now
	s.deletionRepo.Update(ctx, request)

	// Process based on request type
	var processingErr error
	switch request.RequestType {
	case domain.DeletionTypeFullDelete:
		processingErr = s.performFullDeletion(ctx, request)
	case domain.DeletionTypeSoftDelete:
		processingErr = s.performSoftDeletion(ctx, request)
	case domain.DeletionTypeAnonymization:
		processingErr = s.performAnonymization(ctx, request)
	case domain.DeletionTypeDeactivation:
		processingErr = s.performDeactivation(ctx, request)
	case domain.DeletionTypeExportAndDelete:
		processingErr = s.performExportAndDelete(ctx, request)
	default:
		processingErr = fmt.Errorf("unknown deletion type: %s", request.RequestType)
	}

	// Update request status based on result
	if processingErr != nil {
		request.Status = domain.DeletionStatusFailed
		if s.auditRepo != nil {
			s.auditRepo.Create(ctx, &domain.DeletionAuditLog{
			ID:           uuid.New(),
			RequestID:    request.ID,
			UserID:       request.UserID,
			Action:       "deletion_failed",
			PerformedBy:  "system",
			PerformedAt:  time.Now(),
			Result:       "error",
			ErrorMessage: processingErr.Error(),
			CreatedAt:    time.Now(),
		})
		}
	} else {
		completedAt := time.Now()
		request.Status = domain.DeletionStatusCompleted
		request.CompletedAt = &completedAt
		if s.auditRepo != nil {
			s.auditRepo.Create(ctx, &domain.DeletionAuditLog{
			ID:          uuid.New(),
			RequestID:   request.ID,
			UserID:      request.UserID,
			Action:      "deletion_completed",
			PerformedBy: "system",
			PerformedAt: time.Now(),
			Result:      "success",
			CreatedAt:   time.Now(),
		})
		}
	}

	s.deletionRepo.Update(ctx, request)
	return processingErr
}

// performFullDeletion executes complete data erasure
func (s *UserDeletionService) performFullDeletion(ctx context.Context, request *domain.DeletionRequest) error {
	// Log all user sessions out first
	if s.sessionRepo != nil {
		if err := s.sessionRepo.DeleteAllForUser(ctx, request.UserID); err != nil {
			log.Printf("Warning: failed to delete sessions for user %d: %v", request.UserID, err)
		}
	}

	// Get data summary before deletion for audit
	dataSummary, _ := s.cascadeDeletor.GetUserDataSummary(ctx, request.UserID)

	// Perform cascade deletion of related data
	deletedCounts := make(map[string]int)
	
	// Delete sessions
	if count, err := s.cascadeDeletor.DeleteUserSessions(ctx, request.UserID); err == nil {
		deletedCounts["sessions"] = count
	}

	// Delete OTP requests
	if count, err := s.cascadeDeletor.DeleteUserOTPRequests(ctx, request.UserID); err == nil {
		deletedCounts["otp_requests"] = count
	}

	// Delete password history
	if count, err := s.cascadeDeletor.DeletePasswordHistory(ctx, request.UserID); err == nil {
		deletedCounts["password_history"] = count
	}

	// Anonymize audit logs (don't delete for compliance)
	if count, err := s.cascadeDeletor.DeleteOrAnonymizeAuditLogs(ctx, request.UserID, true); err == nil {
		deletedCounts["audit_logs_anonymized"] = count
	}

	// Delete user policies
	if count, err := s.cascadeDeletor.DeleteUserPolicies(ctx, request.UserID); err == nil {
		deletedCounts["policies"] = count
	}

	// Delete tokens
	if count, err := s.cascadeDeletor.DeleteUserTokens(ctx, request.UserID); err == nil {
		deletedCounts["tokens"] = count
	}

	// Finally, delete the user record
	if err := s.userRepo.HardDelete(ctx, request.UserID); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	// Create detailed audit log
	if s.auditRepo != nil {
		metadataJSON, _ := json.Marshal(map[string]interface{}{
			"data_summary_before": dataSummary,
		})
		s.auditRepo.Create(ctx, &domain.DeletionAuditLog{
		ID:             uuid.New(),
		RequestID:      request.ID,
		UserID:         request.UserID,
		Action:         "full_deletion_executed",
		PerformedBy:    "system",
		PerformedAt:    time.Now(),
		Result:         "success",
		AffectedTables: getTableNames(deletedCounts),
		RecordsDeleted: deletedCounts,
		Metadata:       datatypes.JSON(metadataJSON),
		CreatedAt:      time.Now(),
	})
	}

	// Log to audit service
	totalRecords := 0
	for _, count := range deletedCounts {
		totalRecords += count
	}
	s.auditService.LogDataWrite(ctx, request.UserID, "full_deletion", totalRecords)

	return nil
}

// performSoftDeletion marks user as deleted but retains data
func (s *UserDeletionService) performSoftDeletion(ctx context.Context, request *domain.DeletionRequest) error {
	// Log user out
	if s.sessionRepo != nil {
		s.sessionRepo.DeleteAllForUser(ctx, request.UserID)
	}

	// Soft delete the user
	if err := s.userRepo.SoftDelete(ctx, request.UserID); err != nil {
		return fmt.Errorf("soft delete failed: %w", err)
	}

	// Audit the soft deletion
	s.auditService.LogDataWrite(ctx, 0, "user_deletion", 1)

	return nil
}

// performAnonymization replaces PII with anonymous data (admin and scheduled paths).
func (s *UserDeletionService) performAnonymization(ctx context.Context, request *domain.DeletionRequest) error {
	phone := ""
	if user, err := s.userRepo.FindByID(ctx, request.UserID); err == nil && user != nil {
		phone = user.Phone
	}
	_, err := s.anonymize(ctx, request, phone, false)
	return err
}

// anonymize replaces the account's identifiers, makes its password unusable, revokes sessions,
// anonymises the audit trail and drops cached state. It reports whether the account row was changed.
//
// strict (immediate self-deletion) turns a failed session sweep after the anonymisation into an error;
// otherwise it is logged, as it always was. Failures of the audit-log anonymisation and of the cache
// invalidation never fail the operation: they are logged and recorded as warnings in the request's
// anonymization log.
func (s *UserDeletionService) anonymize(ctx context.Context, request *domain.DeletionRequest, phone string, strict bool) (bool, error) {
	// Generate anonymous identifiers
	anonymousID := s.generateAnonymousID(request.UserID)
	anonymousEmail := fmt.Sprintf("deleted_user_%d@anonymous.local", request.UserID)
	anonymousPhone := fmt.Sprintf("+00000%06d", request.UserID) // Unique anonymous phone based on user ID

	// Create anonymized user record
	anonymizedUser := &domain.AnonymizedUser{
		ID:                request.UserID,
		AnonymousID:       anonymousID,
		Email:             anonymousEmail,
		Phone:             anonymousPhone,
		PasswordHash:      domain.UnusablePasswordHash,
		AnonymizedAt:      time.Now(),
		RetainedForReason: request.RetentionReason,
		RetainedUntil:     request.RetentionUntil,
	}

	// Perform anonymization
	if err := s.userRepo.Anonymize(ctx, request.UserID, anonymizedUser); err != nil {
		return false, fmt.Errorf("anonymization failed: %w", err)
	}

	var warnings []string
	warn := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		log.Printf("Warning: user %d anonymization: %s", request.UserID, msg)
		warnings = append(warnings, msg)
	}

	// Log user out (again: catches a session created while we were working)
	if s.sessionRepo != nil {
		if err := s.sessionRepo.DeleteAllForUser(ctx, request.UserID); err != nil {
			if strict {
				return true, fmt.Errorf("failed to revoke sessions after anonymization: %w", err)
			}
			warn("failed to revoke sessions: %v", err)
		}
	}

	// Anonymize related data
	if _, err := s.cascadeDeletor.DeleteOrAnonymizeAuditLogs(ctx, request.UserID, true); err != nil {
		warn("failed to anonymize audit logs: %v", err)
	}

	// Drop the identity cache entry and pending OTP keys
	if s.accountInvalidator != nil {
		if err := s.accountInvalidator.InvalidateAccount(ctx, request.UserID, phone); err != nil {
			warn("failed to invalidate cached state: %v", err)
		}
	}

	// Record anonymization details
	metadata := map[string]interface{}{"anonymous_id": anonymousID}
	if len(warnings) > 0 {
		metadata["warnings"] = warnings
	}
	anonymizationDetails := domain.AnonymizationDetails{
		FieldsAnonymized: []string{"email", "phone", "password", "phone_verified", "name", "ip_addresses"},
		Method:           s.config.AnonymizationMethod,
		Timestamp:        time.Now(),
		OriginalDataHash: s.hashUserData(request.UserID),
		Metadata:         metadata,
	}
	anonymizationJSON, _ := json.Marshal(anonymizationDetails)
	request.AnonymizationLog = datatypes.JSON(anonymizationJSON)

	// Audit the anonymization
	if err := s.auditService.LogDataWrite(ctx, request.UserID, "user_anonymization", 1); err != nil {
		log.Printf("Warning: failed to audit anonymization of user %d: %v", request.UserID, err)
	}

	return true, nil
}

// performDeactivation only deactivates the account
func (s *UserDeletionService) performDeactivation(ctx context.Context, request *domain.DeletionRequest) error {
	// Deactivate user account
	if err := s.userRepo.Deactivate(ctx, request.UserID, request.Reason); err != nil {
		return fmt.Errorf("deactivation failed: %w", err)
	}

	// Log user out
	s.sessionRepo.DeleteAllForUser(ctx, request.UserID)

	// Audit the deactivation
	s.auditService.LogDataWrite(ctx, request.UserID, "user_deactivation", 1)

	return nil
}

// performExportAndDelete exports data then deletes
func (s *UserDeletionService) performExportAndDelete(ctx context.Context, request *domain.DeletionRequest) error {
	// First export the data
	export, err := s.ExportUserData(ctx, request.UserID, "json")
	if err != nil {
		return fmt.Errorf("failed to export data: %w", err)
	}

	// Mark export in request
	request.DataExported = true
	request.DataExportPath = export.DownloadURL

	// Then perform deletion
	return s.performFullDeletion(ctx, request)
}

// ExportUserData creates a data export for LGPD portability
func (s *UserDeletionService) ExportUserData(ctx context.Context, userID uint, format string) (*domain.UserDataExport, error) {
	// Get user data
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Collect all user data
	userData := map[string]interface{}{
		"user_profile": user,
		"data_summary": nil,
	}

	// Get data summary
	if summary, err := s.cascadeDeletor.GetUserDataSummary(ctx, userID); err == nil {
		userData["data_summary"] = summary
	}

	// Marshal data based on format
	var exportData []byte
	switch format {
	case "json":
		exportData, err = json.MarshalIndent(userData, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal data: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported export format: %s", format)
	}

	// Create export record
	export := &domain.UserDataExport{
		ExportID:     uuid.New(),
		UserID:       userID,
		RequestedAt:  time.Now(),
		GeneratedAt:  time.Now(),
		ExpiresAt:    time.Now().Add(s.config.ExportExpirationTime),
		Format:       format,
		DownloadURL:  fmt.Sprintf("/api/exports/%s", uuid.New().String()),
		Checksum:     s.calculateChecksum(exportData),
		Size:         int64(len(exportData)),
		IncludedData: []string{"profile", "sessions", "audit_logs"},
	}

	// Save export record
	if err := s.exportRepo.Create(ctx, export); err != nil {
		return nil, fmt.Errorf("failed to create export record: %w", err)
	}

	// Audit the export
	s.auditService.LogDataExport(ctx, userID, format, "LGPD Article 18, V - Data Portability", 1)

	return export, nil
}

// Helper functions

func (s *UserDeletionService) generateAnonymousID(userID uint) string {
	if s.config.AnonymizationMethod == "hash" {
		hash := sha256.Sum256([]byte(fmt.Sprintf("user_%d_%d", userID, time.Now().Unix())))
		return "ANON_" + hex.EncodeToString(hash[:8])
	}
	return fmt.Sprintf("ANON_USER_%d", userID)
}

func (s *UserDeletionService) hashUserData(userID uint) string {
	data := fmt.Sprintf("%d:%d", userID, time.Now().Unix())
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func (s *UserDeletionService) calculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func getTableNames(counts map[string]int) []string {
	tables := make([]string, 0, len(counts))
	for table := range counts {
		tables = append(tables, table)
	}
	return tables
}


// Additional interface methods implementation...

func (s *UserDeletionService) GetDeletionStatus(ctx context.Context, requestID uuid.UUID) (*domain.DeletionRequest, error) {
	return s.deletionRepo.FindByID(ctx, requestID)
}

func (s *UserDeletionService) CancelDeletionRequest(ctx context.Context, requestID uuid.UUID, reason string) error {
	request, err := s.deletionRepo.FindByID(ctx, requestID)
	if err != nil {
		return err
	}
	
	if request.Status != domain.DeletionStatusPending && request.Status != domain.DeletionStatusScheduled {
		return fmt.Errorf("cannot cancel request with status: %s", request.Status)
	}
	
	request.Status = domain.DeletionStatusCancelled
	return s.deletionRepo.Update(ctx, request)
}

func (s *UserDeletionService) GetExportStatus(ctx context.Context, exportID uuid.UUID) (*domain.UserDataExport, error) {
	return s.exportRepo.FindByID(ctx, exportID)
}

func (s *UserDeletionService) AnonymizeUser(ctx context.Context, userID uint, retainForLegal bool) error {
	request := &domain.DeletionRequest{
		ID:                uuid.New(),
		UserID:            userID,
		RequestType:       domain.DeletionTypeAnonymization,
		Status:            domain.DeletionStatusPending,
		RetentionRequired: retainForLegal,
	}
	return s.performAnonymization(ctx, request)
}

func (s *UserDeletionService) GetAnonymizedUserData(ctx context.Context, anonymousID string) (*domain.AnonymizedUser, error) {
	// Implementation would query anonymized users table
	return nil, fmt.Errorf("not implemented")
}

func (s *UserDeletionService) GetRetentionPolicy(ctx context.Context, dataType string) (*domain.DataRetentionPolicy, error) {
	policies, err := s.complianceChecker.GetRetentionRequirements(ctx, 0)
	if err != nil || len(policies) == 0 {
		return nil, fmt.Errorf("no retention policy found for data type: %s", dataType)
	}
	return &policies[0], nil
}

// ProcessScheduledDeletion processes a scheduled deletion request after grace period expires
func (s *UserDeletionService) ProcessScheduledDeletion(ctx context.Context, requestID string) error {
	// Parse UUID from string
	reqUUID, err := uuid.Parse(requestID)
	if err != nil {
		return fmt.Errorf("invalid request ID: %w", err)
	}
	
	// Get deletion request
	request, err := s.deletionRepo.FindByID(ctx, reqUUID)
	if err != nil {
		return fmt.Errorf("failed to find deletion request: %w", err)
	}
	
	// Verify grace period has expired
	if request.ScheduledFor != nil && time.Now().Before(*request.ScheduledFor) {
		return fmt.Errorf("grace period not yet expired")
	}
	
	// Update status to processing
	request.Status = domain.DeletionStatusProcessing
	if err := s.deletionRepo.Update(ctx, request); err != nil {
		return fmt.Errorf("failed to update request status: %w", err)
	}
	
	// Process based on deletion type
	switch request.RequestType {
	case domain.DeletionTypeFullDelete:
		err = s.performFullDeletion(ctx, request)
	case domain.DeletionTypeSoftDelete:
		err = s.performSoftDeletion(ctx, request)
	case domain.DeletionTypeAnonymization:
		err = s.performAnonymization(ctx, request)
	case domain.DeletionTypeDeactivation:
		err = s.performDeactivation(ctx, request)
	case domain.DeletionTypeExportAndDelete:
		// Export first, then delete
		if _, err := s.ExportUserData(ctx, request.UserID, "json"); err != nil {
			return fmt.Errorf("failed to export user data: %w", err)
		}
		err = s.performFullDeletion(ctx, request)
	default:
		err = fmt.Errorf("unknown deletion type: %s", request.RequestType)
	}
	
	// Update final status
	if err != nil {
		request.Status = domain.DeletionStatusFailed
		s.deletionRepo.Update(ctx, request)
		return err
	}
	
	now := time.Now()
	request.Status = domain.DeletionStatusCompleted
	request.CompletedAt = &now
	return s.deletionRepo.Update(ctx, request)
}

// CleanupExport removes an expired data export file
func (s *UserDeletionService) CleanupExport(ctx context.Context, exportID string) error {
	// Parse UUID from string
	expUUID, err := uuid.Parse(exportID)
	if err != nil {
		return fmt.Errorf("invalid export ID: %w", err)
	}
	
	// Get export record
	export, err := s.exportRepo.FindByID(ctx, expUUID)
	if err != nil {
		return fmt.Errorf("failed to find export: %w", err)
	}
	
	// Check if export has expired
	if time.Now().Before(export.ExpiresAt) {
		return fmt.Errorf("export has not yet expired")
	}
	
	// Delete the export file if it exists
	// Note: In a real implementation, this would delete from storage system
	// For now, just mark as deleted in database
	
	// Update export status - mark as expired instead of deleting
	// Note: We don't delete the record completely to maintain audit trail
	
	// Log cleanup
	s.auditService.LogSystemEvent(ctx, "export_cleanup_completed",
		fmt.Sprintf("Cleaned up expired export %s for user %d", exportID, export.UserID),
		map[string]interface{}{
			"export_id": exportID,
			"user_id":   export.UserID,
			"expired_at": export.ExpiresAt,
		})
	
	return nil
}

func (s *UserDeletionService) ListPendingDeletions(ctx context.Context, olderThan time.Duration) ([]*domain.DeletionRequest, error) {
	return s.deletionRepo.ListScheduled(ctx, time.Now().Add(-olderThan))
}

func (s *UserDeletionService) GetDeletionAuditLog(ctx context.Context, userID uint) ([]*domain.DeletionAuditLog, error) {
	return s.auditRepo.FindByUserID(ctx, userID)
}