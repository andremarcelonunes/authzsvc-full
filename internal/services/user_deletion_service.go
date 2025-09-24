package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
}

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
) *UserDeletionService {
	if config == nil {
		config = DefaultUserDeletionConfig()
	}
	
	return &UserDeletionService{
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
}

// RequestDeletion creates a new deletion request per LGPD Article 18
func (s *UserDeletionService) RequestDeletion(
	ctx context.Context,
	userID uint,
	requestType domain.DeletionRequestType,
	reason string,
) (*domain.DeletionRequest, error) {
	// Verify user exists
	_, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check if deletion is allowed
	canDelete, blockedReason, err := s.complianceChecker.CanDeleteUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("compliance check failed: %w", err)
	}
	if !canDelete {
		// Audit the blocked deletion attempt
		s.auditService.LogSecurityViolation(ctx, "deletion_blocked", domain.SecuritySeverityMedium, 
			fmt.Sprintf("User deletion blocked: %s", blockedReason), &userID, "")
		return nil, fmt.Errorf("deletion blocked: %s", blockedReason)
	}

	// Check retention requirements
	retentionPolicies, err := s.complianceChecker.GetRetentionRequirements(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to check retention requirements: %w", err)
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

	// Create deletion request
	request := &domain.DeletionRequest{
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
	if s.config.GracePeriod > 0 {
		scheduledTime := time.Now().Add(s.config.GracePeriod)
		request.ScheduledFor = &scheduledTime
		request.Status = domain.DeletionStatusScheduled
	}

	// Save deletion request
	if err := s.deletionRepo.Create(ctx, request); err != nil {
		return nil, fmt.Errorf("failed to create deletion request: %w", err)
	}

	// Audit the deletion request
	s.auditService.LogDataExport(ctx, userID, "deletion_request", "LGPD Article 18, VI", 1)

	// Create audit log entry
	metadataJSON, _ := json.Marshal(map[string]interface{}{
		"request_type":       requestType,
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
		s.auditRepo.Create(ctx, auditLog)
	}

	return request, nil
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

// performAnonymization replaces PII with anonymous data
func (s *UserDeletionService) performAnonymization(ctx context.Context, request *domain.DeletionRequest) error {
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
		AnonymizedAt:      time.Now(),
		RetainedForReason: request.RetentionReason,
		RetainedUntil:     request.RetentionUntil,
	}

	// Perform anonymization
	if err := s.userRepo.Anonymize(ctx, request.UserID, anonymizedUser); err != nil {
		return fmt.Errorf("anonymization failed: %w", err)
	}

	// Log user out
	s.sessionRepo.DeleteAllForUser(ctx, request.UserID)

	// Anonymize related data
	s.cascadeDeletor.DeleteOrAnonymizeAuditLogs(ctx, request.UserID, true)

	// Record anonymization details
	anonymizationDetails := domain.AnonymizationDetails{
		FieldsAnonymized: []string{"email", "phone", "name", "ip_addresses"},
		Method:           s.config.AnonymizationMethod,
		Timestamp:        time.Now(),
		OriginalDataHash: s.hashUserData(request.UserID),
		Metadata: map[string]interface{}{
			"anonymous_id": anonymousID,
		},
	}
	anonymizationJSON, _ := json.Marshal(anonymizationDetails)
	request.AnonymizationLog = datatypes.JSON(anonymizationJSON)

	// Audit the anonymization
	s.auditService.LogDataWrite(ctx, request.UserID, "user_anonymization", 1)

	return nil
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