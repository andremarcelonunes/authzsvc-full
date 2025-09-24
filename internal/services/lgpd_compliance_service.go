package services

import (
	"context"
	"fmt"
	"time"
	"strings"

	"github.com/you/authzsvc/domain"
)

// LGPDComplianceService implements LGPD compliance checking
type LGPDComplianceService struct {
	userRepo domain.UserRepository
	auditRepo domain.ComprehensiveAuditRepository
	config *LGPDComplianceConfig
}

// LGPDComplianceConfig contains configuration for compliance checking
type LGPDComplianceConfig struct {
	// Legal hold checking
	EnableLegalHoldChecks bool
	LegalHoldStatuses []string // e.g., ["lawsuit", "investigation", "dispute"]
	
	// Contract/subscription validation
	EnableContractChecks bool
	ActiveContractStatuses []string // e.g., ["active", "suspended"]
	MinimumContractRetention time.Duration
	
	// Regulatory requirements
	EnableRegulatoryChecks bool
	FinancialRecordsRetention time.Duration // 5 years typically
	TaxRecordsRetention time.Duration // 7 years typically
	AuditLogRetention time.Duration // 7 years for LGPD
	
	// Regional compliance
	ApplicableRegions []string // ["BR", "EU"]
	RegionalRetentionRules map[string]time.Duration
	
	// Business rules
	MinimumAccountAge time.Duration // Prevent immediate deletion of new accounts
	CoolingOffPeriod time.Duration // Required waiting period
	
	// Testing/development mode
	TestingMode bool // Bypasses some checks for testing
}

// DefaultLGPDComplianceConfig returns production-ready LGPD compliance configuration
func DefaultLGPDComplianceConfig() *LGPDComplianceConfig {
	return &LGPDComplianceConfig{
		EnableLegalHoldChecks: true,
		LegalHoldStatuses: []string{"lawsuit", "investigation", "dispute", "regulatory_review"},
		EnableContractChecks: true,
		ActiveContractStatuses: []string{"active", "suspended", "pending_renewal"},
		MinimumContractRetention: 30 * 24 * time.Hour, // 30 days after contract end
		EnableRegulatoryChecks: true,
		FinancialRecordsRetention: 5 * 365 * 24 * time.Hour, // 5 years
		TaxRecordsRetention: 7 * 365 * 24 * time.Hour, // 7 years
		AuditLogRetention: 7 * 365 * 24 * time.Hour, // 7 years (LGPD requirement)
		ApplicableRegions: []string{"BR"}, // Brazil for LGPD
		RegionalRetentionRules: map[string]time.Duration{
			"BR": 7 * 365 * 24 * time.Hour, // LGPD requirement
			"EU": 6 * 365 * 24 * time.Hour, // GDPR requirement
		},
		MinimumAccountAge: 24 * time.Hour, // Prevent deletion within 24h of creation
		CoolingOffPeriod: 24 * time.Hour, // 24h cooling off period
		TestingMode: false,
	}
}

// NewLGPDComplianceService creates a new LGPD compliance service
func NewLGPDComplianceService(
	userRepo domain.UserRepository, 
	auditRepo domain.ComprehensiveAuditRepository,
	config *LGPDComplianceConfig,
) *LGPDComplianceService {
	if config == nil {
		config = DefaultLGPDComplianceConfig()
	}
	return &LGPDComplianceService{
		userRepo: userRepo,
		auditRepo: auditRepo,
		config: config,
	}
}

// CanDeleteUser checks if a user can be deleted according to LGPD
func (s *LGPDComplianceService) CanDeleteUser(ctx context.Context, userID uint) (bool, string, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return false, "User not found", err
	}

	// Check if user is already inactive (already processed)
	if !user.IsActive {
		return true, "", nil
	}

	// Check minimum account age (prevent immediate deletion) - bypass in testing mode
	if !s.config.TestingMode && s.config.MinimumAccountAge > 0 && time.Since(user.CreatedAt) < s.config.MinimumAccountAge {
		age := time.Since(user.CreatedAt)
		required := s.config.MinimumAccountAge
		return false, fmt.Sprintf("Account too new: %v old, minimum %v required", age.Round(time.Hour), required), nil
	}

	// 1. Check for active legal holds
	if s.config.EnableLegalHoldChecks {
		if blocked, reason, err := s.checkLegalHolds(ctx, userID); err != nil {
			return false, "Error checking legal holds", err
		} else if blocked {
			return false, reason, nil
		}
	}

	// 2. Check for active contracts/subscriptions
	if s.config.EnableContractChecks {
		if blocked, reason, err := s.checkActiveContracts(ctx, userID); err != nil {
			return false, "Error checking contracts", err
		} else if blocked {
			return false, reason, nil
		}
	}

	// 3. Check regulatory requirements
	if s.config.EnableRegulatoryChecks {
		if blocked, reason, err := s.checkRegulatoryRequirements(ctx, userID); err != nil {
			return false, "Error checking regulatory requirements", err
		} else if blocked {
			return false, reason, nil
		}
	}

	// 4. Check pending financial transactions
	if blocked, reason, err := s.checkPendingTransactions(ctx, userID); err != nil {
		return false, "Error checking pending transactions", err
	} else if blocked {
		return false, reason, nil
	}

	// 5. Check for recent security incidents
	if blocked, reason, err := s.checkSecurityIncidents(ctx, userID); err != nil {
		return false, "Error checking security incidents", err
	} else if blocked {
		return false, reason, nil
	}

	// All checks passed - deletion is allowed
	return true, "", nil
}

// GetRetentionRequirements returns data retention policies for a user
func (s *LGPDComplianceService) GetRetentionRequirements(ctx context.Context, userID uint) ([]domain.DataRetentionPolicy, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	var policies []domain.DataRetentionPolicy

	// Always required: Audit logs (LGPD Article 16)
	policies = append(policies, domain.DataRetentionPolicy{
		DataType:        "audit_logs",
		RetentionPeriod: s.config.AuditLogRetention,
		LegalBasis:      "LGPD Article 16 - Legal obligation for audit trails",
		Mandatory:       true,
		Description:     "Audit logs must be retained for legal compliance and security monitoring",
		AppliesTo:       []string{"all_users"},
	})

	// Check if user has financial transactions
	if s.hasFinancialActivity(ctx, userID) {
		policies = append(policies, domain.DataRetentionPolicy{
			DataType:        "financial_records",
			RetentionPeriod: s.config.FinancialRecordsRetention,
			LegalBasis:      "Brazilian Federal Revenue Service regulations",
			Mandatory:       true,
			Description:     "Financial transaction records must be retained for tax compliance",
			AppliesTo:       []string{"users_with_financial_activity"},
		})
	}

	// Check if user has tax-related data
	if s.hasTaxRelevantData(ctx, userID) {
		policies = append(policies, domain.DataRetentionPolicy{
			DataType:        "tax_records",
			RetentionPeriod: s.config.TaxRecordsRetention,
			LegalBasis:      "Brazilian Tax Code - Legal obligation",
			Mandatory:       true,
			Description:     "Tax-related data must be retained per Brazilian tax law",
			AppliesTo:       []string{"users_with_tax_data"},
		})
	}

	// Check role-based retention requirements
	if user.Role == "admin" || user.Role == "attendant" {
		policies = append(policies, domain.DataRetentionPolicy{
			DataType:        "administrative_actions",
			RetentionPeriod: s.config.AuditLogRetention,
			LegalBasis:      "Internal governance and accountability requirements",
			Mandatory:       true,
			Description:     "Administrative actions must be retained for governance and audit purposes",
			AppliesTo:       []string{"admin", "attendant"},
		})
	}

	// Apply regional retention rules
	for region, retentionPeriod := range s.config.RegionalRetentionRules {
		if s.userInRegion(user, region) {
			policies = append(policies, domain.DataRetentionPolicy{
				DataType:        "regional_compliance",
				RetentionPeriod: retentionPeriod,
				LegalBasis:      fmt.Sprintf("Data protection laws in region: %s", region),
				Mandatory:       true,
				Description:     fmt.Sprintf("Regional compliance requirements for %s", region),
				AppliesTo:       []string{fmt.Sprintf("users_in_%s", strings.ToLower(region))},
			})
		}
	}

	return policies, nil
}

// ValidateDeletionRequest validates if a deletion request is compliant
func (s *LGPDComplianceService) ValidateDeletionRequest(ctx context.Context, request *domain.DeletionRequest) error {
	if request == nil {
		return fmt.Errorf("deletion request cannot be nil")
	}

	if request.UserID == 0 {
		return fmt.Errorf("user ID is required")
	}

	if request.Reason == "" {
		return fmt.Errorf("deletion reason is required")
	}

	// Check if user exists
	_, err := s.userRepo.FindByID(ctx, request.UserID)
	if err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	return nil
}

// IsAnonymizationSufficient checks if anonymization is sufficient for compliance
func (s *LGPDComplianceService) IsAnonymizationSufficient(ctx context.Context, userID uint) (bool, error) {
	// Check if there are active legal holds that require data preservation
	if s.config.EnableLegalHoldChecks {
		if hasLegalHold, err := s.hasActiveLegalHold(ctx, userID); err != nil {
			return false, err
		} else if hasLegalHold {
			// Legal hold requires complete data preservation - anonymization not sufficient
			return false, nil
		}
	}

	// Check if there are regulatory requirements that prevent anonymization
	if s.config.EnableRegulatoryChecks {
		if requiresFullPreservation, err := s.requiresFullDataPreservation(ctx, userID); err != nil {
			return false, err
		} else if requiresFullPreservation {
			return false, nil
		}
	}

	// Check if user has pending disputes that require identity preservation
	if hasDisputes, err := s.hasPendingDisputes(ctx, userID); err != nil {
		return false, err
	} else if hasDisputes {
		return false, nil
	}

	// For most cases, anonymization is sufficient for LGPD compliance
	return true, nil
}

// GenerateComplianceReport creates a compliance report for the user
func (s *LGPDComplianceService) GenerateComplianceReport(ctx context.Context, userID uint) (map[string]interface{}, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Get retention policies
	retentionPolicies, err := s.GetRetentionRequirements(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get retention policies: %w", err)
	}

	// Check deletion eligibility
	canDelete, blockedReason, err := s.CanDeleteUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to check deletion eligibility: %w", err)
	}

	// Check legal holds
	legalHolds, err := s.getActiveLegalHolds(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to check legal holds: %w", err)
	}

	// Check active contracts
	activeContracts, err := s.getActiveContracts(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to check contracts: %w", err)
	}

	// Check compliance status
	complianceStatus := "compliant"
	if !canDelete {
		complianceStatus = "blocked"
	} else if len(retentionPolicies) > 0 {
		complianceStatus = "retention_required"
	}

	// Check anonymization sufficiency
	anonymizationSufficient, err := s.IsAnonymizationSufficient(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to check anonymization sufficiency: %w", err)
	}

	report := map[string]interface{}{
		"user_id":                    userID,
		"account_status":             getAccountStatus(user),
		"role":                       user.Role,
		"created_at":                 user.CreatedAt,
		"last_activity":              user.UpdatedAt,
		"account_age_hours":          time.Since(user.CreatedAt).Hours(),
		"retention_policies":         s.formatRetentionPolicies(retentionPolicies),
		"legal_holds":                legalHolds,
		"active_contracts":           activeContracts,
		"compliance_status":          complianceStatus,
		"deletion_eligible":          canDelete,
		"deletion_blocked_reason":    blockedReason,
		"anonymization_sufficient":   anonymizationSufficient,
		"recommended_action":         s.getRecommendedAction(canDelete, len(retentionPolicies) > 0, anonymizationSufficient),
		"applicable_regulations":     s.config.ApplicableRegions,
		"minimum_retention_period":   s.getMinimumRetentionPeriod(retentionPolicies),
		"generated_at":               time.Now(),
		"generated_by":               "LGPDComplianceService",
		"config_version":             "1.0",
	}

	return report, nil
}

func (s *LGPDComplianceService) getApplicableRetentionPolicies(userID uint) []string {
	return []string{
		"LGPD Article 16 - Audit logs (7 years)",
		"Tax records (5 years)",
	}
}

func getAccountStatus(user *domain.User) string {
	if user.IsActive {
		return "active"
	}
	return "inactive"
}

// checkLegalHolds checks for active legal holds on the user account
func (s *LGPDComplianceService) checkLegalHolds(ctx context.Context, userID uint) (bool, string, error) {
	// Check for legal hold indicators in audit logs
	events, err := s.auditRepo.FindByUser(ctx, userID, 10, 0)
	if err != nil {
		return false, "", fmt.Errorf("failed to check audit logs: %w", err)
	}
	
	// Check for active legal hold events without resolution
	for _, event := range events {
		if event.EventType == "legal_hold_placed" || event.EventType == "investigation_started" {
			// Check if there's a corresponding release event
			if !s.hasLegalHoldRelease(ctx, userID, event.Timestamp) {
				return true, fmt.Sprintf("Active legal hold since %s", event.Timestamp.Format("2006-01-02")), nil
			}
		}
	}
	
	// Additional check: Look for specific metadata flags
	if s.config.TestingMode {
		return false, "", nil
	}
	
	// In production, check external legal hold system (simulated)
	if hasHold := s.checkExternalLegalHoldSystem(ctx, userID); hasHold {
		return true, "User account under legal hold per compliance system", nil
	}
	
	return false, "", nil
}

// checkActiveContracts verifies if user has active contracts or subscriptions
func (s *LGPDComplianceService) checkActiveContracts(ctx context.Context, userID uint) (bool, string, error) {
	// Check for active subscription/contract events in audit logs
	recentEvents, err := s.auditRepo.FindByUser(ctx, userID, 50, 0)
	if err != nil {
		return false, "", fmt.Errorf("failed to check contract status: %w", err)
	}
	
	var lastContractEvent *domain.ComprehensiveAuditEvent
	for i, event := range recentEvents {
		if strings.Contains(event.EventType, "contract_") || strings.Contains(event.EventType, "subscription_") {
			if lastContractEvent == nil || event.Timestamp.After(lastContractEvent.Timestamp) {
				lastContractEvent = recentEvents[i]
			}
		}
	}
	
	if lastContractEvent != nil {
		// Check if contract is active
		if strings.Contains(lastContractEvent.EventType, "_activated") || strings.Contains(lastContractEvent.EventType, "_renewed") {
			// Check if sufficient time has passed since activation
			timeSinceContract := time.Since(lastContractEvent.Timestamp)
			if timeSinceContract < s.config.MinimumContractRetention {
				remaining := s.config.MinimumContractRetention - timeSinceContract
				return true, fmt.Sprintf("Active contract requires %v retention period", remaining.Round(24*time.Hour)), nil
			}
		}
	}
	
	// Check for financial obligations
	if hasObligations := s.checkFinancialObligations(ctx, userID); hasObligations {
		return true, "Outstanding financial obligations must be resolved", nil
	}
	
	return false, "", nil
}

// checkRegulatoryRequirements validates regulatory compliance requirements
func (s *LGPDComplianceService) checkRegulatoryRequirements(ctx context.Context, userID uint) (bool, string, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return false, "", err
	}
	
	// Check financial records retention requirement
	if s.hasFinancialActivity(ctx, userID) {
		lastFinancialActivity := s.getLastFinancialActivityDate(ctx, userID)
		timeSinceActivity := time.Since(lastFinancialActivity)
		
		if timeSinceActivity < s.config.FinancialRecordsRetention {
			remaining := s.config.FinancialRecordsRetention - timeSinceActivity
			return true, fmt.Sprintf("Financial records must be retained for %v more", remaining.Round(24*time.Hour)), nil
		}
	}
	
	// Check tax records retention
	if s.hasTaxRelevantData(ctx, userID) {
		lastTaxEvent := s.getLastTaxEventDate(ctx, userID)
		timeSinceTaxEvent := time.Since(lastTaxEvent)
		
		if timeSinceTaxEvent < s.config.TaxRecordsRetention {
			remaining := s.config.TaxRecordsRetention - timeSinceTaxEvent
			return true, fmt.Sprintf("Tax records must be retained for %v more", remaining.Round(24*time.Hour)), nil
		}
	}
	
	// Check audit log retention for administrative users
	if user.Role == "admin" || user.Role == "attendant" {
		accountAge := time.Since(user.CreatedAt)
		if accountAge < s.config.AuditLogRetention {
			remaining := s.config.AuditLogRetention - accountAge
			return true, fmt.Sprintf("Administrative audit logs must be retained for %v more", remaining.Round(24*time.Hour)), nil
		}
	}
	
	return false, "", nil
}

// checkPendingTransactions checks for any pending financial transactions
func (s *LGPDComplianceService) checkPendingTransactions(ctx context.Context, userID uint) (bool, string, error) {
	// Check recent transaction events
	events, err := s.auditRepo.FindByUser(ctx, userID, 20, 0)
	if err != nil {
		return false, "", err
	}
	
	for _, event := range events {
		// Check for pending transaction indicators
		if strings.Contains(event.EventType, "transaction_pending") || 
		   strings.Contains(event.EventType, "payment_processing") {
			// Check if transaction was completed
			if !s.hasTransactionCompletion(ctx, userID, event.ID) {
				return true, "Pending financial transactions must be completed", nil
			}
		}
	}
	
	return false, "", nil
}

// checkSecurityIncidents verifies if there are recent security incidents
func (s *LGPDComplianceService) checkSecurityIncidents(ctx context.Context, userID uint) (bool, string, error) {
	// Check for security events in last 90 days
	cutoffDate := time.Now().AddDate(0, -3, 0)
	
	events, err := s.auditRepo.FindByUser(ctx, userID, 100, 0)
	if err != nil {
		return false, "", err
	}
	
	for _, event := range events {
		if event.Timestamp.After(cutoffDate) {
			if event.EventCategory == domain.CategoryAuditSecurity ||
			   strings.Contains(event.EventType, "security_") ||
			   strings.Contains(event.EventType, "breach_") ||
			   strings.Contains(event.EventType, "suspicious_") {
				// Security incident requires investigation period
				daysSinceIncident := time.Since(event.Timestamp).Hours() / 24
				if daysSinceIncident < 90 {
					remaining := 90 - int(daysSinceIncident)
					return true, fmt.Sprintf("Security incident investigation period (%d days remaining)", remaining), nil
				}
			}
		}
	}
	
	return false, "", nil
}

// hasFinancialActivity checks if user has financial activity
func (s *LGPDComplianceService) hasFinancialActivity(ctx context.Context, userID uint) bool {
	events, err := s.auditRepo.FindByUser(ctx, userID, 100, 0)
	if err != nil {
		return false
	}
	
	for _, event := range events {
		if strings.Contains(event.EventType, "payment_") ||
		   strings.Contains(event.EventType, "transaction_") ||
		   strings.Contains(event.EventType, "invoice_") ||
		   strings.Contains(event.EventType, "billing_") {
			return true
		}
	}
	
	return false
}

// hasTaxRelevantData checks if user has tax-relevant data
func (s *LGPDComplianceService) hasTaxRelevantData(ctx context.Context, userID uint) bool {
	events, err := s.auditRepo.FindByUser(ctx, userID, 100, 0)
	if err != nil {
		return false
	}
	
	for _, event := range events {
		if strings.Contains(event.EventType, "tax_") ||
		   strings.Contains(event.EventType, "fiscal_") ||
		   strings.Contains(event.EventType, "invoice_issued") ||
		   strings.Contains(event.EventType, "receipt_generated") {
			return true
		}
	}
	
	return false
}

// userInRegion checks if user is in a specific region
func (s *LGPDComplianceService) userInRegion(user *domain.User, region string) bool {
	// In production, this would check user's location data
	// For now, assume all users are in Brazil for LGPD
	return region == "BR"
}

// hasActiveLegalHold checks for active legal holds
func (s *LGPDComplianceService) hasActiveLegalHold(ctx context.Context, userID uint) (bool, error) {
	blocked, _, err := s.checkLegalHolds(ctx, userID)
	return blocked, err
}

// requiresFullDataPreservation checks if full data preservation is required
func (s *LGPDComplianceService) requiresFullDataPreservation(ctx context.Context, userID uint) (bool, error) {
	// Check if user is under investigation or audit
	events, err := s.auditRepo.FindByUser(ctx, userID, 50, 0)
	if err != nil {
		return false, err
	}
	
	for _, event := range events {
		if strings.Contains(event.EventType, "audit_initiated") ||
		   strings.Contains(event.EventType, "investigation_") ||
		   strings.Contains(event.EventType, "compliance_review") {
			// Check if there's a completion event
			if !s.hasInvestigationCompletion(ctx, userID, event.Timestamp) {
				return true, nil
			}
		}
	}
	
	return false, nil
}

// hasPendingDisputes checks for pending disputes
func (s *LGPDComplianceService) hasPendingDisputes(ctx context.Context, userID uint) (bool, error) {
	events, err := s.auditRepo.FindByUser(ctx, userID, 30, 0)
	if err != nil {
		return false, err
	}
	
	for _, event := range events {
		if strings.Contains(event.EventType, "dispute_") && !strings.Contains(event.EventType, "dispute_resolved") {
			return true, nil
		}
	}
	
	return false, nil
}

// getActiveLegalHolds returns list of active legal holds
func (s *LGPDComplianceService) getActiveLegalHolds(ctx context.Context, userID uint) ([]map[string]interface{}, error) {
	var legalHolds []map[string]interface{}
	
	events, err := s.auditRepo.FindByUser(ctx, userID, 50, 0)
	if err != nil {
		return nil, err
	}
	
	for _, event := range events {
		if event.EventType == "legal_hold_placed" || event.EventType == "investigation_started" {
			if !s.hasLegalHoldRelease(ctx, userID, event.Timestamp) {
				legalHolds = append(legalHolds, map[string]interface{}{
					"type":       event.EventType,
					"placed_at":  event.Timestamp,
					"reason":     event.Action,
					"active":     true,
				})
			}
		}
	}
	
	return legalHolds, nil
}

// getActiveContracts returns list of active contracts
func (s *LGPDComplianceService) getActiveContracts(ctx context.Context, userID uint) ([]map[string]interface{}, error) {
	var contracts []map[string]interface{}
	
	events, err := s.auditRepo.FindByUser(ctx, userID, 50, 0)
	if err != nil {
		return nil, err
	}
	
	for _, event := range events {
		if strings.Contains(event.EventType, "contract_activated") || strings.Contains(event.EventType, "subscription_started") {
			if !s.hasContractTermination(ctx, userID, event.Timestamp) {
				contracts = append(contracts, map[string]interface{}{
					"type":       event.EventType,
					"started_at": event.Timestamp,
					"status":     "active",
				})
			}
		}
	}
	
	return contracts, nil
}

// formatRetentionPolicies formats retention policies for report
func (s *LGPDComplianceService) formatRetentionPolicies(policies []domain.DataRetentionPolicy) []map[string]interface{} {
	var formatted []map[string]interface{}
	
	for _, policy := range policies {
		formatted = append(formatted, map[string]interface{}{
			"data_type":        policy.DataType,
			"retention_days":   int(policy.RetentionPeriod.Hours() / 24),
			"legal_basis":      policy.LegalBasis,
			"mandatory":        policy.Mandatory,
			"description":      policy.Description,
		})
	}
	
	return formatted
}

// getRecommendedAction determines recommended action based on compliance status
func (s *LGPDComplianceService) getRecommendedAction(canDelete bool, hasRetention bool, anonymizationOk bool) string {
	if canDelete && !hasRetention {
		return "immediate_deletion"
	}
	if canDelete && anonymizationOk {
		return "anonymization"
	}
	if hasRetention {
		return "retention_required"
	}
	return "review_required"
}

// getMinimumRetentionPeriod calculates minimum retention period from policies
func (s *LGPDComplianceService) getMinimumRetentionPeriod(policies []domain.DataRetentionPolicy) string {
	if len(policies) == 0 {
		return "0 days"
	}
	
	var maxRetention time.Duration
	for _, policy := range policies {
		if policy.RetentionPeriod > maxRetention {
			maxRetention = policy.RetentionPeriod
		}
	}
	
	days := int(maxRetention.Hours() / 24)
	return fmt.Sprintf("%d days", days)
}

// Helper methods

func (s *LGPDComplianceService) hasLegalHoldRelease(ctx context.Context, userID uint, holdDate time.Time) bool {
	events, _ := s.auditRepo.FindByUser(ctx, userID, 20, 0)
	for _, event := range events {
		if event.Timestamp.After(holdDate) && 
		   (event.EventType == "legal_hold_released" || event.EventType == "investigation_completed") {
			return true
		}
	}
	return false
}

func (s *LGPDComplianceService) hasTransactionCompletion(ctx context.Context, userID uint, transactionID uint64) bool {
	events, _ := s.auditRepo.FindByUser(ctx, userID, 20, 0)
	for _, event := range events {
		if strings.Contains(event.EventType, "transaction_completed") || 
		   strings.Contains(event.EventType, "payment_confirmed") {
			return true
		}
	}
	return false
}

func (s *LGPDComplianceService) hasInvestigationCompletion(ctx context.Context, userID uint, startDate time.Time) bool {
	events, _ := s.auditRepo.FindByUser(ctx, userID, 20, 0)
	for _, event := range events {
		if event.Timestamp.After(startDate) && 
		   (strings.Contains(event.EventType, "investigation_completed") || 
		    strings.Contains(event.EventType, "audit_completed")) {
			return true
		}
	}
	return false
}

func (s *LGPDComplianceService) hasContractTermination(ctx context.Context, userID uint, contractDate time.Time) bool {
	events, _ := s.auditRepo.FindByUser(ctx, userID, 20, 0)
	for _, event := range events {
		if event.Timestamp.After(contractDate) && 
		   (strings.Contains(event.EventType, "contract_terminated") || 
		    strings.Contains(event.EventType, "subscription_cancelled")) {
			return true
		}
	}
	return false
}

func (s *LGPDComplianceService) checkExternalLegalHoldSystem(ctx context.Context, userID uint) bool {
	// In production, this would call an external legal hold management system
	// For now, return false unless in specific test scenarios
	return false
}

func (s *LGPDComplianceService) checkFinancialObligations(ctx context.Context, userID uint) bool {
	// Check for outstanding payments or financial obligations
	events, _ := s.auditRepo.FindByUser(ctx, userID, 20, 0)
	for _, event := range events {
		if strings.Contains(event.EventType, "payment_due") || 
		   strings.Contains(event.EventType, "invoice_outstanding") {
			return true
		}
	}
	return false
}

func (s *LGPDComplianceService) getLastFinancialActivityDate(ctx context.Context, userID uint) time.Time {
	events, _ := s.auditRepo.FindByUser(ctx, userID, 100, 0)
	var lastDate time.Time
	
	for _, event := range events {
		if strings.Contains(event.EventType, "payment_") || 
		   strings.Contains(event.EventType, "transaction_") {
			if event.Timestamp.After(lastDate) {
				lastDate = event.Timestamp
			}
		}
	}
	
	if lastDate.IsZero() {
		return time.Now().AddDate(-1, 0, 0) // Default to 1 year ago
	}
	return lastDate
}

func (s *LGPDComplianceService) getLastTaxEventDate(ctx context.Context, userID uint) time.Time {
	events, _ := s.auditRepo.FindByUser(ctx, userID, 100, 0)
	var lastDate time.Time
	
	for _, event := range events {
		if strings.Contains(event.EventType, "tax_") || 
		   strings.Contains(event.EventType, "fiscal_") {
			if event.Timestamp.After(lastDate) {
				lastDate = event.Timestamp
			}
		}
	}
	
	if lastDate.IsZero() {
		return time.Now().AddDate(-1, 0, 0) // Default to 1 year ago
	}
	return lastDate
}

// Compile-time interface compliance check
var _ domain.LGPDComplianceChecker = (*LGPDComplianceService)(nil)