package services

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/you/authzsvc/domain"
)

// AuditIntegratedAuthService wraps the existing AuthService with audit logging
type AuditIntegratedAuthService struct {
	authService domain.AuthService
	auditLogger domain.ComprehensiveAuditLogger
	logger      *slog.Logger
}

// NewAuditIntegratedAuthService creates an auth service with integrated audit logging
func NewAuditIntegratedAuthService(
	authService domain.AuthService,
	auditLogger domain.ComprehensiveAuditLogger,
	logger *slog.Logger,
) domain.AuthService {
	return &AuditIntegratedAuthService{
		authService: authService,
		auditLogger: auditLogger,
		logger:      logger,
	}
}

// Register implements domain.AuthService with audit logging
func (s *AuditIntegratedAuthService) Register(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
	startTime := time.Now()
	
	// Extract client context for auditing
	clientCtx := s.extractClientContext(ctx)
	
	// Call the original auth service
	user, err := s.authService.Register(ctx, email, phone, password, role)
	
	// Log the registration attempt
	if s.auditLogger != nil {
		authEvent := &domain.AuthEvent{
			UserID:        0, // Will be set after successful registration
			Email:         email,
			Action:        "register",
			Success:       err == nil,
			FailureReason: "",
			SessionID:     "",
			IPAddress:     clientCtx.IPAddress,
			UserAgent:     clientCtx.UserAgent,
			Timestamp:     startTime,
			Metadata: map[string]interface{}{
				"phone": phone,
				"role":  role,
			},
		}
		
		if err != nil {
			authEvent.FailureReason = err.Error()
		} else if user != nil {
			authEvent.UserID = user.ID
		}
		
		if auditErr := s.auditLogger.LogAuthenticationEvent(ctx, authEvent); auditErr != nil {
			s.logger.Error("Failed to log registration audit event", "error", auditErr)
		}
	}
	
	return user, err
}

// Login implements domain.AuthService with audit logging
func (s *AuditIntegratedAuthService) Login(ctx context.Context, email, password string) (*domain.AuthResult, error) {
	startTime := time.Now()
	
	// Extract client context for auditing
	clientCtx := s.extractClientContext(ctx)
	
	// Call the original auth service
	result, err := s.authService.Login(ctx, email, password)
	
	// Log the login attempt
	if s.auditLogger != nil {
		var userID uint
		var sessionID string
		
		if result != nil && result.User != nil {
			userID = result.User.ID
			sessionID = result.SessionID
		}
		
		// Log authentication event
		authEvent := &domain.AuthEvent{
			UserID:        userID,
			Email:         email,
			Action:        "login",
			Success:       err == nil,
			FailureReason: "",
			SessionID:     sessionID,
			IPAddress:     clientCtx.IPAddress,
			UserAgent:     clientCtx.UserAgent,
			Timestamp:     startTime,
			Metadata:      map[string]interface{}{},
		}
		
		if err != nil {
			authEvent.FailureReason = err.Error()
		}
		
		if auditErr := s.auditLogger.LogAuthenticationEvent(ctx, authEvent); auditErr != nil {
			s.logger.Error("Failed to log login audit event", "error", auditErr)
		}
		
		// Additional security logging for failed attempts
		if err != nil {
			if auditErr := s.auditLogger.LogLoginAttempt(ctx, userID, email, clientCtx.IPAddress, false, err.Error()); auditErr != nil {
				s.logger.Error("Failed to log failed login attempt", "error", auditErr)
			}
		}
	}
	
	return result, err
}

// RefreshToken implements domain.AuthService with audit logging
func (s *AuditIntegratedAuthService) RefreshToken(ctx context.Context, refreshToken string) (*domain.AuthResult, error) {
	startTime := time.Now()
	
	// Extract client context for auditing
	clientCtx := s.extractClientContext(ctx)
	
	// Call the original auth service
	result, err := s.authService.RefreshToken(ctx, refreshToken)
	
	// Log the token refresh attempt
	if s.auditLogger != nil {
		var userID uint
		var sessionID string
		
		if result != nil && result.User != nil {
			userID = result.User.ID
			sessionID = result.SessionID
		}
		
		authEvent := &domain.AuthEvent{
			UserID:        userID,
			Email:         "",
			Action:        "refresh_token",
			Success:       err == nil,
			FailureReason: "",
			SessionID:     sessionID,
			IPAddress:     clientCtx.IPAddress,
			UserAgent:     clientCtx.UserAgent,
			Timestamp:     startTime,
			Metadata: map[string]interface{}{
				"token_operation": "refresh",
			},
		}
		
		if err != nil {
			authEvent.FailureReason = err.Error()
		}
		
		if result != nil && result.User != nil {
			authEvent.Email = result.User.Email
		}
		
		if auditErr := s.auditLogger.LogAuthenticationEvent(ctx, authEvent); auditErr != nil {
			s.logger.Error("Failed to log token refresh audit event", "error", auditErr)
		}
	}
	
	return result, err
}

// Logout implements domain.AuthService with audit logging
func (s *AuditIntegratedAuthService) Logout(ctx context.Context, sessionID string) error {
	// Extract client context for auditing
	clientCtx := s.extractClientContext(ctx)
	
	// Call the original auth service
	err := s.authService.Logout(ctx, sessionID)
	
	// Log the logout
	if s.auditLogger != nil {
		// Try to extract user ID from context if available
		var userID uint
		if userIDValue := ctx.Value("user_id"); userIDValue != nil {
			if uid, ok := userIDValue.(uint); ok {
				userID = uid
			}
		}
		
		if logErr := s.auditLogger.LogLogout(ctx, userID, sessionID, clientCtx.IPAddress); logErr != nil {
			s.logger.Error("Failed to log logout audit event", "error", logErr)
		}
	}
	
	return err
}

// GetUserProfile implements domain.AuthService with audit logging
func (s *AuditIntegratedAuthService) GetUserProfile(ctx context.Context, userID uint) (*domain.User, error) {
	// Extract client context for auditing
	clientCtx := s.extractClientContext(ctx)
	
	// Call the original auth service
	user, err := s.authService.GetUserProfile(ctx, userID)
	
	// Log the data access for LGPD compliance
	if s.auditLogger != nil && err == nil {
		dataAccessEvent := &domain.DataAccessEvent{
			UserID:             userID,
			DataSubjectID:      &userID, // Accessing own profile
			DataType:           "user_profile",
			Operation:          domain.DataOperationRead,
			LegalBasis:         domain.LegalBasisLegitimateInterests,
			ConsentID:          "",
			DataClassification: domain.DataClassificationPII,
			FieldsAccessed:     []string{"id", "email", "phone", "role", "is_active", "phone_verified"},
			RecordsCount:       1,
			IPAddress:          clientCtx.IPAddress,
			SessionID:          clientCtx.SessionID,
			Timestamp:          time.Now().UTC(),
			Purpose:            "user_profile_access",
			Metadata: map[string]interface{}{
				"accessed_own_profile": true,
			},
		}
		
		if auditErr := s.auditLogger.LogDataAccessEvent(ctx, dataAccessEvent); auditErr != nil {
			s.logger.Error("Failed to log user profile access audit event", "error", auditErr)
		}
	}
	
	return user, err
}

// AuthenticateUser implements domain.AuthService with audit logging for CB-194
func (s *AuditIntegratedAuthService) AuthenticateUser(ctx context.Context, request *domain.AuthRequest) (*domain.AuthResult, error) {
	// Determine identifier for logging (preserve privacy)
	identifier := request.Email
	if identifier == "" {
		identifier = request.Identifier
	}
	// Mask identifier for privacy
	maskedIdentifier := s.maskIdentifier(identifier)
	
	// Call the original auth service
	result, err := s.authService.AuthenticateUser(ctx, request)
	
	// Log the authentication attempt with method metadata
	if s.auditLogger != nil {
		var userID uint = 0
		var authMethod string = ""
		if result != nil && result.User != nil {
			userID = result.User.ID
		}
		if result != nil && result.AuthenticationContext != nil {
			authMethod = string(result.AuthenticationContext.Method)
		}
		
		// Use existing LogLoginAttempt method with enhanced message
		successMessage := ""
		if err == nil {
			successMessage = fmt.Sprintf("authentication successful via %s", authMethod)
		} else {
			successMessage = err.Error()
		}
		
		// Log the authentication attempt
		auditErr := s.auditLogger.LogLoginAttempt(ctx, userID, maskedIdentifier, authMethod, err == nil, successMessage)
		if auditErr != nil {
			s.logger.Error("Failed to log authentication event",
				"error", auditErr,
				"user_id", userID,
				"auth_method", authMethod,
				"success", err == nil,
			)
		}
	}
	
	return result, err
}

// maskIdentifier masks sensitive parts of identifiers for logging
func (s *AuditIntegratedAuthService) maskIdentifier(identifier string) string {
	if identifier == "" {
		return ""
	}
	
	// For emails, show first 3 chars and domain
	if containsAt := false; len(identifier) > 0 {
		for _, char := range identifier {
			if char == '@' {
				containsAt = true
				break
			}
		}
		if containsAt {
			parts := make([]string, 0, 2)
			current := ""
			for _, char := range identifier {
				if char == '@' {
					parts = append(parts, current)
					current = ""
				} else {
					current += string(char)
				}
			}
			parts = append(parts, current)
			
			if len(parts) == 2 && len(parts[0]) > 3 {
				return parts[0][:3] + "***@" + parts[1]
			}
		}
	}
	
	// For phone numbers, show country code and last 4 digits
	if len(identifier) > 7 {
		if identifier[0] == '+' {
			// International format
			return identifier[:2] + "***" + identifier[len(identifier)-4:]
		}
		return "***" + identifier[len(identifier)-4:]
	}
	
	return "***"
}

// extractClientContext extracts client information from the request context
func (s *AuditIntegratedAuthService) extractClientContext(ctx context.Context) *domain.ClientContext {
	clientCtx := &domain.ClientContext{
		IPAddress: "unknown",
		UserAgent: "unknown",
		SessionID: "",
	}
	
	// Try to extract IP address from context
	if ipValue := ctx.Value("ip_address"); ipValue != nil {
		if ip, ok := ipValue.(string); ok {
			clientCtx.IPAddress = ip
		}
	}
	
	// Try to extract User-Agent from context
	if uaValue := ctx.Value("user_agent"); uaValue != nil {
		if ua, ok := uaValue.(string); ok {
			clientCtx.UserAgent = ua
		}
	}
	
	// Try to extract session ID from context
	if sessionValue := ctx.Value("session_id"); sessionValue != nil {
		if session, ok := sessionValue.(string); ok {
			clientCtx.SessionID = session
		}
	}
	
	return clientCtx
}

// CasbinAuditIntegration provides audit logging for Casbin authorization events
type CasbinAuditIntegration struct {
	enforcer    domain.CasbinEnforcer
	auditLogger domain.ComprehensiveAuditLogger
	logger      *slog.Logger
}

// NewCasbinAuditIntegration creates a Casbin enforcer with audit logging
func NewCasbinAuditIntegration(
	enforcer domain.CasbinEnforcer,
	auditLogger domain.ComprehensiveAuditLogger,
	logger *slog.Logger,
) *CasbinAuditIntegration {
	return &CasbinAuditIntegration{
		enforcer:    enforcer,
		auditLogger: auditLogger,
		logger:      logger,
	}
}

// Enforce wraps Casbin's Enforce method with audit logging
func (c *CasbinAuditIntegration) Enforce(ctx context.Context, userID uint, role, resource, action string) (bool, error) {
	startTime := time.Now()
	
	// Extract client context
	clientCtx := &domain.ClientContext{
		IPAddress: "unknown",
		UserAgent: "unknown",
		SessionID: "",
	}
	
	if ipValue := ctx.Value("ip_address"); ipValue != nil {
		if ip, ok := ipValue.(string); ok {
			clientCtx.IPAddress = ip
		}
	}
	
	if sessionValue := ctx.Value("session_id"); sessionValue != nil {
		if session, ok := sessionValue.(string); ok {
			clientCtx.SessionID = session
		}
	}
	
	// Call Casbin enforce
	allowed, err := c.enforcer.Enforce(role, resource, action)
	if err != nil {
		return false, fmt.Errorf("casbin enforcement failed: %w", err)
	}
	
	// Log the authorization event
	if c.auditLogger != nil {
		decision := domain.AuthzDecisionDeny
		if allowed {
			decision = domain.AuthzDecisionAllow
		}
		
		authzEvent := &domain.AuthzEvent{
			UserID:        userID,
			Role:          role,
			Resource:      resource,
			Action:        action,
			Decision:      decision,
			PolicyApplied: fmt.Sprintf("casbin_%s_%s_%s", role, resource, action),
			IPAddress:     clientCtx.IPAddress,
			SessionID:     clientCtx.SessionID,
			Timestamp:     startTime,
			Metadata: map[string]interface{}{
				"enforcement_time_ms": time.Since(startTime).Milliseconds(),
			},
		}
		
		if auditErr := c.auditLogger.LogAuthorizationEvent(ctx, authzEvent); auditErr != nil {
			c.logger.Error("Failed to log authorization audit event", "error", auditErr)
		}
		
		// Additional logging for denied access
		if !allowed {
			if auditErr := c.auditLogger.LogAccessDenied(ctx, userID, resource, action, "casbin_policy_denied"); auditErr != nil {
				c.logger.Error("Failed to log access denied audit event", "error", auditErr)
			}
		}
	}
	
	return allowed, nil
}

// GetEnforcer returns the wrapped Casbin enforcer
func (c *CasbinAuditIntegration) GetEnforcer() domain.CasbinEnforcer {
	return c.enforcer
}

// Security validation integration for CB-182 validation system
type SecurityValidationAuditIntegration struct {
	validationService domain.SecurityValidationService
	auditLogger       domain.ComprehensiveAuditLogger
	logger            *slog.Logger
}

// NewSecurityValidationAuditIntegration creates security validation with audit integration
func NewSecurityValidationAuditIntegration(
	validationService domain.SecurityValidationService,
	auditLogger domain.ComprehensiveAuditLogger,
	logger *slog.Logger,
) *SecurityValidationAuditIntegration {
	return &SecurityValidationAuditIntegration{
		validationService: validationService,
		auditLogger:       auditLogger,
		logger:            logger,
	}
}

// ScanForThreats wraps security validation with audit logging
func (s *SecurityValidationAuditIntegration) ScanForThreats(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
	// Call the original validation service
	result, err := s.validationService.ScanForThreats(ctx, input, rules)
	if err != nil {
		return nil, err
	}
	
	// Log security violations found
	if s.auditLogger != nil && result != nil && len(result.Violations) > 0 {
		for _, violation := range result.Violations {
			securityEvent := &domain.SecurityEvent{
				EventType:        domain.SecurityEventType(violation.Type),
				Severity:         s.mapValidationSeverityToSecuritySeverity(violation.Severity),
				Description:      violation.Description,
				UserID:           violation.UserID,
				IPAddress:        violation.IPAddress,
				UserAgent:        violation.UserAgent,
				SessionID:        violation.RequestID, // Use request ID as session context
				ThreatIndicators: []string{violation.Pattern},
				ActionTaken:      domain.SecurityAction(violation.Action),
				BlockedRequest:   input,
				Timestamp:        time.Now().UTC(),
				Metadata: map[string]interface{}{
					"risk_score":  violation.RiskScore,
					"confidence":  violation.Confidence,
					"field_name":  violation.FieldName,
					"pattern":     violation.Pattern,
				},
			}
			
			if auditErr := s.auditLogger.LogSecurityEvent(ctx, securityEvent); auditErr != nil {
				s.logger.Error("Failed to log security validation audit event", "error", auditErr)
			}
		}
	}
	
	return result, nil
}

// Helper methods

func (s *SecurityValidationAuditIntegration) extractClientContext(ctx context.Context) *domain.ClientContext {
	clientCtx := &domain.ClientContext{
		IPAddress: "unknown",
		UserAgent: "unknown",
		SessionID: "",
	}
	
	if ipValue := ctx.Value("ip_address"); ipValue != nil {
		if ip, ok := ipValue.(string); ok {
			clientCtx.IPAddress = ip
		}
	}
	
	if uaValue := ctx.Value("user_agent"); uaValue != nil {
		if ua, ok := uaValue.(string); ok {
			clientCtx.UserAgent = ua
		}
	}
	
	return clientCtx
}

func (s *SecurityValidationAuditIntegration) mapValidationSeverityToSecuritySeverity(severity domain.ValidationSeverity) domain.SecuritySeverity {
	switch severity {
	case domain.SeverityInfo:
		return domain.SecuritySeverityLow
	case domain.SeverityWarning:
		return domain.SecuritySeverityMedium
	case domain.SeverityError:
		return domain.SecuritySeverityHigh
	case domain.SeverityCritical:
		return domain.SecuritySeverityCritical
	default:
		return domain.SecuritySeverityMedium
	}
}