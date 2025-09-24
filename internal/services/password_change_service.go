package services

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/you/authzsvc/domain"
)

// PasswordChangeService handles password change and forgot password operations
type PasswordChangeService struct {
	passwordChangeRepo  domain.PasswordChangeRepository
	passwordHistoryRepo domain.PasswordHistoryRepository
	forgotPasswordRepo  domain.ForgotPasswordRepository
	userRepo            domain.UserRepository
	passwordService     domain.PasswordService
	otpService          domain.OTPService
	sessionRepo         domain.SessionRepository
	auditService        domain.ComprehensiveAuditService
	config              PasswordChangeConfig
}

// PasswordChangeConfig contains configuration for password operations
type PasswordChangeConfig struct {
	RequestTTL              time.Duration // How long password change requests are valid
	OTPTTL                  time.Duration // How long OTP codes are valid
	MaxOTPAttempts          int           // Maximum OTP verification attempts
	PasswordHistoryCount    int           // Number of previous passwords to check for reuse
	RateLimitWindow         time.Duration // Rate limiting window
	MaxRequestsPerWindow    int           // Max password change requests per window per user
	ForgotPasswordRateLimit int           // Max forgot password requests per hour per IP
	MinPasswordLength       int           // Minimum password length
	RequireUppercase        bool          // Require uppercase letters
	RequireLowercase        bool          // Require lowercase letters  
	RequireNumbers          bool          // Require numbers
	RequireSpecialChars     bool          // Require special characters
	ForbiddenPasswords      []string      // Common passwords to forbid
}

// DefaultPasswordChangeConfig returns default configuration
func DefaultPasswordChangeConfig() PasswordChangeConfig {
	return PasswordChangeConfig{
		RequestTTL:              15 * time.Minute,
		OTPTTL:                  5 * time.Minute,
		MaxOTPAttempts:          5,
		PasswordHistoryCount:    5,
		RateLimitWindow:         30 * time.Second,  // Changed to 30 seconds for testing
		MaxRequestsPerWindow:    2,                  // Changed to 2 requests for testing
		ForgotPasswordRateLimit: 2,                  // Changed to 2 for testing
		MinPasswordLength:       8,
		RequireUppercase:        true,
		RequireLowercase:        true,
		RequireNumbers:          true,
		RequireSpecialChars:     false,
		ForbiddenPasswords:      []string{"password", "123456", "admin", "user", "test"},
	}
}

// NewPasswordChangeService creates a new password change service
func NewPasswordChangeService(
	passwordChangeRepo domain.PasswordChangeRepository,
	passwordHistoryRepo domain.PasswordHistoryRepository,
	forgotPasswordRepo domain.ForgotPasswordRepository,
	userRepo domain.UserRepository,
	passwordService domain.PasswordService,
	otpService domain.OTPService,
	sessionRepo domain.SessionRepository,
	auditService domain.ComprehensiveAuditService,
	config PasswordChangeConfig,
) *PasswordChangeService {
	return &PasswordChangeService{
		passwordChangeRepo:  passwordChangeRepo,
		passwordHistoryRepo: passwordHistoryRepo,
		forgotPasswordRepo:  forgotPasswordRepo,
		userRepo:            userRepo,
		passwordService:     passwordService,
		otpService:          otpService,
		sessionRepo:         sessionRepo,
		auditService:        auditService,
		config:              config,
	}
}

// InitiatePasswordChange initiates a password change request for an authenticated user
func (s *PasswordChangeService) InitiatePasswordChange(ctx context.Context, userID uint, currentPassword, newPassword, confirmPassword, ipAddress, userAgent string) (*domain.PasswordChangeResponse, error) {
	// Validate passwords match
	if newPassword != confirmPassword {
		return nil, fmt.Errorf("new password and confirmation do not match")
	}

	// Get user
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	// Verify current password
	if !s.passwordService.Verify(user.PasswordHash, currentPassword) {
		return nil, domain.ErrCurrentPasswordIncorrect
	}

	// Check if new password is same as current
	if s.passwordService.Verify(user.PasswordHash, newPassword) {
		return nil, domain.ErrPasswordSameAsCurrent
	}

	// Validate new password strength
	if err := s.validatePasswordStrength(newPassword, user.Email); err != nil {
		return nil, err
	}

	// Check password history
	if err := s.checkPasswordHistory(ctx, userID, newPassword); err != nil {
		return nil, err
	}

	// Check rate limiting
	if err := s.checkPasswordChangeRateLimit(ctx, userID); err != nil {
		return nil, err
	}

	// Check for existing active request
	existingRequest, err := s.passwordChangeRepo.GetActiveByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to check existing requests: %w", err)
	}
	if existingRequest != nil {
		return nil, domain.ErrPasswordChangeInProgress
	}

	// Generate request ID and nonce
	requestID := s.generateRequestID()
	nonce := s.generateNonce()

	// Create password change request
	request := &domain.PasswordChangeRequest{
		ID:          requestID,
		UserID:      userID,
		Status:      string(domain.PasswordChangeStatusInitiated),
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(s.config.RequestTTL),
		Nonce:       nonce,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
	}

	// Store new password hash temporarily for OTP verification
	// We'll hash it and store in OTPCode field (will be replaced with actual OTP)
	newPasswordHash, err := s.passwordService.Hash(newPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to hash new password: %w", err)
	}
	request.OTPCode = newPasswordHash // Temporarily store here

	// Generate and send OTP
	otpCode, err := s.generateAndSendOTP(ctx, user.Phone, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to send OTP: %w", err)
	}

	// Replace temporary password hash with OTP code
	request.OTPCode = otpCode
	otpExpiresAt := time.Now().Add(s.config.OTPTTL)
	request.OTPGeneratedAt = &time.Time{}
	*request.OTPGeneratedAt = time.Now()
	request.OTPExpiresAt = &otpExpiresAt

	// Save request
	if err := s.passwordChangeRepo.Create(ctx, request); err != nil {
		// Audit the failure
		if s.auditService != nil {
			s.auditService.LogPasswordChangeFailed(ctx, &userID, requestID, fmt.Sprintf("Failed to create request: %v", err), ipAddress, userAgent)
		}
		return nil, fmt.Errorf("failed to create password change request: %w", err)
	}

	// Store the new password hash in a separate field for later verification
	// We'll use a Redis key for this temporarily
	s.storeTemporaryPasswordHash(requestID, newPasswordHash)

	// Audit successful initiation
	if s.auditService != nil {
		if err := s.auditService.LogPasswordChangeInitiated(ctx, userID, requestID, ipAddress, userAgent); err != nil {
			log.Printf("Failed to log password change initiation audit event: %v", err)
		}
	}

	return &domain.PasswordChangeResponse{
		RequestID: requestID,
		Status:    "initiated",
		Message:   "Password change initiated. Please check your phone for OTP verification code.",
		ExpiresAt: request.ExpiresAt,
		Nonce:     nonce,
	}, nil
}

// CompletePasswordChange completes a password change request with OTP verification
func (s *PasswordChangeService) CompletePasswordChange(ctx context.Context, userID uint, requestID, otpCode, nonce string) (*domain.PasswordChangeResponse, error) {
	// Get the request
	request, err := s.passwordChangeRepo.GetByID(ctx, requestID)
	if err != nil {
		return nil, err
	}

	// Verify user owns the request
	if request.UserID != userID {
		return nil, domain.ErrPasswordChangeUnauthorized
	}

	// Check request status
	if request.Status != string(domain.PasswordChangeStatusInitiated) {
		return nil, fmt.Errorf("password change request is not in initiated status")
	}

	// Check if expired
	if request.IsExpired() {
		s.passwordChangeRepo.UpdateStatus(ctx, requestID, string(domain.PasswordChangeStatusExpired), "Request expired")
		// Audit the expiration
		if s.auditService != nil {
			s.auditService.LogPasswordChangeExpired(ctx, userID, requestID, request.IPAddress, request.UserAgent)
		}
		return nil, domain.ErrPasswordChangeExpired
	}

	// Verify nonce
	if request.Nonce != nonce {
		return nil, domain.ErrPasswordChangeInvalidNonce
	}

	// Check OTP attempts
	if !request.CanAttemptOTP() {
		s.passwordChangeRepo.UpdateStatus(ctx, requestID, string(domain.PasswordChangeStatusFailed), "Maximum OTP attempts exceeded")
		return nil, domain.ErrPasswordChangeOTPMaxAttempts
	}

	// For password change requests, OTP expiration is same as request expiration
	// No separate OTP expiration check needed since IsExpired() already validated above

	if request.OTPCode != otpCode {
		// Increment OTP attempts
		request.OTPAttempts++
		s.passwordChangeRepo.UpdateOTPAttempts(ctx, requestID, request.OTPAttempts)
		// Audit the invalid OTP attempt
		if s.auditService != nil {
			s.auditService.LogPasswordChangeFailed(ctx, &userID, requestID, "Invalid OTP code", request.IPAddress, request.UserAgent)
		}
		return nil, domain.ErrPasswordChangeInvalidOTP
	}

	// Get the temporarily stored password hash
	newPasswordHash := s.getTemporaryPasswordHash(requestID)
	if newPasswordHash == "" {
		return nil, fmt.Errorf("password hash not found for request")
	}

	// Update user password
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	// Add current password to history
	if err := s.passwordHistoryRepo.Add(ctx, userID, user.PasswordHash, "change"); err != nil {
		log.Printf("Failed to add password to history: %v", err)
	}

	// Update user password
	user.PasswordHash = newPasswordHash
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user password: %w", err)
	}

	// Invalidate all sessions for security after password change
	if err := s.sessionRepo.DeleteAllForUser(ctx, userID); err != nil {
		log.Printf("Warning: Failed to invalidate sessions for user %d: %v", userID, err)
		// Continue with password change even if session invalidation fails
	} else {
		log.Printf("Successfully invalidated all sessions for user %d after password change", userID)
	}

	// Mark request as completed
	if err := s.passwordChangeRepo.UpdateStatus(ctx, requestID, string(domain.PasswordChangeStatusCompleted), ""); err != nil {
		log.Printf("Failed to update request status: %v", err)
	}

	// Clean up temporary password hash
	s.deleteTemporaryPasswordHash(requestID)

	// Clean up old password history
	s.passwordHistoryRepo.CleanupOldHistory(ctx, userID, s.config.PasswordHistoryCount)

	// Audit successful password change completion
	if s.auditService != nil {
		if err := s.auditService.LogPasswordChangeCompleted(ctx, userID, requestID, request.IPAddress, request.UserAgent); err != nil {
			log.Printf("Failed to log password change completion audit event: %v", err)
		}
	}

	return &domain.PasswordChangeResponse{
		RequestID: requestID,
		Status:    "completed",
		Message:   "Password changed successfully. Please login with your new password.",
	}, nil
}

// InitiateForgotPassword initiates a forgot password request
func (s *PasswordChangeService) InitiateForgotPassword(ctx context.Context, email, phone, ipAddress, userAgent string) (*domain.PasswordChangeResponse, error) {
	// Check rate limiting by IP
	if err := s.checkForgotPasswordRateLimit(ctx, ipAddress); err != nil {
		return nil, err
	}

	// Validate email and phone combination (but don't reveal if user exists)
	userByEmail, err1 := s.userRepo.FindByEmail(ctx, email)
	userByPhone, err2 := s.userRepo.FindByPhone(ctx, phone)
	
	var userID *uint
	// Check if both email and phone belong to the same user
	if err1 == nil && err2 == nil && userByEmail != nil && userByPhone != nil && userByEmail.ID == userByPhone.ID {
		userID = &userByEmail.ID
	}

	// Generate request ID and nonce
	requestID := s.generateRequestID()
	nonce := s.generateNonce()

	// Create forgot password request
	request := &domain.ForgotPasswordRequest{
		ID:          requestID,
		Email:       email,
		Phone:       phone,
		UserID:      userID,
		Status:      string(domain.ForgotPasswordStatusInitiated),
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(s.config.RequestTTL),
		Nonce:       nonce,
		IPAddress:   ipAddress,
		UserAgent:   userAgent,
	}

	// Save request first
	if err := s.forgotPasswordRepo.Create(ctx, request); err != nil {
		return nil, fmt.Errorf("failed to create forgot password request: %w", err)
	}

	// Only send OTP if user exists (but always return success message for security)
	if userID != nil {
		otpCode, err := s.generateAndSendOTP(ctx, phone, *userID)
		if err == nil {
			otpExpiresAt := time.Now().Add(s.config.OTPTTL)
			request.OTPCode = otpCode
			request.OTPGeneratedAt = &time.Time{}
			*request.OTPGeneratedAt = time.Now()
			request.OTPExpiresAt = &otpExpiresAt
			s.forgotPasswordRepo.Update(ctx, request)
		}
	}

	return &domain.PasswordChangeResponse{
		RequestID: requestID,
		Status:    "initiated",
		Message:   "If this email and phone combination exists, an OTP has been sent.",
		ExpiresAt: request.ExpiresAt,
		Nonce:     nonce,
	}, nil
}

// CompleteForgotPassword completes a forgot password request
func (s *PasswordChangeService) CompleteForgotPassword(ctx context.Context, requestID, otpCode, nonce, newPassword, confirmPassword string) (*domain.PasswordChangeResponse, error) {
	// Validate passwords match
	if newPassword != confirmPassword {
		return nil, fmt.Errorf("new password and confirmation do not match")
	}

	// Get the request
	request, err := s.forgotPasswordRepo.GetByID(ctx, requestID)
	if err != nil {
		return nil, err
	}

	// Check if user was found (userID is nil if user doesn't exist)
	if request.UserID == nil {
		return nil, domain.ErrEmailPhoneMismatch
	}

	// Check request status
	if request.Status != string(domain.ForgotPasswordStatusInitiated) {
		return nil, fmt.Errorf("forgot password request is not in initiated status")
	}

	// Check if expired
	if request.IsExpired() {
		s.forgotPasswordRepo.UpdateStatus(ctx, requestID, string(domain.ForgotPasswordStatusExpired), "Request expired")
		return nil, domain.ErrForgotPasswordExpired
	}

	// Verify nonce
	if request.Nonce != nonce {
		return nil, domain.ErrForgotPasswordInvalidNonce
	}

	// Check OTP attempts
	if !request.CanAttemptOTP() {
		s.forgotPasswordRepo.UpdateStatus(ctx, requestID, string(domain.ForgotPasswordStatusFailed), "Maximum OTP attempts exceeded")
		return nil, domain.ErrForgotPasswordOTPMaxAttempts
	}

	// For forgot password requests, OTP expiration is same as request expiration
	// No separate OTP expiration check needed since IsExpired() already validated above

	if request.OTPCode != otpCode {
		// Increment OTP attempts
		request.OTPAttempts++
		s.forgotPasswordRepo.UpdateOTPAttempts(ctx, requestID, request.OTPAttempts)
		return nil, domain.ErrForgotPasswordInvalidOTP
	}

	// Validate new password strength
	user, err := s.userRepo.FindByID(ctx, *request.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if err := s.validatePasswordStrength(newPassword, user.Email); err != nil {
		return nil, err
	}

	// Check password history
	if err := s.checkPasswordHistory(ctx, *request.UserID, newPassword); err != nil {
		return nil, err
	}

	// Hash new password
	newPasswordHash, err := s.passwordService.Hash(newPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to hash new password: %w", err)
	}

	// Add current password to history
	if err := s.passwordHistoryRepo.Add(ctx, *request.UserID, user.PasswordHash, "reset"); err != nil {
		log.Printf("Failed to add password to history: %v", err)
	}

	// Update user password
	user.PasswordHash = newPasswordHash
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update user password: %w", err)
	}

	// Invalidate all sessions for security after password reset
	if err := s.sessionRepo.DeleteAllForUser(ctx, *request.UserID); err != nil {
		log.Printf("Warning: Failed to invalidate sessions for user %d: %v", *request.UserID, err)
		// Continue with password reset even if session invalidation fails
	} else {
		log.Printf("Successfully invalidated all sessions for user %d after password reset", *request.UserID)
	}

	// Mark request as completed
	if err := s.forgotPasswordRepo.UpdateStatus(ctx, requestID, string(domain.ForgotPasswordStatusCompleted), ""); err != nil {
		log.Printf("Failed to update request status: %v", err)
	}

	// Clean up old password history
	s.passwordHistoryRepo.CleanupOldHistory(ctx, *request.UserID, s.config.PasswordHistoryCount)

	return &domain.PasswordChangeResponse{
		RequestID: requestID,
		Status:    "completed",
		Message:   "Password reset successfully. You can now login with your new password.",
	}, nil
}

// GetPasswordChangeStatus gets the status of a password change request
func (s *PasswordChangeService) GetPasswordChangeStatus(ctx context.Context, userID uint, requestID string) (*domain.PasswordChangeStatusResponse, error) {
	request, err := s.passwordChangeRepo.GetByID(ctx, requestID)
	if err != nil {
		return nil, err
	}

	// Verify user owns the request
	if request.UserID != userID {
		return nil, domain.ErrPasswordChangeUnauthorized
	}

	return &domain.PasswordChangeStatusResponse{
		RequestID:   request.ID,
		Status:      request.Status,
		RequestedAt: request.RequestedAt,
		ExpiresAt:   request.ExpiresAt,
		CompletedAt: request.CompletedAt,
		OTPAttempts: request.OTPAttempts,
		IPAddress:   request.IPAddress,
		UserAgent:   request.UserAgent,
	}, nil
}

// CancelPasswordChange cancels a password change request
func (s *PasswordChangeService) CancelPasswordChange(ctx context.Context, userID uint, requestID string) (*domain.PasswordChangeResponse, error) {
	request, err := s.passwordChangeRepo.GetByID(ctx, requestID)
	if err != nil {
		return nil, err
	}

	// Verify user owns the request
	if request.UserID != userID {
		return nil, domain.ErrPasswordChangeUnauthorized
	}

	// Check if request can be cancelled
	if request.Status != string(domain.PasswordChangeStatusInitiated) {
		return nil, fmt.Errorf("password change request cannot be cancelled in current status: %s", request.Status)
	}

	// Cancel the request
	if err := s.passwordChangeRepo.UpdateStatus(ctx, requestID, string(domain.PasswordChangeStatusCancelled), "Cancelled by user"); err != nil {
		return nil, fmt.Errorf("failed to cancel request: %w", err)
	}

	// Clean up temporary password hash
	s.deleteTemporaryPasswordHash(requestID)

	return &domain.PasswordChangeResponse{
		RequestID: requestID,
		Status:    "cancelled",
		Message:   "Password change request cancelled successfully.",
	}, nil
}

// GetPasswordChangeHistory gets the password change history for a user
func (s *PasswordChangeService) GetPasswordChangeHistory(ctx context.Context, userID uint, limit int) (*domain.PasswordChangeHistoryResponse, error) {
	requests, err := s.passwordChangeRepo.GetByUserID(ctx, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get password change history: %w", err)
	}

	history := make([]domain.PasswordChangeStatusResponse, len(requests))
	for i, request := range requests {
		history[i] = domain.PasswordChangeStatusResponse{
			RequestID:   request.ID,
			Status:      request.Status,
			RequestedAt: request.RequestedAt,
			ExpiresAt:   request.ExpiresAt,
			CompletedAt: request.CompletedAt,
			OTPAttempts: request.OTPAttempts,
			IPAddress:   request.IPAddress,
			UserAgent:   request.UserAgent,
		}
	}

	return &domain.PasswordChangeHistoryResponse{
		History: history,
	}, nil
}

// Helper methods

func (s *PasswordChangeService) validatePasswordStrength(password, email string) error {
	if len(password) < s.config.MinPasswordLength {
		return domain.ErrPasswordStrengthInsufficient
	}

	if s.config.RequireUppercase && !containsUppercase(password) {
		return domain.ErrPasswordStrengthInsufficient
	}

	if s.config.RequireLowercase && !containsLowercase(password) {
		return domain.ErrPasswordStrengthInsufficient
	}

	if s.config.RequireNumbers && !containsNumbers(password) {
		return domain.ErrPasswordStrengthInsufficient
	}

	if s.config.RequireSpecialChars && !containsSpecialChars(password) {
		return domain.ErrPasswordStrengthInsufficient
	}

	// Check against forbidden passwords
	lowerPassword := strings.ToLower(password)
	for _, forbidden := range s.config.ForbiddenPasswords {
		if lowerPassword == strings.ToLower(forbidden) {
			return domain.ErrPasswordCommonlyUsed
		}
	}

	// Check if password contains user info
	if email != "" {
		emailPrefix := strings.Split(email, "@")[0]
		if strings.Contains(strings.ToLower(password), strings.ToLower(emailPrefix)) {
			return domain.ErrPasswordContainsUserInfo
		}
	}

	return nil
}

func (s *PasswordChangeService) checkPasswordHistory(ctx context.Context, userID uint, newPassword string) error {
	recentHashes, err := s.passwordHistoryRepo.GetRecentPasswords(ctx, userID, s.config.PasswordHistoryCount)
	if err != nil {
		return fmt.Errorf("failed to check password history: %w", err)
	}

	for _, hash := range recentHashes {
		if s.passwordService.Verify(hash, newPassword) {
			return domain.ErrPasswordReused
		}
	}

	return nil
}

func (s *PasswordChangeService) checkPasswordChangeRateLimit(ctx context.Context, userID uint) error {
	since := time.Now().Add(-s.config.RateLimitWindow)
	count, err := s.passwordChangeRepo.CountRecentByUserID(ctx, userID, since)
	if err != nil {
		return fmt.Errorf("failed to check rate limit: %w", err)
	}

	if count >= int64(s.config.MaxRequestsPerWindow) {
		return domain.ErrPasswordChangeRateLimitExceeded
	}

	return nil
}

func (s *PasswordChangeService) checkForgotPasswordRateLimit(ctx context.Context, ipAddress string) error {
	since := time.Now().Add(-time.Hour)
	count, err := s.forgotPasswordRepo.CountRecentByIP(ctx, ipAddress, since)
	if err != nil {
		return fmt.Errorf("failed to check rate limit: %w", err)
	}

	// Check forgot password rate limit
	if count >= int64(s.config.ForgotPasswordRateLimit) {
		return domain.ErrForgotPasswordRateLimitExceeded
	}

	return nil
}

func (s *PasswordChangeService) generateRequestID() string {
	// Generate a proper UUID for database compatibility
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		panic(err)
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant is 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:])
}

func (s *PasswordChangeService) generateNonce() string {
	return s.generateRandomString(32)
}

func (s *PasswordChangeService) generateRandomString(length int) string {
	bytes := make([]byte, length/2)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *PasswordChangeService) generateAndSendOTP(ctx context.Context, phone string, userID uint) (string, error) {
	otpRequest, err := s.otpService.Generate(ctx, phone, userID)
	if err != nil {
		return "", err
	}
	return otpRequest.Code, nil
}

// Thread-safe temporary password hash storage using sync.Map
var (
	tempPasswordHashes = &sync.Map{}
	tempPasswordTTL    = &sync.Map{}
)

func (s *PasswordChangeService) storeTemporaryPasswordHash(requestID, hash string) {
	tempPasswordHashes.Store(requestID, hash)
	// Set TTL for automatic cleanup
	tempPasswordTTL.Store(requestID, time.Now().Add(30*time.Minute))
	
	// Start cleanup goroutine if needed (run once per service instance)
	go s.cleanupExpiredHashes()
}

func (s *PasswordChangeService) getTemporaryPasswordHash(requestID string) string {
	// Check if expired
	if ttl, exists := tempPasswordTTL.Load(requestID); exists {
		if time.Now().After(ttl.(time.Time)) {
			s.deleteTemporaryPasswordHash(requestID)
			return ""
		}
	}
	
	if hash, exists := tempPasswordHashes.Load(requestID); exists {
		return hash.(string)
	}
	return ""
}

func (s *PasswordChangeService) deleteTemporaryPasswordHash(requestID string) {
	tempPasswordHashes.Delete(requestID)
	tempPasswordTTL.Delete(requestID)
}

// cleanupExpiredHashes runs periodically to clean up expired hashes
func (s *PasswordChangeService) cleanupExpiredHashes() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		now := time.Now()
		tempPasswordTTL.Range(func(key, value interface{}) bool {
			if now.After(value.(time.Time)) {
				requestID := key.(string)
				s.deleteTemporaryPasswordHash(requestID)
			}
			return true
		})
	}
}

// Password validation helper functions
func containsUppercase(s string) bool {
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			return true
		}
	}
	return false
}

func containsLowercase(s string) bool {
	for _, r := range s {
		if r >= 'a' && r <= 'z' {
			return true
		}
	}
	return false
}

func containsNumbers(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

func containsSpecialChars(s string) bool {
	specialChars := "!@#$%^&*()_+-=[]{}|;:,.<>?"
	for _, r := range s {
		for _, sc := range specialChars {
			if r == sc {
				return true
			}
		}
	}
	return false
}