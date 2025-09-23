package domain

import (
	"time"
)

// PasswordChangeRequest represents a password change request in the domain
type PasswordChangeRequest struct {
	ID                string
	UserID            uint
	CurrentPassword   string    // Only for validation, not stored
	NewPassword       string    // Only for validation, not stored
	Status            string    // initiated, completed, failed, expired, cancelled
	RequestedAt       time.Time
	ExpiresAt         time.Time
	CompletedAt       *time.Time
	OTPCode           string    // Temporary OTP for verification
	OTPAttempts       int
	OTPGeneratedAt    *time.Time
	OTPExpiresAt      *time.Time
	Nonce             string    // Security nonce for request validation
	IPAddress         string
	UserAgent         string
	FailureReason     string
	SessionInvalidated bool
}

// ForgotPasswordRequest represents a forgot password request in the domain
type ForgotPasswordRequest struct {
	ID             string
	Email          string
	Phone          string
	UserID         *uint     // Found user ID, nil if user not found
	Status         string    // initiated, completed, failed, expired, cancelled
	RequestedAt    time.Time
	ExpiresAt      time.Time
	CompletedAt    *time.Time
	OTPCode        string    // Temporary OTP for verification
	OTPAttempts    int
	OTPGeneratedAt *time.Time
	OTPExpiresAt   *time.Time
	Nonce          string    // Security nonce for request validation
	IPAddress      string
	UserAgent      string
	FailureReason  string
}

// PasswordHistory represents a user's password history for preventing reuse
type PasswordHistory struct {
	ID           uint
	UserID       uint
	PasswordHash string
	CreatedAt    time.Time
	Source       string // "change", "reset", "initial"
}

// PasswordChangeStatus represents the possible states of a password change request
type PasswordChangeStatus string

const (
	PasswordChangeStatusInitiated PasswordChangeStatus = "initiated"
	PasswordChangeStatusCompleted PasswordChangeStatus = "completed"
	PasswordChangeStatusFailed    PasswordChangeStatus = "failed"
	PasswordChangeStatusExpired   PasswordChangeStatus = "expired"
	PasswordChangeStatusCancelled PasswordChangeStatus = "cancelled"
)

// ForgotPasswordStatus represents the possible states of a forgot password request
type ForgotPasswordStatus string

const (
	ForgotPasswordStatusInitiated ForgotPasswordStatus = "initiated"
	ForgotPasswordStatusCompleted ForgotPasswordStatus = "completed"
	ForgotPasswordStatusFailed    ForgotPasswordStatus = "failed"
	ForgotPasswordStatusExpired   ForgotPasswordStatus = "expired"
	ForgotPasswordStatusCancelled ForgotPasswordStatus = "cancelled"
)

// PasswordChangeInitiateRequest represents the request to initiate a password change
type PasswordChangeInitiateRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
	ConfirmPassword string `json:"confirm_password" binding:"required"`
}

// PasswordChangeCompleteRequest represents the request to complete a password change
type PasswordChangeCompleteRequest struct {
	OTPCode string `json:"otp_code" binding:"required"`
	Nonce   string `json:"nonce" binding:"required"`
}

// ForgotPasswordInitiateRequest represents the request to initiate forgot password
type ForgotPasswordInitiateRequest struct {
	Email string `json:"email" binding:"required"`
	Phone string `json:"phone" binding:"required"`
}

// ForgotPasswordCompleteRequest represents the request to complete forgot password
type ForgotPasswordCompleteRequest struct {
	OTPCode         string `json:"otp_code" binding:"required"`
	Nonce           string `json:"nonce" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
	ConfirmPassword string `json:"confirm_password" binding:"required"`
}

// PasswordChangeResponse represents the response for password change operations
type PasswordChangeResponse struct {
	RequestID string    `json:"request_id"`
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Nonce     string    `json:"nonce,omitempty"`
}

// PasswordChangeStatusResponse represents the status response for password change requests
type PasswordChangeStatusResponse struct {
	RequestID    string     `json:"request_id"`
	Status       string     `json:"status"`
	RequestedAt  time.Time  `json:"requested_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	OTPAttempts  int        `json:"otp_attempts"`
	IPAddress    string     `json:"ip_address,omitempty"`
	UserAgent    string     `json:"user_agent,omitempty"`
}

// PasswordChangeHistoryResponse represents the response for password change history
type PasswordChangeHistoryResponse struct {
	History []PasswordChangeStatusResponse `json:"history"`
}

// IsExpired checks if the password change request has expired
func (pcr *PasswordChangeRequest) IsExpired() bool {
	return time.Now().After(pcr.ExpiresAt)
}

// IsOTPExpired checks if the OTP has expired
func (pcr *PasswordChangeRequest) IsOTPExpired() bool {
	if pcr.OTPExpiresAt == nil {
		return true
	}
	return time.Now().After(*pcr.OTPExpiresAt)
}

// CanAttemptOTP checks if more OTP attempts are allowed
func (pcr *PasswordChangeRequest) CanAttemptOTP() bool {
	return pcr.OTPAttempts < 5 // Max 5 attempts
}

// IsExpired checks if the forgot password request has expired
func (fpr *ForgotPasswordRequest) IsExpired() bool {
	return time.Now().After(fpr.ExpiresAt)
}

// IsOTPExpired checks if the OTP has expired
func (fpr *ForgotPasswordRequest) IsOTPExpired() bool {
	if fpr.OTPExpiresAt == nil {
		return true
	}
	return time.Now().After(*fpr.OTPExpiresAt)
}

// CanAttemptOTP checks if more OTP attempts are allowed
func (fpr *ForgotPasswordRequest) CanAttemptOTP() bool {
	return fpr.OTPAttempts < 5 // Max 5 attempts
}