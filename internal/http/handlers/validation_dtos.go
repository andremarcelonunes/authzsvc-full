package handlers

import (
	"encoding/json"
	"time"
	
	"github.com/you/authzsvc/domain"
)

// ValidationMetadata provides additional context for cross-field validation
type ValidationMetadata struct {
	RequestID        string            `json:"request_id,omitempty"`
	ClientIP         string            `json:"client_ip,omitempty"`
	UserAgent        string            `json:"user_agent,omitempty"`
	Timestamp        time.Time         `json:"timestamp,omitempty"`
	ValidationRules  []string          `json:"validation_rules,omitempty"`
	SecurityContext  map[string]string `json:"security_context,omitempty"`
}

// RegisterRequestV2 represents enhanced registration request with comprehensive validation
type RegisterRequestV2 struct {
	// Basic fields with enhanced validation
	Email    string `json:"email" binding:"required,email,max=255" validate:"business_email,no_disposable_email,domain_whitelist"`
	Phone    string `json:"phone" binding:"required,min=10,max=15" validate:"phone_format,phone_region_valid,no_voip"`
	Password string `json:"password" binding:"required,min=8,max=128" validate:"password_complexity,no_common_passwords,no_personal_info"`
	Role     string `json:"role,omitempty" binding:"omitempty,oneof=user admin moderator" validate:"role_allowed_for_registration"`
	
	// Enhanced security fields
	CaptchaToken      string `json:"captcha_token,omitempty" validate:"captcha_valid_if_required"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty" validate:"device_fingerprint_format"`
	ReferralCode      string `json:"referral_code,omitempty" validate:"referral_code_valid"`
	
	// Terms and privacy
	AcceptTerms       bool   `json:"accept_terms" binding:"required" validate:"must_be_true"`
	AcceptPrivacy     bool   `json:"accept_privacy" binding:"required" validate:"must_be_true"`
	AcceptMarketing   bool   `json:"accept_marketing,omitempty"`
	
	// Geographic and locale information
	Country           string `json:"country,omitempty" validate:"country_code_valid"`
	Timezone          string `json:"timezone,omitempty" validate:"timezone_valid"`
	Language          string `json:"language,omitempty" validate:"language_code_valid"`
	
	// Additional profile information
	FirstName         string `json:"first_name,omitempty" binding:"omitempty,max=50" validate:"name_format,no_special_chars"`
	LastName          string `json:"last_name,omitempty" binding:"omitempty,max=50" validate:"name_format,no_special_chars"`
	DateOfBirth       string `json:"date_of_birth,omitempty" validate:"date_format,age_verification"`
	
	// Cross-field validation metadata
	Metadata ValidationMetadata `json:"-"`
}

// LoginRequestV2 represents enhanced login request with security validation
type LoginRequestV2 struct {
	// Credentials with security validation
	Email    string `json:"email" binding:"required,email,max=255" validate:"no_xss,no_sql_injection,email_format"`
	Password string `json:"password" binding:"required,max=128" validate:"no_sql_injection,no_script_injection,length_check"`
	
	// Security enhancement fields
	CaptchaToken      string `json:"captcha_token,omitempty" validate:"captcha_valid_if_suspicious"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty" validate:"device_fingerprint_format,device_tracking"`
	TwoFactorCode     string `json:"two_factor_code,omitempty" validate:"2fa_code_format"`
	
	// Session management
	RememberMe        bool   `json:"remember_me,omitempty"`
	SessionDuration   int    `json:"session_duration,omitempty" validate:"session_duration_valid"`
	
	// Risk assessment fields
	ClientTimezone    string `json:"client_timezone,omitempty" validate:"timezone_valid"`
	ClientLanguage    string `json:"client_language,omitempty" validate:"language_code_valid"`
	ClientPlatform    string `json:"client_platform,omitempty" validate:"platform_valid"`
	
	// Cross-field validation metadata
	Metadata ValidationMetadata `json:"-"`
}

// OTPVerifyRequestV2 represents enhanced OTP verification request
type OTPVerifyRequestV2 struct {
	// Core OTP fields with enhanced validation
	Phone    string `json:"phone" binding:"required,min=10,max=15" validate:"phone_format,user_owns_phone,phone_verified"`
	Code     string `json:"code" binding:"required,len=6,numeric" validate:"otp_format,otp_not_expired,otp_attempts_check"`
	UserID   uint   `json:"user_id" binding:"required" validate:"user_exists,user_active,matches_phone"`
	
	// OTP context and security
	OTPType          string `json:"otp_type,omitempty" binding:"omitempty,oneof=sms email voice" validate:"otp_type_valid"`
	RequestID        string `json:"request_id,omitempty" validate:"request_id_valid,request_not_expired"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty" validate:"device_fingerprint_format"`
	
	// Rate limiting and security context
	RequestSource    string `json:"request_source,omitempty" validate:"known_source,source_allowed"`
	ClientIP         string `json:"client_ip,omitempty" validate:"ip_format,ip_not_blocked"`
	
	// Verification context
	VerificationPurpose string `json:"verification_purpose,omitempty" validate:"purpose_valid"`
	ExpiresAt          string `json:"expires_at,omitempty" validate:"expiry_format,not_expired"`
	
	// Cross-field validation metadata
	Metadata ValidationMetadata `json:"-"`
}

// RefreshTokenRequestV2 represents enhanced token refresh request
type RefreshTokenRequestV2 struct {
	// Token fields
	RefreshToken string `json:"refresh_token" binding:"required" validate:"jwt_format,token_not_expired,token_not_revoked"`
	
	// Security context
	DeviceFingerprint string `json:"device_fingerprint,omitempty" validate:"device_fingerprint_format,device_consistency"`
	ClientInfo        string `json:"client_info,omitempty" validate:"client_info_format"`
	
	// Session management
	ExtendSession     bool   `json:"extend_session,omitempty"`
	SessionScope      string `json:"session_scope,omitempty" validate:"scope_valid"`
	
	// Cross-field validation metadata
	Metadata ValidationMetadata `json:"-"`
}

// PasswordResetRequestV2 represents enhanced password reset request
type PasswordResetRequestV2 struct {
	// Identification
	Email string `json:"email" binding:"required,email,max=255" validate:"email_format,user_exists,account_active"`
	
	// Security validation
	CaptchaToken string `json:"captcha_token,omitempty" validate:"captcha_valid_if_required"`
	
	// Reset context
	ResetReason  string `json:"reset_reason,omitempty" validate:"reset_reason_valid"`
	ClientInfo   string `json:"client_info,omitempty" validate:"client_info_format"`
	
	// Cross-field validation metadata
	Metadata ValidationMetadata `json:"-"`
}

// PasswordUpdateRequestV2 represents enhanced password update request
type PasswordUpdateRequestV2 struct {
	// Current and new passwords
	CurrentPassword string `json:"current_password" binding:"required,max=128" validate:"password_correct"`
	NewPassword     string `json:"new_password" binding:"required,min=8,max=128" validate:"password_complexity,password_not_reused,password_different"`
	ConfirmPassword string `json:"confirm_password" binding:"required" validate:"passwords_match"`
	
	// Security context
	TwoFactorCode     string `json:"two_factor_code,omitempty" validate:"2fa_code_valid_if_required"`
	DeviceFingerprint string `json:"device_fingerprint,omitempty" validate:"device_fingerprint_format"`
	
	// Update context
	ForceLogoutAll    bool   `json:"force_logout_all,omitempty"`
	UpdateReason      string `json:"update_reason,omitempty" validate:"update_reason_valid"`
	
	// Cross-field validation metadata
	Metadata ValidationMetadata `json:"-"`
}

// UserProfileUpdateRequestV2 represents enhanced user profile update request
type UserProfileUpdateRequestV2 struct {
	// Basic profile information
	FirstName   string `json:"first_name,omitempty" binding:"omitempty,max=50" validate:"name_format,no_special_chars"`
	LastName    string `json:"last_name,omitempty" binding:"omitempty,max=50" validate:"name_format,no_special_chars"`
	Email       string `json:"email,omitempty" binding:"omitempty,email,max=255" validate:"email_format,email_available"`
	Phone       string `json:"phone,omitempty" binding:"omitempty,min=10,max=15" validate:"phone_format,phone_available"`
	
	// Extended profile
	DateOfBirth string `json:"date_of_birth,omitempty" validate:"date_format,age_verification"`
	Country     string `json:"country,omitempty" validate:"country_code_valid"`
	Timezone    string `json:"timezone,omitempty" validate:"timezone_valid"`
	Language    string `json:"language,omitempty" validate:"language_code_valid"`
	
	// Privacy settings
	ProfileVisibility string `json:"profile_visibility,omitempty" validate:"visibility_level_valid"`
	AllowMarketing    *bool  `json:"allow_marketing,omitempty"`
	AllowNotifications *bool `json:"allow_notifications,omitempty"`
	
	// Security context
	CurrentPassword   string `json:"current_password,omitempty" validate:"password_required_for_sensitive"`
	TwoFactorCode     string `json:"two_factor_code,omitempty" validate:"2fa_code_valid_if_required"`
	
	// Cross-field validation metadata
	Metadata ValidationMetadata `json:"-"`
}

// SecurityContextFields represents security-related fields for validation
type SecurityContextFields struct {
	IPAddress         string            `json:"ip_address,omitempty"`
	UserAgent         string            `json:"user_agent,omitempty"`
	DeviceFingerprint string            `json:"device_fingerprint,omitempty"`
	GeoLocation       *GeoLocation      `json:"geo_location,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	Timestamp         time.Time         `json:"timestamp"`
}

// GeoLocation represents geographic information for security validation
type GeoLocation struct {
	Country     string  `json:"country,omitempty"`
	Region      string  `json:"region,omitempty"`
	City        string  `json:"city,omitempty"`
	Latitude    float64 `json:"latitude,omitempty"`
	Longitude   float64 `json:"longitude,omitempty"`
	Accuracy    int     `json:"accuracy,omitempty"`
	IsVPN       bool    `json:"is_vpn,omitempty"`
	IsProxy     bool    `json:"is_proxy,omitempty"`
	IsTor       bool    `json:"is_tor,omitempty"`
}

// Validation helper methods

// IsValid performs comprehensive validation on RegisterRequestV2
func (r *RegisterRequestV2) IsValid() error {
	// Perform cross-field validation
	if r.Password != "" && r.Email != "" {
		// Check if password contains email
		if containsSubstring(r.Password, r.Email) {
			return &domain.ValidationError{
				Code:    "PASSWORD_CONTAINS_EMAIL",
				Field:   "password",
				Message: "Password cannot contain email address",
			}
		}
	}
	
	// Validate terms acceptance
	if !r.AcceptTerms || !r.AcceptPrivacy {
		return &domain.ValidationError{
			Code:    "TERMS_NOT_ACCEPTED",
			Field:   "accept_terms",
			Message: "Terms and privacy policy must be accepted",
		}
	}
	
	return nil
}

// IsValid performs comprehensive validation on LoginRequestV2
func (l *LoginRequestV2) IsValid() error {
	// Check for empty credentials
	if l.Email == "" || l.Password == "" {
		return &domain.ValidationError{
			Code:    "MISSING_CREDENTIALS",
			Message: "Email and password are required",
		}
	}
	
	return nil
}

// IsValid performs comprehensive validation on OTPVerifyRequestV2
func (o *OTPVerifyRequestV2) IsValid() error {
	// Validate OTP code format
	if len(o.Code) != 6 {
		return &domain.ValidationError{
			Code:    "INVALID_OTP_LENGTH",
			Field:   "code",
			Message: "OTP code must be exactly 6 digits",
		}
	}
	
	// Validate phone and user ID consistency
	if o.UserID == 0 {
		return &domain.ValidationError{
			Code:    "MISSING_USER_ID",
			Field:   "user_id",
			Message: "User ID is required for OTP verification",
		}
	}
	
	return nil
}

// ToValidationContext converts request to validation context
func (r *RegisterRequestV2) ToValidationContext() *domain.ValidationContext {
	return &domain.ValidationContext{
		RequestID: r.Metadata.RequestID,
		IPAddress: r.Metadata.ClientIP,
		UserAgent: r.Metadata.UserAgent,
		Timestamp: r.Metadata.Timestamp,
		Headers:   convertToStringMap(r.Metadata.SecurityContext),
	}
}

// ToValidationContext converts request to validation context
func (l *LoginRequestV2) ToValidationContext() *domain.ValidationContext {
	return &domain.ValidationContext{
		RequestID: l.Metadata.RequestID,
		IPAddress: l.Metadata.ClientIP,
		UserAgent: l.Metadata.UserAgent,
		Timestamp: l.Metadata.Timestamp,
		Headers:   convertToStringMap(l.Metadata.SecurityContext),
	}
}

// ToValidationContext converts request to validation context
func (o *OTPVerifyRequestV2) ToValidationContext() *domain.ValidationContext {
	return &domain.ValidationContext{
		RequestID: o.Metadata.RequestID,
		IPAddress: o.Metadata.ClientIP,
		UserAgent: o.Metadata.UserAgent,
		Timestamp: o.Metadata.Timestamp,
		Headers:   convertToStringMap(o.Metadata.SecurityContext),
	}
}

// Sanitize removes or masks sensitive information for logging
func (r *RegisterRequestV2) Sanitize() *RegisterRequestV2 {
	sanitized := *r
	sanitized.Password = "***REDACTED***"
	return &sanitized
}

// Sanitize removes or masks sensitive information for logging
func (l *LoginRequestV2) Sanitize() *LoginRequestV2 {
	sanitized := *l
	sanitized.Password = "***REDACTED***"
	return &sanitized
}

// Sanitize removes or masks sensitive information for logging
func (o *OTPVerifyRequestV2) Sanitize() *OTPVerifyRequestV2 {
	sanitized := *o
	sanitized.Code = "***REDACTED***"
	return &sanitized
}

// MarshalJSON provides custom JSON marshaling that excludes sensitive fields
func (r *RegisterRequestV2) MarshalJSON() ([]byte, error) {
	type Alias RegisterRequestV2
	sanitized := r.Sanitize()
	return json.Marshal((*Alias)(sanitized))
}

// MarshalJSON provides custom JSON marshaling that excludes sensitive fields
func (l *LoginRequestV2) MarshalJSON() ([]byte, error) {
	type Alias LoginRequestV2
	sanitized := l.Sanitize()
	return json.Marshal((*Alias)(sanitized))
}

// MarshalJSON provides custom JSON marshaling that excludes sensitive fields
func (o *OTPVerifyRequestV2) MarshalJSON() ([]byte, error) {
	type Alias OTPVerifyRequestV2
	sanitized := o.Sanitize()
	return json.Marshal((*Alias)(sanitized))
}

// Utility functions

func containsSubstring(str, substr string) bool {
	return len(substr) > 0 && len(str) >= len(substr) && 
		   (str == substr || 
		    str[:len(substr)] == substr || 
		    str[len(str)-len(substr):] == substr ||
		    contains(str, substr))
}

func contains(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func convertToStringMap(input map[string]string) map[string]string {
	if input == nil {
		return make(map[string]string)
	}
	result := make(map[string]string, len(input))
	for k, v := range input {
		result[k] = v
	}
	return result
}

// Validation tag definitions for reference
/*
Custom validation tags used in this file:

Security Validation:
- no_xss: Prevent XSS attacks
- no_sql_injection: Prevent SQL injection attacks
- no_script_injection: Prevent script injection attacks

Business Validation:
- business_email: Validate business email format
- no_disposable_email: Block disposable email providers
- domain_whitelist: Check against allowed domains
- phone_format: Validate phone number format
- phone_region_valid: Validate phone number region
- no_voip: Block VoIP phone numbers
- password_complexity: Check password complexity requirements
- no_common_passwords: Block common/weak passwords
- no_personal_info: Ensure password doesn't contain personal info

Authentication Validation:
- user_exists: Verify user exists in database
- user_active: Verify user account is active
- user_owns_phone: Verify phone belongs to user
- phone_verified: Check if phone is verified
- account_active: Verify account is not suspended

OTP Validation:
- otp_format: Validate OTP code format
- otp_not_expired: Check OTP expiration
- otp_attempts_check: Validate OTP attempt count
- request_id_valid: Validate OTP request ID
- request_not_expired: Check OTP request expiration

Security Context:
- device_fingerprint_format: Validate device fingerprint
- device_tracking: Track device consistency
- device_consistency: Check device fingerprint consistency
- captcha_valid_if_required: Validate CAPTCHA when required
- captcha_valid_if_suspicious: Validate CAPTCHA for suspicious activity

Cross-field Validation:
- passwords_match: Ensure password confirmation matches
- password_different: Ensure new password is different
- password_not_reused: Check against password history
- matches_phone: Ensure phone matches user record
- must_be_true: Boolean field must be true
*/