package domain

import "errors"

// Authentication errors
var (
	ErrUserNotFound      = errors.New("user not found")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrUserInactive      = errors.New("user account is inactive")
	ErrPhoneNotVerified  = errors.New("phone number not verified")
)

// OTP errors
var (
	ErrOTPExpired     = errors.New("otp has expired")
	ErrOTPInvalid     = errors.New("invalid otp code")
	ErrOTPMaxAttempts = errors.New("maximum otp attempts exceeded")
	ErrOTPNotFound    = errors.New("otp not found")
	ErrOTPResendLimit = errors.New("otp resend limit exceeded")
)

// Token errors
var (
	ErrTokenInvalid   = errors.New("invalid token")
	ErrTokenExpired   = errors.New("token has expired")
	ErrTokenMalformed = errors.New("malformed token")
)

// Session errors
var (
	ErrSessionNotFound     = errors.New("session not found")
	ErrSessionExpired      = errors.New("session has expired")
	ErrSessionRevoked      = errors.New("session has been revoked")
	ErrConcurrentRefresh   = errors.New("concurrent token refresh detected")
)

// Authorization errors
var (
	ErrUnauthorized     = errors.New("unauthorized access")
	ErrInsufficientRole = errors.New("insufficient role permissions")
	ErrResourceNotFound = errors.New("resource not found")
)

// Validation errors
var (
	ErrValidationFailed     = errors.New("validation failed")
	ErrInvalidInput         = errors.New("invalid input provided")
	ErrFieldRequired        = errors.New("required field missing")
	ErrFieldInvalid         = errors.New("field value is invalid")
	ErrFieldTooLong         = errors.New("field value exceeds maximum length")
	ErrFieldTooShort        = errors.New("field value below minimum length")
	ErrFieldOutOfRange      = errors.New("field value out of allowed range")
	ErrFieldFormatInvalid   = errors.New("field format is invalid")
	ErrCrossFieldValidation = errors.New("cross-field validation failed")
	ErrBusinessRuleViolation = errors.New("business rule violation")
	ErrInvalidUUID          = errors.New("invalid UUID format")
	ErrInvalidUserID        = errors.New("invalid user ID format")
)

// Identifier resolution errors
var (
	ErrInvalidIdentifier     = errors.New("identifier format is invalid")
	ErrIdentifierTypeUnknown = errors.New("unable to determine identifier type")
	ErrPhoneFormatInvalid    = errors.New("phone number format is invalid")
	ErrEmailFormatInvalid    = errors.New("email format is invalid")
	ErrCountryCodeRequired   = errors.New("country code is required for phone normalization")
	ErrPhoneNormalizationFailed = errors.New("phone number normalization failed")
)

// Security validation errors
var (
	ErrSecurityViolation    = errors.New("security violation detected")
	ErrXSSDetected          = errors.New("cross-site scripting attempt detected")
	ErrSQLInjectionDetected = errors.New("sql injection attempt detected")
	ErrScriptInjectionDetected = errors.New("script injection attempt detected")
	ErrMaliciousPatternDetected = errors.New("malicious pattern detected")
	ErrEncodingViolation    = errors.New("encoding validation failed")
	ErrContentBlocked       = errors.New("content blocked by security policy")
	ErrThreatDetected       = errors.New("security threat detected")
	ErrViolationNotFound    = errors.New("security violation not found")
)

// Rate limiting errors
var (
	ErrRateLimitExceeded    = errors.New("rate limit exceeded")
	ErrTooManyRequests      = errors.New("too many requests")
	ErrUserBlocked          = errors.New("user is blocked")
	ErrIPBlocked            = errors.New("ip address is blocked")
	ErrBruteForceDetected   = errors.New("brute force attack detected")
	ErrQuotaExceeded        = errors.New("quota limit exceeded")
	ErrResourceLimitReached = errors.New("resource limit reached")
)

// Validation configuration errors
var (
	ErrValidationRuleNotFound = errors.New("validation rule not found")
	ErrInvalidValidationRule  = errors.New("invalid validation rule configuration")
	ErrRuleConflict          = errors.New("validation rule conflict detected")
	ErrCustomValidatorNotFound = errors.New("custom validator not found")
)

// Audit errors
var (
	ErrAuditEventNotFound    = errors.New("audit event not found")
	ErrAuditRepositoryError  = errors.New("audit repository error")
	ErrAuditEncryptionFailed = errors.New("audit data encryption failed")
	ErrAuditIntegrityFailed  = errors.New("audit integrity check failed")
	ErrAuditExportFailed     = errors.New("audit export failed")
)

// Password change errors
var (
	ErrPasswordChangeInProgress        = errors.New("password change already in progress")
	ErrPasswordChangeRateLimitExceeded = errors.New("password change rate limit exceeded")
	ErrPasswordChangeExpired           = errors.New("password change request has expired")
	ErrPasswordChangeInvalidNonce      = errors.New("invalid nonce for password change")
	ErrPasswordReused                  = errors.New("new password must be different from recent passwords")
	ErrPasswordChangeCancelled         = errors.New("password change request was cancelled")
	ErrPasswordChangeNotFound          = errors.New("password change request not found")
	ErrPasswordChangeUnauthorized      = errors.New("unauthorized to access password change request")
	ErrPasswordChangeInvalidOTP        = errors.New("invalid OTP for password change")
	ErrPasswordChangeOTPExpired        = errors.New("OTP for password change has expired")
	ErrPasswordChangeOTPMaxAttempts    = errors.New("maximum OTP attempts exceeded for password change")
	ErrPasswordChangeFailed            = errors.New("password change operation failed")
	ErrPasswordStrengthInsufficient    = errors.New("password does not meet strength requirements")
	ErrPasswordCommonlyUsed            = errors.New("password is commonly used and not allowed")
	ErrPasswordContainsUserInfo        = errors.New("password cannot contain user information")
	ErrCurrentPasswordIncorrect        = errors.New("current password is incorrect")
	ErrPasswordSameAsCurrent           = errors.New("new password cannot be the same as current password")
)

// Forgot password errors
var (
	ErrForgotPasswordRateLimitExceeded = errors.New("forgot password rate limit exceeded")
	ErrForgotPasswordExpired           = errors.New("forgot password request has expired")
	ErrForgotPasswordInvalidNonce      = errors.New("invalid nonce for forgot password")
	ErrForgotPasswordNotFound          = errors.New("forgot password request not found")
	ErrForgotPasswordInvalidOTP        = errors.New("invalid OTP for forgot password")
	ErrForgotPasswordOTPExpired        = errors.New("OTP for forgot password has expired")
	ErrForgotPasswordOTPMaxAttempts    = errors.New("maximum OTP attempts exceeded for forgot password")
	ErrForgotPasswordFailed            = errors.New("forgot password operation failed")
	ErrEmailPhoneMismatch              = errors.New("email and phone combination not found")
)

// LGPD/GDPR User Deletion errors
var (
	ErrDeletionRequestNotFound     = errors.New("deletion request not found")
	ErrDeletionBlocked             = errors.New("deletion blocked due to legal requirements")
	ErrDeletionInProgress          = errors.New("deletion already in progress")
	ErrDeletionCancelled           = errors.New("deletion request was cancelled")
	ErrDeletionFailed              = errors.New("deletion operation failed")
	ErrDataExportNotFound          = errors.New("data export not found")
	ErrDataExportExpired           = errors.New("data export has expired")
	ErrDataExportFailed            = errors.New("data export failed")
	ErrAnonymizationFailed         = errors.New("data anonymization failed")
	ErrRetentionPolicyViolation    = errors.New("operation violates data retention policy")
	ErrComplianceCheckFailed       = errors.New("compliance validation failed")
)

// Generic repository errors
var (
	ErrNotFound = errors.New("record not found")
)