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