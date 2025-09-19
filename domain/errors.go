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