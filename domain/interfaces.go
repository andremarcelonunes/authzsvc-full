package domain

import (
	"context"
	"time"
)

// UserRepository defines user data access operations
type UserRepository interface {
	Create(ctx context.Context, user *User) error
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByPhone(ctx context.Context, phone string) (*User, error)
	FindByID(ctx context.Context, id uint) (*User, error)
	FindByIdentifier(ctx context.Context, identifier string, identifierType IdentifierType) (*User, error)
	Update(ctx context.Context, user *User) error
	ActivatePhone(ctx context.Context, userID uint) error
}

// SessionRepository defines session data access operations
type SessionRepository interface {
	Create(ctx context.Context, session *Session) error
	FindByID(ctx context.Context, sessionID string) (*Session, error)
	Delete(ctx context.Context, sessionID string) error
	DeleteExpired(ctx context.Context) error
	DeleteAllForUser(ctx context.Context, userID uint) error
	ExtendTTL(ctx context.Context, sessionID string, ttl time.Duration) error
	Update(ctx context.Context, session *Session) error
}

// AuthenticationStrategy defines strategy pattern for different authentication methods
type AuthenticationStrategy interface {
	// Authenticate performs authentication using this specific strategy
	Authenticate(ctx context.Context, identifier, password string) (*User, error)
	
	// SupportsIdentifier checks if this strategy can handle the given identifier
	SupportsIdentifier(ctx context.Context, identifier string) bool
	
	// GetIdentifierType returns the type of identifier this strategy handles
	GetIdentifierType() IdentifierType
	
	// ValidateCredentials performs strategy-specific credential validation
	ValidateCredentials(ctx context.Context, identifier, password string) error
}

// AuthService defines authentication business logic
type AuthService interface {
	Register(ctx context.Context, email, phone, password, role string) (*User, error)
	Login(ctx context.Context, email, password string) (*AuthResult, error)
	RefreshToken(ctx context.Context, refreshToken string) (*AuthResult, error)
	Logout(ctx context.Context, sessionID string) error
	GetUserProfile(ctx context.Context, userID uint) (*User, error)
	
	// AuthenticateUser provides unified authentication with support for email or phone identifier
	AuthenticateUser(ctx context.Context, request *AuthRequest) (*AuthResult, error)
}

// OTPService defines OTP operations
type OTPService interface {
	Generate(ctx context.Context, phone string, userID uint) (*OTPRequest, error)
	Verify(ctx context.Context, phone, code string, userID uint) (bool, error)
	CanResend(ctx context.Context, phone string) (bool, int64, error)
}

// PasswordService defines password operations
type PasswordService interface {
	Hash(password string) (string, error)
	Verify(hashedPassword, password string) bool
}

// TokenService defines token operations
type TokenService interface {
	GenerateAccessToken(userID uint, role string, sessionID string) (string, error)
	GenerateRefreshToken(userID uint, role string, sessionID string) (string, error)
	ValidateAccessToken(token string) (*TokenClaims, error)
	ValidateRefreshToken(token string) (*TokenClaims, error)
}

// NotificationService defines notification operations
type NotificationService interface {
	SendSMS(to, message string) error
	SendEmail(to, subject, body string) error
}

// PolicyService defines authorization policy operations
type PolicyService interface {
	AddPolicy(role, resource, action string) error
	RemovePolicy(role, resource, action string) error
	CheckPermission(role, resource, action string) (bool, error)
	GetPolicies() [][]string
}

// TokenClaims represents JWT token claims
type TokenClaims struct {
	UserID    uint   `json:"user_id"`
	Role      string `json:"role"`
	SessionID string `json:"session_id,omitempty"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// CasbinEnforcer interface defines the methods we need from Casbin enforcer
type CasbinEnforcer interface {
	AddPolicy(params ...interface{}) (bool, error)
	RemovePolicy(params ...interface{}) (bool, error)
	Enforce(rvals ...interface{}) (bool, error)
	GetPolicy() ([][]string, error)
	SavePolicy() error
}

// PhoneVerificationUseCase defines phone verification business logic
type PhoneVerificationUseCase interface {
	VerifyAndActivatePhone(ctx context.Context, userID uint, phone, code string) error
	SendOTP(ctx context.Context, userID uint, phone string) error
}

// PhoneVerificationPolicy defines phone verification requirements
type PhoneVerificationPolicy interface {
	RequiresPhoneVerification() bool
	AllowUnverifiedLogin() bool
	ShouldEnforceVerification(user *User) bool
}

// IdentifierType represents the type of authentication identifier
type IdentifierType string

const (
	IdentifierTypeEmail IdentifierType = "email"
	IdentifierTypePhone IdentifierType = "phone"
)

// IdentifierResolutionService handles smart detection and resolution of authentication identifiers
type IdentifierResolutionService interface {
	// ResolveIdentifier detects whether an identifier is email or phone and normalizes it
	ResolveIdentifier(ctx context.Context, identifier string) (*IdentifierResolution, error)
	
	// NormalizePhone converts phone number to E.164 format for consistent storage/lookup
	NormalizePhone(ctx context.Context, phone string, countryCode string) (string, error)
	
	// NormalizeEmail converts email to lowercase and trims whitespace
	NormalizeEmail(ctx context.Context, email string) (string, error)
	
	// ValidateIdentifier performs format validation on the identifier
	ValidateIdentifier(ctx context.Context, identifier string, identifierType IdentifierType) error
}

// IdentifierResolution contains the resolved identifier information
type IdentifierResolution struct {
	Type              IdentifierType `json:"type"`
	OriginalValue     string         `json:"original_value"`
	NormalizedValue   string         `json:"normalized_value"`
	CountryCode       string         `json:"country_code,omitempty"`
	IsValid           bool           `json:"is_valid"`
	ValidationMessage string         `json:"validation_message,omitempty"`
}

// RequestValidationService orchestrates comprehensive request validation
type RequestValidationService interface {
	// Main validation pipeline
	ValidateRequest(ctx context.Context, request interface{}, validationCtx *ValidationContext) (*ValidationResult, error)
	ValidateRegistrationRequest(ctx context.Context, email, phone, password, role string, validationCtx *ValidationContext) (*ValidationResult, error)
	ValidateLoginRequest(ctx context.Context, email, password string, validationCtx *ValidationContext) (*ValidationResult, error)
	ValidateOTPRequest(ctx context.Context, phone, code string, userID uint, validationCtx *ValidationContext) (*ValidationResult, error)
	
	// Field validation
	ValidateFields(ctx context.Context, fields map[string]interface{}, rules []ValidationRule) (*ValidationResult, error)
	ValidateField(ctx context.Context, fieldName string, value interface{}, constraints *FieldConstraint) (*FieldValidationResult, error)
	
	// Performance optimization
	ValidateBatch(ctx context.Context, requests []interface{}, validationCtx *ValidationContext) ([]ValidationResult, error)
}

// SecurityValidationService provides security-focused validation
type SecurityValidationService interface {
	// Threat detection
	ScanForThreats(ctx context.Context, input map[string]interface{}, rules []SecurityConstraint) (*SecurityValidationResult, error)
	DetectXSS(ctx context.Context, input string) (*SecurityValidationResult, error)
	DetectSQLInjection(ctx context.Context, input string) (*SecurityValidationResult, error)
	DetectScriptInjection(ctx context.Context, input string) (*SecurityValidationResult, error)
	
	// Content sanitization
	SanitizeInput(ctx context.Context, input map[string]interface{}, rules []SecurityConstraint) (map[string]interface{}, error)
	SanitizeHTML(ctx context.Context, html string) (string, error)
	
	// Violation handling
	RecordViolation(ctx context.Context, violation *SecurityViolation) error
	GetViolationHistory(ctx context.Context, userID uint, timeWindow time.Duration) ([]SecurityViolation, error)
}

// BusinessValidationService enforces domain-specific business rules
type BusinessValidationService interface {
	// Authentication business rules
	ValidateRegistrationRules(ctx context.Context, email, phone, password, role string) (*ValidationResult, error)
	ValidateLoginRules(ctx context.Context, email, password string, user *User) (*ValidationResult, error)
	ValidateOTPRules(ctx context.Context, phone, code string, userID uint) (*ValidationResult, error)
	ValidatePasswordComplexity(ctx context.Context, password string) (*ValidationResult, error)
	
	// General business rules
	ValidateBusinessRules(ctx context.Context, entity interface{}, rules []BusinessConstraint) (*ValidationResult, error)
	ValidateResourceLimits(ctx context.Context, userID uint, resource string, requestedAmount int) error
	CheckQuotaLimits(ctx context.Context, userID uint, operation string) (*QuotaStatus, error)
	
	// Domain constraints
	ValidateDomainConstraints(ctx context.Context, entity interface{}, domainName string) (*ValidationResult, error)
	ExecuteCustomValidation(ctx context.Context, entity interface{}, validatorName string, params map[string]interface{}) (*ValidationResult, error)
}

// RateLimitValidationService handles rate limiting and brute force protection
type RateLimitValidationService interface {
	// Rate limiting operations
	CheckRateLimit(ctx context.Context, key string, limit int, window time.Duration) (*RateLimitResult, error)
	IncrementCounter(ctx context.Context, key string, window time.Duration) error
	GetRateLimitStatus(ctx context.Context, key string) (*RateLimitStatus, error)
	
	// Advanced rate limiting algorithms
	CheckSlidingWindowLimit(ctx context.Context, key string, limit int, window time.Duration) (*RateLimitResult, error)
	CheckTokenBucketLimit(ctx context.Context, key string, capacity int, refillRate float64) (*RateLimitResult, error)
	
	// Brute force protection
	RecordFailedAttempt(ctx context.Context, identifier string, attemptType string) error
	IsBlocked(ctx context.Context, identifier string, attemptType string) (bool, time.Duration, error)
	ResetFailedAttempts(ctx context.Context, identifier string, attemptType string) error
	
	// Blocking operations
	BlockUser(ctx context.Context, userID uint, duration time.Duration, reason string) error
	UnblockUser(ctx context.Context, userID uint) error
	BlockIP(ctx context.Context, ipAddress string, duration time.Duration, reason string) error
	UnblockIP(ctx context.Context, ipAddress string) error
}

// PasswordChangeRepository defines password change request data access operations
type PasswordChangeRepository interface {
	Create(ctx context.Context, request *PasswordChangeRequest) error
	GetByID(ctx context.Context, id string) (*PasswordChangeRequest, error)
	GetByUserID(ctx context.Context, userID uint, limit int) ([]*PasswordChangeRequest, error)
	GetActiveByUserID(ctx context.Context, userID uint) (*PasswordChangeRequest, error)
	Update(ctx context.Context, request *PasswordChangeRequest) error
	UpdateStatus(ctx context.Context, id string, status string, reason string) error
	UpdateOTPAttempts(ctx context.Context, id string, attempts int) error
	DeleteExpired(ctx context.Context) error
	CountActiveByUserID(ctx context.Context, userID uint) (int64, error)
	CountRecentByUserID(ctx context.Context, userID uint, since time.Time) (int64, error)
}

// PasswordHistoryRepository defines password history data access operations
type PasswordHistoryRepository interface {
	Add(ctx context.Context, userID uint, passwordHash string, source string) error
	GetRecentPasswords(ctx context.Context, userID uint, count int) ([]string, error)
	CleanupOldHistory(ctx context.Context, userID uint, keepCount int) error
	CountUserHistory(ctx context.Context, userID uint) (int64, error)
}

// ForgotPasswordRepository defines forgot password request data access operations
type ForgotPasswordRepository interface {
	Create(ctx context.Context, request *ForgotPasswordRequest) error
	GetByID(ctx context.Context, id string) (*ForgotPasswordRequest, error)
	Update(ctx context.Context, request *ForgotPasswordRequest) error
	UpdateStatus(ctx context.Context, id string, status string, reason string) error
	UpdateOTPAttempts(ctx context.Context, id string, attempts int) error
	CountRecentByIP(ctx context.Context, ipAddress string, since time.Time) (int64, error)
	DeleteExpired(ctx context.Context) error
}