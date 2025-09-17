package domain

import "context"

// UserRepository defines user data access operations
type UserRepository interface {
	Create(ctx context.Context, user *User) error
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByPhone(ctx context.Context, phone string) (*User, error)
	FindByID(ctx context.Context, id uint) (*User, error)
	Update(ctx context.Context, user *User) error
	ActivatePhone(ctx context.Context, userID uint) error
}

// SessionRepository defines session data access operations
type SessionRepository interface {
	Create(ctx context.Context, session *Session) error
	FindByID(ctx context.Context, sessionID string) (*Session, error)
	Delete(ctx context.Context, sessionID string) error
	DeleteExpired(ctx context.Context) error
}

// AuthService defines authentication business logic
type AuthService interface {
	Register(ctx context.Context, email, phone, password, role string) (*User, error)
	Login(ctx context.Context, email, password string) (*AuthResult, error)
	RefreshToken(ctx context.Context, refreshToken string) (*AuthResult, error)
	Logout(ctx context.Context, sessionID string) error
	GetUserProfile(ctx context.Context, userID uint) (*User, error)
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