package domain

import "time"

// User represents a user in the system
type User struct {
	ID            uint
	Email         string
	Phone         string
	PasswordHash  string `gorm:"column:password"`
	Role          string
	IsActive      bool
	PhoneVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// AuthRequest represents authentication credentials
type AuthRequest struct {
	Email    string
	Password string
}

// AuthResult represents authentication outcome
type AuthResult struct {
	User         *User
	AccessToken  string
	RefreshToken string
	SessionID    string
	ExpiresIn    int64
}

// OTPRequest represents OTP verification data
type OTPRequest struct {
	Phone     string
	Code      string
	UserID    uint
	ExpiresAt time.Time
	Attempts  int
}

// Session represents a user session
type Session struct {
	ID        string
	UserID    uint
	ExpiresAt time.Time
	CreatedAt time.Time
}