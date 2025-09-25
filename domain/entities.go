package domain

import "time"

// User represents a user in the system
type User struct {
	ID            uint
	Email         string     `gorm:"uniqueIndex"`
	Phone         string     `gorm:"uniqueIndex"`
	PasswordHash  string     `gorm:"column:password"`
	Role          string
	IsActive      bool
	PhoneVerified bool
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     *time.Time `gorm:"index"` // Soft delete support for LGPD
}

// AuthRequest represents authentication credentials with unified identifier support
type AuthRequest struct {
	// Unified identifier field - can be email or phone number
	Identifier string `json:"identifier,omitempty"`
	
	// Legacy email field for backward compatibility - when provided, takes precedence over Identifier
	Email    string `json:"email,omitempty"`
	
	// Password for authentication
	Password string `json:"password" validate:"required,min=8"`
}

// AuthResult represents authentication outcome
type AuthResult struct {
	User                  *User
	AccessToken           string
	RefreshToken          string
	SessionID             string
	ExpiresIn             int64
	AuthenticationContext *AuthenticationContext `json:"authentication_context,omitempty"`
}

// AuthenticationContext contains metadata about the authentication process
type AuthenticationContext struct {
	// Method used for authentication (email or phone)
	Method              IdentifierType `json:"method"`
	
	// Original identifier provided by user
	OriginalIdentifier  string         `json:"original_identifier"`
	
	// Normalized identifier used for lookup
	NormalizedIdentifier string        `json:"normalized_identifier"`
	
	// Country code for phone numbers (E.164 format)
	CountryCode         string         `json:"country_code,omitempty"`
	
	// Timestamp when authentication occurred
	AuthenticatedAt     time.Time      `json:"authenticated_at"`
	
	// Client information for audit purposes
	UserAgent           string         `json:"user_agent,omitempty"`
	IPAddress           string         `json:"ip_address,omitempty"`
	
	// Performance metrics
	ResolutionDuration  time.Duration  `json:"resolution_duration"`
	LookupDuration      time.Duration  `json:"lookup_duration"`
	ValidationDuration  time.Duration  `json:"validation_duration"`
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