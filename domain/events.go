package domain

import (
	"context"
	"time"
)

// AuditEventType defines the type of audit event
type AuditEventType string

const (
	// Phone verification events
	PhoneActivationEvent        AuditEventType = "PHONE_ACTIVATED"
	PhoneActivationFailureEvent AuditEventType = "PHONE_ACTIVATION_FAILED"
	PhoneOTPRequestEvent        AuditEventType = "PHONE_OTP_REQUESTED"
	PhoneOTPVerifyEvent         AuditEventType = "PHONE_OTP_VERIFIED"
	PhoneOTPFailureEvent        AuditEventType = "PHONE_OTP_VERIFICATION_FAILED"
	
	// Authentication events
	UserLoginEvent              AuditEventType = "USER_LOGIN"
	UserLoginFailureEvent       AuditEventType = "USER_LOGIN_FAILED"
	UserRegistrationEvent       AuditEventType = "USER_REGISTERED"
	UserLogoutEvent             AuditEventType = "USER_LOGOUT"
	
	// Authorization events
	AccessGrantedEvent          AuditEventType = "ACCESS_GRANTED"
	AccessDeniedEvent           AuditEventType = "ACCESS_DENIED"
)

// AuditEvent represents a business event that occurred in the system
type AuditEvent struct {
	EventType   AuditEventType         `json:"event_type"`
	UserID      uint                   `json:"user_id"`
	Email       string                 `json:"email,omitempty"`
	Phone       string                 `json:"phone,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	ErrorMsg    string                 `json:"error_msg,omitempty"`
	Success     bool                   `json:"success"`
}

// AuditLogger defines operations for audit logging
type AuditLogger interface {
	// LogEvent logs a generic audit event
	LogEvent(ctx context.Context, event *AuditEvent) error
	
	// Phone verification specific events
	LogPhoneActivation(ctx context.Context, userID uint, phone, email string) error
	LogPhoneActivationFailure(ctx context.Context, userID uint, phone string, err error) error
	LogPhoneOTPRequest(ctx context.Context, userID uint, phone string) error
	LogPhoneOTPVerification(ctx context.Context, userID uint, phone string, success bool, errMsg string) error
	
	// Authentication specific events
	LogUserLogin(ctx context.Context, userID uint, email string, success bool, errMsg string) error
	LogUserRegistration(ctx context.Context, userID uint, email, phone string) error
	LogUserLogout(ctx context.Context, userID uint, sessionID string) error
	
	// Authorization specific events
	LogAccessAttempt(ctx context.Context, userID uint, resource, action string, granted bool, reason string) error
}

// ClientContext represents client information extracted from HTTP request
type ClientContext struct {
	IPAddress string
	UserAgent string
	SessionID string
}

// ExtractClientContext extracts client information from context
type ClientContextExtractor interface {
	ExtractClientContext(ctx context.Context) *ClientContext
}

// NewAuditEvent creates a new audit event with common fields populated
func NewAuditEvent(eventType AuditEventType, userID uint) *AuditEvent {
	return &AuditEvent{
		EventType: eventType,
		UserID:    userID,
		Timestamp: time.Now().UTC(),
		Metadata:  make(map[string]interface{}),
		Success:   true,
	}
}

// WithError sets error information on the audit event
func (e *AuditEvent) WithError(err error) *AuditEvent {
	e.Success = false
	if err != nil {
		e.ErrorMsg = err.Error()
	}
	return e
}

// WithEmail sets the email field
func (e *AuditEvent) WithEmail(email string) *AuditEvent {
	e.Email = email
	return e
}

// WithPhone sets the phone field
func (e *AuditEvent) WithPhone(phone string) *AuditEvent {
	e.Phone = phone
	return e
}

// WithClientContext sets client context information
func (e *AuditEvent) WithClientContext(ctx *ClientContext) *AuditEvent {
	if ctx != nil {
		e.IPAddress = ctx.IPAddress
		e.UserAgent = ctx.UserAgent
		e.SessionID = ctx.SessionID
	}
	return e
}

// WithMetadata adds metadata to the event
func (e *AuditEvent) WithMetadata(key string, value interface{}) *AuditEvent {
	e.Metadata[key] = value
	return e
}