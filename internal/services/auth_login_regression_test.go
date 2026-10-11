package services

import (
	"context"
	"errors"
	"testing"

	"github.com/you/authzsvc/domain"
)

// An identifier with an invalid format must carry domain.ErrInvalidIdentifier,
// which the login handler maps to HTTP 400 instead of 500.
func TestIdentifierResolutionService_ValidateIdentifier_InvalidFormatWrapsSentinel(t *testing.T) {
	resolver := NewIdentifierResolutionService()

	tests := []struct {
		name           string
		identifier     string
		identifierType domain.IdentifierType
	}{
		{name: "invalid email", identifier: "invalid-email", identifierType: domain.IdentifierTypeEmail},
		{name: "invalid phone", identifier: "not-a-phone", identifierType: domain.IdentifierTypePhone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := resolver.ValidateIdentifier(context.Background(), tt.identifier, tt.identifierType)
			if !errors.Is(err, domain.ErrInvalidIdentifier) {
				t.Errorf("expected error wrapping domain.ErrInvalidIdentifier, got '%v'", err)
			}
		})
	}

	if err := resolver.ValidateIdentifier(context.Background(), "user@example.com", domain.IdentifierTypeEmail); err != nil {
		t.Errorf("expected valid email to pass validation, got '%v'", err)
	}
}

// Login attempts are audited with the client IP: the audit table stores it in an
// inet column, so any other value makes the insert fail and the event is lost.
func TestAuthServiceImpl_AuthenticateUser_AuditsLoginWithClientIP(t *testing.T) {
	type auditCall struct {
		userID    uint
		ipAddress string
		success   bool
	}

	tests := []struct {
		name        string
		setupMocks  func(mocks *testAuthServiceMocks)
		expectError bool
		expected    auditCall
	}{
		{
			name: "successful login",
			setupMocks: func(mocks *testAuthServiceMocks) {
				mocks.emailAuthStrategy.ConfigureForSuccess(&domain.User{
					ID: 5, Email: "user@example.com", Role: "user", IsActive: true, PhoneVerified: true,
				})
			},
			expected: auditCall{userID: 5, ipAddress: "203.0.113.7", success: true},
		},
		{
			name: "failed login",
			setupMocks: func(mocks *testAuthServiceMocks) {
				mocks.emailAuthStrategy.AuthenticateFunc = func(ctx context.Context, identifier, password string) (*domain.User, error) {
					return nil, domain.ErrInvalidCredentials
				}
			},
			expectError: true,
			expected:    auditCall{userID: 0, ipAddress: "203.0.113.7", success: false},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mocks := createAuthServiceMocks(t)
			tt.setupMocks(mocks)

			var calls []auditCall
			mocks.auditSvc.LogLoginAttemptFunc = func(ctx context.Context, userID uint, email, ipAddress string, success bool, reason string) error {
				calls = append(calls, auditCall{userID: userID, ipAddress: ipAddress, success: success})
				return nil
			}

			authService := &AuthServiceImpl{
				userRepo:           mocks.userRepo,
				sessionRepo:        mocks.sessionRepo,
				passwordSvc:        mocks.passwordSvc,
				tokenSvc:           mocks.tokenSvc,
				otpSvc:             mocks.otpSvc,
				policySvc:          mocks.policySvc,
				redisClient:        mocks.redisClient,
				requestValidator:   mocks.requestValidator,
				auditSvc:           mocks.auditSvc,
				identifierResolver: mocks.identifierResolver,
				emailAuthStrategy:  mocks.emailAuthStrategy,
				phoneAuthStrategy:  mocks.phoneAuthStrategy,
			}

			ctx := context.WithValue(context.Background(), "client_ip", "203.0.113.7")
			_, err := authService.AuthenticateUser(ctx, &domain.AuthRequest{
				Email:    "user@example.com",
				Password: "validpassword123",
			})
			if tt.expectError != (err != nil) {
				t.Fatalf("expected error: %v, got '%v'", tt.expectError, err)
			}

			if len(calls) != 1 {
				t.Fatalf("expected exactly 1 audited login attempt, got %d", len(calls))
			}
			if calls[0] != tt.expected {
				t.Errorf("expected audit call %+v, got %+v", tt.expected, calls[0])
			}
		})
	}
}
