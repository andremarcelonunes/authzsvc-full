package services

import (
	"context"
	"errors"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// TestAuthServiceImpl_AuthenticateUser_CB194 tests the CB-194 unified authentication functionality
func TestAuthServiceImpl_AuthenticateUser_CB194(t *testing.T) {
	tests := []struct {
		name           string
		request        *domain.AuthRequest
		setupMocks     func(*testAuthServiceMocks)
		expectedResult func(*testing.T, *domain.AuthResult)
		expectedError  string
	}{
		{
			name: "successful email authentication via legacy email field",
			request: &domain.AuthRequest{
				Email:    "user@example.com",
				Password: "validpassword123",
			},
			setupMocks: func(mocks *testAuthServiceMocks) {
				// Configure identifier resolver for email
				mocks.identifierResolver.ResolveIdentifierFunc = func(ctx context.Context, identifier string) (*domain.IdentifierResolution, error) {
					return &domain.IdentifierResolution{
						Type:              domain.IdentifierTypeEmail,
						OriginalValue:     identifier,
						NormalizedValue:   "user@example.com",
						IsValid:           true,
					}, nil
				}
				
				// Configure email auth strategy
				testUser := &domain.User{
					ID:            1,
					Email:         "user@example.com",
					Phone:         "+1234567890",
					Role:          "user",
					IsActive:      true,
					PhoneVerified: true,
				}
				mocks.emailAuthStrategy.ConfigureForSuccess(testUser)
				
				// Configure token service
				mocks.tokenSvc.GenerateAccessTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "access_token_123", nil
				}
				mocks.tokenSvc.GenerateRefreshTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "refresh_token_456", nil
				}
				
				// Configure session repository
				mocks.sessionRepo.CreateFunc = func(ctx context.Context, session *domain.Session) error {
					return nil
				}
			},
			expectedResult: func(t *testing.T, result *domain.AuthResult) {
				t.Helper()
				if result == nil {
					t.Fatal("expected non-nil result")
				}
				if result.User.ID != 1 {
					t.Errorf("expected user ID 1, got %d", result.User.ID)
				}
				if result.AccessToken != "access_token_123" {
					t.Errorf("expected access token 'access_token_123', got '%s'", result.AccessToken)
				}
				if result.AuthenticationContext == nil {
					t.Error("expected authentication context to be populated")
				} else {
					if result.AuthenticationContext.Method != domain.IdentifierTypeEmail {
						t.Errorf("expected authentication method email, got %s", result.AuthenticationContext.Method)
					}
				}
			},
		},
		{
			name: "successful phone authentication via unified identifier field",
			request: &domain.AuthRequest{
				Identifier: "+1234567890",
				Password:   "validpassword123",
			},
			setupMocks: func(mocks *testAuthServiceMocks) {
				// Configure identifier resolver for phone
				mocks.identifierResolver.ResolveIdentifierFunc = func(ctx context.Context, identifier string) (*domain.IdentifierResolution, error) {
					return &domain.IdentifierResolution{
						Type:              domain.IdentifierTypePhone,
						OriginalValue:     identifier,
						NormalizedValue:   "+1234567890",
						CountryCode:       "1",
						IsValid:           true,
					}, nil
				}
				
				// Configure phone auth strategy
				testUser := &domain.User{
					ID:            2,
					Email:         "user@example.com",
					Phone:         "+1234567890",
					Role:          "user",
					IsActive:      true,
					PhoneVerified: true,
				}
				mocks.phoneAuthStrategy.ConfigureForSuccess(testUser)
				
				// Configure token service
				mocks.tokenSvc.GenerateAccessTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "access_token_456", nil
				}
				mocks.tokenSvc.GenerateRefreshTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "refresh_token_789", nil
				}
				
				// Configure session repository
				mocks.sessionRepo.CreateFunc = func(ctx context.Context, session *domain.Session) error {
					return nil
				}
			},
			expectedResult: func(t *testing.T, result *domain.AuthResult) {
				t.Helper()
				if result == nil {
					t.Fatal("expected non-nil result")
				}
				if result.User.ID != 2 {
					t.Errorf("expected user ID 2, got %d", result.User.ID)
				}
				if result.AuthenticationContext == nil {
					t.Error("expected authentication context to be populated")
				} else {
					if result.AuthenticationContext.Method != domain.IdentifierTypePhone {
						t.Errorf("expected authentication method phone, got %s", result.AuthenticationContext.Method)
					}
					if result.AuthenticationContext.CountryCode == "" {
						t.Error("expected country code to be populated for phone authentication")
					}
				}
			},
		},
		{
			name: "successful email authentication via unified identifier field",
			request: &domain.AuthRequest{
				Identifier: "user@example.com",
				Password:   "validpassword123",
			},
			setupMocks: func(mocks *testAuthServiceMocks) {
				// Configure identifier resolver for email
				mocks.identifierResolver.ResolveIdentifierFunc = func(ctx context.Context, identifier string) (*domain.IdentifierResolution, error) {
					return &domain.IdentifierResolution{
						Type:              domain.IdentifierTypeEmail,
						OriginalValue:     identifier,
						NormalizedValue:   "user@example.com",
						IsValid:           true,
					}, nil
				}
				
				// Configure email auth strategy
				testUser := &domain.User{
					ID:            3,
					Email:         "user@example.com",
					Role:          "user",
					IsActive:      true,
					PhoneVerified: true,
				}
				mocks.emailAuthStrategy.ConfigureForSuccess(testUser)
				
				// Configure token service
				mocks.tokenSvc.GenerateAccessTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "access_token_789", nil
				}
				mocks.tokenSvc.GenerateRefreshTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "refresh_token_012", nil
				}
				
				// Configure session repository
				mocks.sessionRepo.CreateFunc = func(ctx context.Context, session *domain.Session) error {
					return nil
				}
			},
			expectedResult: func(t *testing.T, result *domain.AuthResult) {
				t.Helper()
				if result == nil {
					t.Fatal("expected non-nil result")
				}
				if result.User.ID != 3 {
					t.Errorf("expected user ID 3, got %d", result.User.ID)
				}
				if result.AuthenticationContext.Method != domain.IdentifierTypeEmail {
					t.Errorf("expected authentication method email, got %s", result.AuthenticationContext.Method)
				}
			},
		},
		{
			name: "backward compatibility: email field takes precedence over identifier",
			request: &domain.AuthRequest{
				Email:      "priority@example.com",
				Identifier: "secondary@example.com",
				Password:   "validpassword123",
			},
			setupMocks: func(mocks *testAuthServiceMocks) {
				// Configure email auth strategy to expect the email field, not identifier
				testUser := &domain.User{
					ID:            4,
					Email:         "priority@example.com",
					Role:          "user",
					IsActive:      true,
					PhoneVerified: true,
				}
				mocks.emailAuthStrategy.ConfigureForSuccess(testUser)
				
				// Configure token service
				mocks.tokenSvc.GenerateAccessTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "access_token_priority", nil
				}
				mocks.tokenSvc.GenerateRefreshTokenFunc = func(userID uint, role string, sessionID string) (string, error) {
					return "refresh_token_priority", nil
				}
				
				// Configure session repository
				mocks.sessionRepo.CreateFunc = func(ctx context.Context, session *domain.Session) error {
					return nil
				}
			},
			expectedResult: func(t *testing.T, result *domain.AuthResult) {
				t.Helper()
				if result == nil {
					t.Fatal("expected non-nil result")
				}
				if result.User.Email != "priority@example.com" {
					t.Errorf("expected email to be 'priority@example.com', got '%s'", result.User.Email)
				}
				// Should use email method even though identifier was also provided
				if result.AuthenticationContext.Method != domain.IdentifierTypeEmail {
					t.Errorf("expected authentication method email, got %s", result.AuthenticationContext.Method)
				}
			},
		},
		{
			name: "failure: no identifier provided",
			request: &domain.AuthRequest{
				Password: "validpassword123",
			},
			setupMocks: func(mocks *testAuthServiceMocks) {
				// No setup needed for this failure case
			},
			expectedError: "either email or identifier field must be provided",
		},
		{
			name: "failure: invalid identifier format",
			request: &domain.AuthRequest{
				Identifier: "invalid-identifier",
				Password:   "validpassword123",
			},
			setupMocks: func(mocks *testAuthServiceMocks) {
				// Configure identifier resolver to return invalid
				mocks.identifierResolver.ResolveIdentifierFunc = func(ctx context.Context, identifier string) (*domain.IdentifierResolution, error) {
					return &domain.IdentifierResolution{
						Type:              "",
						OriginalValue:     identifier,
						NormalizedValue:   "",
						IsValid:           false,
						ValidationMessage: "identifier must be a valid email or phone number",
					}, nil
				}
			},
			expectedError: "invalid identifier: identifier must be a valid email or phone number",
		},
		{
			name: "failure: authentication strategy fails",
			request: &domain.AuthRequest{
				Identifier: "user@example.com",
				Password:   "wrongpassword",
			},
			setupMocks: func(mocks *testAuthServiceMocks) {
				// Configure identifier resolver for email
				mocks.identifierResolver.ResolveIdentifierFunc = func(ctx context.Context, identifier string) (*domain.IdentifierResolution, error) {
					return &domain.IdentifierResolution{
						Type:              domain.IdentifierTypeEmail,
						OriginalValue:     identifier,
						NormalizedValue:   "user@example.com",
						IsValid:           true,
					}, nil
				}
				
				// Configure email auth strategy to fail
				mocks.emailAuthStrategy.ConfigureForFailure(domain.ErrInvalidCredentials)
			},
			expectedError: domain.ErrInvalidCredentials.Error(),
		},
		{
			name: "failure: phone not verified for phone authentication",
			request: &domain.AuthRequest{
				Identifier: "+1234567890",
				Password:   "validpassword123",
			},
			setupMocks: func(mocks *testAuthServiceMocks) {
				// Configure identifier resolver for phone
				mocks.identifierResolver.ResolveIdentifierFunc = func(ctx context.Context, identifier string) (*domain.IdentifierResolution, error) {
					return &domain.IdentifierResolution{
						Type:              domain.IdentifierTypePhone,
						OriginalValue:     identifier,
						NormalizedValue:   "+1234567890",
						IsValid:           true,
					}, nil
				}
				
				// Configure phone auth strategy to fail with phone not verified error
				mocks.phoneAuthStrategy.ConfigureForFailure(domain.ErrPhoneNotVerified)
			},
			expectedError: domain.ErrPhoneNotVerified.Error(),
		},
		{
			name: "failure: session creation fails",
			request: &domain.AuthRequest{
				Identifier: "user@example.com",
				Password:   "validpassword123",
			},
			setupMocks: func(mocks *testAuthServiceMocks) {
				// Configure identifier resolver for email
				mocks.identifierResolver.ResolveIdentifierFunc = func(ctx context.Context, identifier string) (*domain.IdentifierResolution, error) {
					return &domain.IdentifierResolution{
						Type:              domain.IdentifierTypeEmail,
						OriginalValue:     identifier,
						NormalizedValue:   "user@example.com",
						IsValid:           true,
					}, nil
				}
				
				// Configure email auth strategy for success
				testUser := &domain.User{
					ID:            5,
					Email:         "user@example.com",
					Role:          "user",
					IsActive:      true,
					PhoneVerified: true,
				}
				mocks.emailAuthStrategy.ConfigureForSuccess(testUser)
				
				// Configure session repository to fail
				mocks.sessionRepo.CreateFunc = func(ctx context.Context, session *domain.Session) error {
					return errors.New("session creation failed")
				}
			},
			expectedError: "failed to create session: session creation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mocks := createAuthServiceMocks(t)
			
			// Setup test-specific mock behaviors
			tt.setupMocks(mocks)
			
			// Create auth service
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

			// Execute test
			ctx := context.Background()
			result, err := authService.AuthenticateUser(ctx, tt.request)

			// Validate results
			if tt.expectedError != "" {
				if err == nil {
					t.Fatalf("expected error '%s', got nil", tt.expectedError)
				}
				if err.Error() != tt.expectedError {
					t.Errorf("expected error '%s', got '%s'", tt.expectedError, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.expectedResult != nil {
				tt.expectedResult(t, result)
			}
		})
	}
}

// testAuthServiceMocks contains all mocks needed for testing AuthService
type testAuthServiceMocks struct {
	userRepo           *mocks.MockUserRepository
	sessionRepo        *mocks.MockSessionRepository
	passwordSvc        *mocks.MockPasswordService
	tokenSvc           *mocks.MockTokenService
	otpSvc             *mocks.MockOTPService
	policySvc          *mocks.MockPolicyService
	redisClient        *redis.Client // Using real Redis client for simplicity in tests
	requestValidator   *mocks.MockRequestValidationService
	auditSvc           *mocks.MockComprehensiveAuditService
	identifierResolver *mocks.MockIdentifierResolutionService
	emailAuthStrategy  *mocks.MockAuthenticationStrategy
	phoneAuthStrategy  *mocks.MockAuthenticationStrategy
}

// createAuthServiceMocks creates and configures all necessary mocks for AuthService testing
func createAuthServiceMocks(t *testing.T) *testAuthServiceMocks {
	t.Helper()

	return &testAuthServiceMocks{
		userRepo:           mocks.NewMockUserRepository(),
		sessionRepo:        mocks.NewMockSessionRepository(),
		passwordSvc:        mocks.NewMockPasswordService(),
		tokenSvc:           mocks.NewMockTokenService(),
		otpSvc:             mocks.NewMockOTPService(),
		policySvc:          mocks.NewMockPolicyService(),
		redisClient:        nil, // Can be nil for most tests
		requestValidator:   mocks.NewMockRequestValidationService(),
		auditSvc:           mocks.NewMockComprehensiveAuditService(),
		identifierResolver: mocks.NewMockIdentifierResolutionService(),
		emailAuthStrategy:  mocks.NewMockEmailAuthenticationStrategy(),
		phoneAuthStrategy:  mocks.NewMockPhoneAuthenticationStrategy(),
	}
}