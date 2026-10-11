package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

type roleTestEnv struct {
	svc      domain.AuthService
	userRepo *mocks.MockUserRepository
	otpSvc   *mocks.MockOTPService
	audit    *mocks.MockComprehensiveAuditService
	created  []*domain.User
	otpCalls int
}

func newRoleTestEnv(t *testing.T) *roleTestEnv {
	t.Helper()
	env := &roleTestEnv{
		userRepo: mocks.NewMockUserRepository(),
		otpSvc:   mocks.NewMockOTPService(),
		audit:    mocks.NewMockComprehensiveAuditService(),
	}
	passwordSvc := mocks.NewMockPasswordService()
	passwordSvc.HashFunc = func(p string) (string, error) { return "hashed_" + p, nil }
	env.userRepo.CreateFunc = func(ctx context.Context, u *domain.User) error {
		u.ID = 42
		env.created = append(env.created, u)
		return nil
	}
	env.otpSvc.GenerateFunc = func(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) {
		env.otpCalls++
		return &domain.OTPRequest{Phone: phone, UserID: userID}, nil
	}
	env.svc = NewAuthService(env.userRepo, mocks.NewMockSessionRepository(), passwordSvc, mocks.NewMockTokenService(),
		env.otpSvc, mocks.NewMockPolicyService(), nil, mocks.NewMockRequestValidationService(), env.audit,
		mocks.NewMockIdentifierResolutionService(), mocks.NewMockEmailAuthenticationStrategy(), mocks.NewMockPhoneAuthenticationStrategy())
	return env
}

func TestRegister_PublicRoles(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", domain.RoleUser},
		{domain.RoleUser, domain.RoleUser},
		{domain.RoleClient, domain.RoleClient},
		{domain.RoleContact, domain.RoleContact},
	} {
		env := newRoleTestEnv(t)
		user, err := env.svc.Register(context.Background(), "a@example.com", "+5511999990000", "Passw0rd!", tc.in)
		if err != nil {
			t.Fatalf("role %q: unexpected error %v", tc.in, err)
		}
		if user.Role != tc.want || env.created[0].Role != tc.want {
			t.Errorf("role %q: got %q, want %q", tc.in, user.Role, tc.want)
		}
	}
}

func TestRegister_PrivilegedOrUnknownRolesRejected(t *testing.T) {
	for _, role := range []string{domain.RoleAdmin, domain.RoleRoot, domain.RoleAttendant, "moderator", "whatever"} {
		env := newRoleTestEnv(t)
		user, err := env.svc.Register(context.Background(), "a@example.com", "+5511999990000", "Passw0rd!", role)
		if !errors.Is(err, domain.ErrRoleNotAllowedForRegistration) {
			t.Errorf("role %q: expected ErrRoleNotAllowedForRegistration, got %v", role, err)
		}
		if user != nil || len(env.created) != 0 || env.otpCalls != 0 {
			t.Errorf("role %q: nothing must be created or sent", role)
		}
	}
}

func TestCreateUserByAdmin_Matrix(t *testing.T) {
	tests := []struct {
		creator string
		target  string
		allowed bool
	}{
		{domain.RoleRoot, domain.RoleAdmin, true},
		{domain.RoleRoot, domain.RoleAttendant, true},
		{domain.RoleRoot, domain.RoleClient, true},
		{domain.RoleRoot, domain.RoleContact, true},
		{domain.RoleRoot, domain.RoleUser, true},
		{domain.RoleRoot, domain.RoleRoot, false},
		{domain.RoleAdmin, domain.RoleAdmin, false},
		{domain.RoleAdmin, domain.RoleRoot, false},
		{domain.RoleAdmin, domain.RoleAttendant, true},
		{domain.RoleAdmin, domain.RoleClient, true},
		{domain.RoleAttendant, domain.RoleUser, false},
		{domain.RoleAttendant, domain.RoleAttendant, false},
		{domain.RoleClient, domain.RoleUser, false},
		{domain.RoleContact, domain.RoleClient, false},
		{domain.RoleUser, domain.RoleUser, false},
		{domain.RoleAdmin, "moderator", false},
	}
	for _, tc := range tests {
		t.Run(tc.creator+"_to_"+tc.target, func(t *testing.T) {
			env := newRoleTestEnv(t)
			creator := &domain.User{ID: 7, Role: tc.creator}
			user, err := env.svc.CreateUserByAdmin(context.Background(), creator, "n@example.com", "+5511988887777", "Passw0rd!", tc.target)
			if tc.allowed {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if user.Role != tc.target || len(env.created) != 1 {
					t.Errorf("user not created with role %q", tc.target)
				}
				return
			}
			if !errors.Is(err, domain.ErrRoleCreationNotAllowed) {
				t.Fatalf("expected ErrRoleCreationNotAllowed, got %v", err)
			}
			if user != nil || len(env.created) != 0 || env.otpCalls != 0 {
				t.Error("nothing must be created or sent when denied")
			}
		})
	}
}

func TestCreateUserByAdmin_NilCreatorDenied(t *testing.T) {
	env := newRoleTestEnv(t)
	if _, err := env.svc.CreateUserByAdmin(context.Background(), nil, "n@example.com", "+5511988887777", "Passw0rd!", domain.RoleUser); !errors.Is(err, domain.ErrRoleCreationNotAllowed) {
		t.Fatalf("expected ErrRoleCreationNotAllowed, got %v", err)
	}
}

func TestCreateUserByAdmin_SharedLifecycleAndCreatorAudit(t *testing.T) {
	env := newRoleTestEnv(t)
	creator := &domain.User{ID: 7, Role: domain.RoleRoot}
	user, err := env.svc.CreateUserByAdmin(context.Background(), creator, "n@example.com", "+5511988887777", "Passw0rd!", domain.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}
	if !user.IsActive || user.PhoneVerified {
		t.Errorf("same lifecycle as public registration expected (active=%v phoneVerified=%v)", user.IsActive, user.PhoneVerified)
	}
	if user.PasswordHash != "hashed_Passw0rd!" {
		t.Errorf("password must be hashed, got %q", user.PasswordHash)
	}
	if env.otpCalls != 1 {
		t.Errorf("expected exactly one OTP dispatch, got %d", env.otpCalls)
	}
	var sawRegistration, sawCreator bool
	for _, ev := range env.audit.LoggedEvents {
		switch ev.EventType {
		case "user_registration_success":
			sawRegistration = ev.UserID == 42
		case "user_created_by_admin":
			sawCreator = ev.Metadata["created_by_user_id"] == uint(7) &&
				ev.Metadata["created_by_role"] == domain.RoleRoot &&
				ev.Metadata["created_user_id"] == uint(42)
		}
	}
	if !sawRegistration {
		t.Error("registration audit event missing")
	}
	if !sawCreator {
		t.Errorf("creator not recorded in audit metadata: %+v", env.audit.LoggedEvents)
	}
}

func TestRegister_PublicHasNoCreatorEvent(t *testing.T) {
	env := newRoleTestEnv(t)
	if _, err := env.svc.Register(context.Background(), "a@example.com", "+5511999990000", "Passw0rd!", ""); err != nil {
		t.Fatal(err)
	}
	if env.otpCalls != 1 {
		t.Errorf("OTP must still be sent, got %d calls", env.otpCalls)
	}
	registered := false
	for _, ev := range env.audit.LoggedEvents {
		if ev.EventType == "user_created_by_admin" {
			t.Error("public registration must not log a creator event")
		}
		if ev.EventType == "user_registration_success" {
			registered = true
		}
	}
	if !registered {
		t.Error("registration audit event missing")
	}
}

func TestCreateUserByAdmin_DuplicateAndThrottle(t *testing.T) {
	env := newRoleTestEnv(t)
	env.userRepo.CreateFunc = func(ctx context.Context, u *domain.User) error {
		return errors.New("ERROR: duplicate key value violates unique constraint")
	}
	creator := &domain.User{ID: 7, Role: domain.RoleAdmin}
	if _, err := env.svc.CreateUserByAdmin(context.Background(), creator, "n@example.com", "+5511988887777", "Passw0rd!", domain.RoleUser); !errors.Is(err, domain.ErrUserAlreadyExists) {
		t.Fatalf("expected ErrUserAlreadyExists, got %v", err)
	}

	env = newRoleTestEnv(t)
	env.otpSvc.GenerateFunc = func(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) {
		return nil, domain.ErrOTPResendThrottled
	}
	if _, err := env.svc.CreateUserByAdmin(context.Background(), creator, "n@example.com", "+5511988887777", "Passw0rd!", domain.RoleUser); !errors.Is(err, domain.ErrOTPResendThrottled) {
		t.Fatalf("expected ErrOTPResendThrottled, got %v", err)
	}
}

// Real validation service (miniredis-backed per-IP registration limit of 2 per window).
func newRateLimitedAuthService(t *testing.T) (domain.AuthService, *int) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	validator := NewRequestValidationService(mocks.NewMockSecurityValidationService(), mocks.NewMockBusinessValidationService(),
		mocks.NewMockRateLimitValidationService(), rdb, RequestValidationConfig{})

	userRepo := mocks.NewMockUserRepository()
	created := 0
	userRepo.CreateFunc = func(ctx context.Context, u *domain.User) error { created++; u.ID = uint(created); return nil }
	passwordSvc := mocks.NewMockPasswordService()
	passwordSvc.HashFunc = func(p string) (string, error) { return "h", nil }
	svc := NewAuthService(userRepo, mocks.NewMockSessionRepository(), passwordSvc, mocks.NewMockTokenService(),
		mocks.NewMockOTPService(), mocks.NewMockPolicyService(), nil, validator, mocks.NewMockComprehensiveAuditService(),
		mocks.NewMockIdentifierResolutionService(), mocks.NewMockEmailAuthenticationStrategy(), mocks.NewMockPhoneAuthenticationStrategy())
	return svc, &created
}

func TestCreateUserByAdmin_NotSubjectToPublicRegistrationRateLimit(t *testing.T) {
	svc, created := newRateLimitedAuthService(t)
	ctx := context.WithValue(context.Background(), "client_ip", "10.0.0.9")
	creator := &domain.User{ID: 1, Role: domain.RoleAdmin}
	for i := 0; i < 6; i++ {
		if _, err := svc.CreateUserByAdmin(ctx, creator, fmt.Sprintf("u%d@example.com", i), fmt.Sprintf("+551190000000%d", i), "Passw0rd!", domain.RoleAttendant); err != nil {
			t.Fatalf("creation %d failed: %v", i, err)
		}
	}
	if *created != 6 {
		t.Fatalf("expected 6 users, got %d", *created)
	}
}

func TestRegister_PublicRateLimitReturnsTypedError(t *testing.T) {
	svc, created := newRateLimitedAuthService(t)
	ctx := context.WithValue(context.Background(), "client_ip", "10.0.0.9")
	for i := 0; i < 2; i++ {
		if _, err := svc.Register(ctx, fmt.Sprintf("p%d@example.com", i), fmt.Sprintf("+551190000001%d", i), "Passw0rd!", domain.RoleClient); err != nil {
			t.Fatalf("registration %d should be allowed: %v", i, err)
		}
	}
	_, err := svc.Register(ctx, "p3@example.com", "+5511900000013", "Passw0rd!", domain.RoleContact)
	if !errors.Is(err, domain.ErrRegistrationRateLimited) {
		t.Fatalf("expected ErrRegistrationRateLimited, got %v", err)
	}
	if *created != 2 {
		t.Errorf("rate-limited registration must not create a user, created=%d", *created)
	}
}

func newRealValidationAuthService(t *testing.T, validatorErr error) domain.AuthService {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	userRepo := mocks.NewMockUserRepository()
	business := NewBusinessValidationService(userRepo, BusinessValidationConfig{
		PasswordPolicy:  PasswordPolicy{MinLength: 8, MaxLength: 128, RequireUppercase: true, RequireLowercase: true, RequireNumbers: true, MaxRepeatingChars: 3},
		EmailValidation: EmailValidationConfig{MaxLength: 254},
	})
	security := mocks.NewMockSecurityValidationService()
	if validatorErr != nil {
		security.ScanForThreatsFunc = func(ctx context.Context, fields map[string]interface{}, c []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
			return nil, validatorErr
		}
	}
	validator := NewRequestValidationService(security, business, mocks.NewMockRateLimitValidationService(), rdb, RequestValidationConfig{})
	passwordSvc := mocks.NewMockPasswordService()
	passwordSvc.HashFunc = func(p string) (string, error) { return "h", nil }
	return NewAuthService(userRepo, mocks.NewMockSessionRepository(), passwordSvc, mocks.NewMockTokenService(),
		mocks.NewMockOTPService(), mocks.NewMockPolicyService(), nil, validator, mocks.NewMockComprehensiveAuditService(),
		mocks.NewMockIdentifierResolutionService(), mocks.NewMockEmailAuthenticationStrategy(), mocks.NewMockPhoneAuthenticationStrategy())
}

func TestCreateUserAccount_ValidationFailuresAreTyped(t *testing.T) {
	cases := []struct {
		name, email, phone, password string
		code, field                  string
	}{
		{"weak password", "ok@example.com", "+5511900000001", "weak", "PASSWORD_TOO_SHORT", "password"},
		{"invalid email", "not-an-email", "+5511900000001", "Passw0rd123", "EMAIL_FORMAT_INVALID", "email"},
		{"invalid phone", "ok@example.com", "abc", "Passw0rd123", "PHONE_FORMAT_INVALID", "phone"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newRealValidationAuthService(t, nil)
			creator := &domain.User{ID: 1, Role: domain.RoleAdmin}
			for label, call := range map[string]func() error{
				"public": func() error {
					_, err := svc.Register(context.Background(), tc.email, tc.phone, tc.password, domain.RoleUser)
					return err
				},
				"admin": func() error {
					_, err := svc.CreateUserByAdmin(context.Background(), creator, tc.email, tc.phone, tc.password, domain.RoleUser)
					return err
				},
			} {
				err := call()
				var verr *domain.RegistrationValidationError
				if !errors.Is(err, domain.ErrRegistrationValidationFailed) || !errors.As(err, &verr) {
					t.Fatalf("%s: expected typed validation error, got %v", label, err)
				}
				if verr.Code != tc.code || verr.Field != tc.field || verr.Message == "" {
					t.Errorf("%s: got code=%q field=%q msg=%q, want %s/%s", label, verr.Code, verr.Field, verr.Message, tc.code, tc.field)
				}
				if tc.password != "" && strings.Contains(verr.Message, tc.password) {
					t.Errorf("%s: message echoes the password", label)
				}
			}
		})
	}
}

func TestCreateUserAccount_ValidatorFailureIsNotAValidationError(t *testing.T) {
	svc := newRealValidationAuthService(t, errors.New("scanner down"))
	_, err := svc.Register(context.Background(), "ok@example.com", "+5511900000001", "Passw0rd123", domain.RoleUser)
	if err == nil || errors.Is(err, domain.ErrRegistrationValidationFailed) {
		t.Fatalf("expected a plain internal error, got %v", err)
	}
}
