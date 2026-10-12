package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

func businessWith(policy domain.PasswordPolicy) domain.BusinessValidationService {
	return NewBusinessValidationService(mocks.NewMockUserRepository(), BusinessValidationConfig{
		PasswordPolicy:  policy,
		EmailValidation: EmailValidationConfig{MaxLength: 254, Optional: true},
	})
}

func firstPasswordCode(t *testing.T, svc domain.BusinessValidationService, password string) string {
	t.Helper()
	res, err := svc.ValidateRegistrationRules(context.Background(), "", "+14155550100", password, domain.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Errors {
		if e.Field == "password" {
			return e.Code
		}
	}
	return ""
}

func TestBusinessValidation_UsesTheSharedPasswordPolicy(t *testing.T) {
	strict := businessWith(domain.NewPasswordPolicy(8, true))
	if got := firstPasswordCode(t, strict, "abcdefgh"); got != "PASSWORD_MISSING_UPPERCASE" {
		t.Errorf("strict: want PASSWORD_MISSING_UPPERCASE, got %q", got)
	}
	if got := firstPasswordCode(t, strict, "Abcdefg1"); got != "" {
		t.Errorf("strict: compliant password refused with %q", got)
	}
	relaxed := businessWith(domain.NewPasswordPolicy(6, false))
	if got := firstPasswordCode(t, relaxed, "abcdef"); got != "" {
		t.Errorf("relaxed: 6 lowercase chars must be accepted, got %q", got)
	}
	if got := firstPasswordCode(t, relaxed, "abcde"); got != "PASSWORD_TOO_SHORT" {
		t.Errorf("relaxed: 5 chars must fail with PASSWORD_TOO_SHORT, got %q", got)
	}
}

func authWithPolicy(policy *domain.PasswordPolicy) domain.AuthService {
	passwordSvc := mocks.NewMockPasswordService()
	var opts []AuthServiceOption
	if policy != nil {
		opts = append(opts, WithPasswordPolicy(*policy))
	}
	otp := mocks.NewMockOTPService()
	return NewAuthService(mocks.NewMockUserRepository(), mocks.NewMockSessionRepository(), passwordSvc, mocks.NewMockTokenService(),
		otp, mocks.NewMockPolicyService(), nil, nil, mocks.NewMockComprehensiveAuditService(),
		mocks.NewMockIdentifierResolutionService(), mocks.NewMockEmailAuthenticationStrategy(), mocks.NewMockPhoneAuthenticationStrategy(), opts...)
}

func TestAuthService_EnforcesPasswordPolicyOnRegisterAndAdminCreate(t *testing.T) {
	strict, relaxed := domain.NewPasswordPolicy(8, true), domain.NewPasswordPolicy(6, false)
	admin := &domain.User{ID: 1, Role: domain.RoleAdmin}
	cases := []struct {
		name     string
		policy   *domain.PasswordPolicy
		password string
		wantCode string
	}{
		{"strict refuses lowercase", &strict, "abcdefgh", "PASSWORD_MISSING_UPPERCASE"},
		{"strict refuses short", &strict, "Abc1", "PASSWORD_TOO_SHORT"},
		{"strict accepts compliant", &strict, "Abcdefg1", ""},
		{"relaxed accepts 6 lowercase", &relaxed, "abcdef", ""},
		{"relaxed refuses 5", &relaxed, "abcde", "PASSWORD_TOO_SHORT"},
		{"no policy wired: unchanged behaviour", nil, "a", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for label, call := range map[string]func(domain.AuthService) error{
				"register": func(s domain.AuthService) error {
					_, err := s.Register(context.Background(), "", "+14155550100", tc.password, domain.RoleUser)
					return err
				},
				"admin": func(s domain.AuthService) error {
					_, err := s.CreateUserByAdmin(context.Background(), admin, "", "+14155550100", tc.password, domain.RoleUser)
					return err
				},
			} {
				err := call(authWithPolicy(tc.policy))
				var verr *domain.RegistrationValidationError
				if tc.wantCode == "" {
					if errors.As(err, &verr) {
						t.Errorf("%s: unexpected validation error %s", label, verr.Code)
					}
					continue
				}
				if !errors.As(err, &verr) || verr.Code != tc.wantCode || verr.Field != "password" {
					t.Errorf("%s: want %s on field password, got %v", label, tc.wantCode, err)
				}
			}
		})
	}
}

func registrationValidator(t *testing.T, limit int) domain.RequestValidationService {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return NewRequestValidationService(mocks.NewMockSecurityValidationService(), businessWith(domain.NewPasswordPolicy(6, false)),
		mocks.NewMockRateLimitValidationService(), rdb, RequestValidationConfig{RegistrationRateLimit: limit})
}

func registrationsAllowed(t *testing.T, v domain.RequestValidationService, ip string, attempts int) int {
	t.Helper()
	allowed := 0
	for i := 0; i < attempts; i++ {
		res, err := v.ValidateRegistrationRequest(context.Background(), "", "+14155550100", "abcdef", domain.RoleUser,
			&domain.ValidationContext{IPAddress: ip, Endpoint: "/auth/register"})
		if err != nil {
			t.Fatal(err)
		}
		if res.Passed {
			allowed++
		}
	}
	return allowed
}

func TestRegistrationRateLimit_DefaultIsTwoPerWindow(t *testing.T) {
	if got := registrationsAllowed(t, registrationValidator(t, 0), "10.0.0.1", 6); got != 2 {
		t.Errorf("default must allow exactly 2, got %d", got)
	}
}

func TestRegistrationRateLimit_LowSetting(t *testing.T) {
	if got := registrationsAllowed(t, registrationValidator(t, 1), "10.0.0.1", 4); got != 1 {
		t.Errorf("limit 1 must allow exactly 1, got %d", got)
	}
}

func TestRegistrationRateLimit_HighSetting(t *testing.T) {
	v := registrationValidator(t, 50)
	if got := registrationsAllowed(t, v, "10.0.0.1", 60); got != 50 {
		t.Errorf("limit 50 must allow exactly 50, got %d", got)
	}
	// the limit is per client IP
	if got := registrationsAllowed(t, v, "10.0.0.2", 3); got != 3 {
		t.Errorf("another IP has its own budget, got %d", got)
	}
}

func TestRegistrationRateLimit_AdminPathIsExempt(t *testing.T) {
	v := registrationValidator(t, 1)
	for i := 0; i < 5; i++ {
		res, err := v.ValidateRegistrationRequest(context.Background(), "", "+14155550100", "abcdef", domain.RoleUser,
			&domain.ValidationContext{IPAddress: "10.0.0.9", SkipRegistrationRateLimit: true})
		if err != nil || !res.Passed {
			t.Fatalf("privileged creation must never be rate limited: %v %v", res, err)
		}
	}
}

func TestRegistrationRateLimit_WindowIsConfigurable(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	v := NewRequestValidationService(mocks.NewMockSecurityValidationService(), businessWith(domain.NewPasswordPolicy(6, false)),
		mocks.NewMockRateLimitValidationService(), rdb, RequestValidationConfig{RegistrationRateLimit: 1, RegistrationRateWindow: time.Second})

	// start just after a window boundary so the two quick calls share one window
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second + 50*time.Millisecond)))
	if got := registrationsAllowed(t, v, "10.0.0.1", 3); got != 1 {
		t.Fatalf("1 per 1s window: want 1 allowed inside the window, got %d", got)
	}
	time.Sleep(time.Second)
	if got := registrationsAllowed(t, v, "10.0.0.1", 1); got != 1 {
		t.Errorf("a new window must give a new budget, got %d", got)
	}
}
