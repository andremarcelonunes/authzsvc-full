package services

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/infrastructure/notifications"
	"github.com/you/authzsvc/internal/infrastructure/smsbudget"
	"github.com/you/authzsvc/internal/mocks"
)

type smsPathFixture struct {
	mr     *miniredis.Miniredis
	sms    *smsBox
	budget *smsbudget.RedisBudget
	otp    domain.OTPService
	svc    *PasswordChangeService
	user   *domain.User
}

func newSMSPathFixture(t *testing.T, limits domain.SMSLimits) *smsPathFixture {
	t.Helper()
	t.Chdir(t.TempDir())
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	f := &smsPathFixture{mr: mr, sms: &smsBox{}}
	f.budget = smsbudget.NewRedisBudget(rdb, limits, "secret")
	notifier := notifications.NewBudgetedNotifier(f.sms, f.budget)
	f.user = &domain.User{ID: 7, Email: "ana@example.com", Phone: "+14155550100", PasswordHash: "hashed_oldpass", IsActive: true, PhoneVerified: true, Role: "user"}

	userRepo := mocks.NewMockUserRepository()
	userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) { return f.user, nil }
	userRepo.FindByEmailFunc = func(ctx context.Context, e string) (*domain.User, error) {
		if e == f.user.Email {
			return f.user, nil
		}
		return nil, domain.ErrUserNotFound
	}
	userRepo.FindByPhoneFunc = func(ctx context.Context, p string) (*domain.User, error) {
		if p == f.user.Phone {
			return f.user, nil
		}
		return nil, domain.ErrUserNotFound
	}
	f.otp = NewOTPService(notifier, userRepo, rdb, OTPConfig{Length: 6, TTL: 5 * time.Minute, MaxAttempts: 5, ResendWindow: 60 * time.Second})
	f.svc = NewPasswordChangeService(mocks.NewMockPasswordChangeRepository(), mocks.NewMockPasswordHistoryRepository(), mocks.NewMockForgotPasswordRepository(),
		userRepo, mocks.NewMockPasswordService(), f.otp, mocks.NewMockSessionRepository(), nil, DefaultPasswordChangeConfig(),
		WithPasswordChangePolicy(domain.NewPasswordPolicy(6, false)), WithPasswordResetRequireEmail(false))
	return f
}

func generousLimits() domain.SMSLimits {
	return domain.SMSLimits{MaxPerPhonePerDay: 50, MaxPerPhonePer30Days: 50, MaxPerIPPerDay: 50, GlobalDailyCap: 500, GlobalMonthlyCap: 5000}
}

func (f *smsPathFixture) usage(t *testing.T) int64 {
	t.Helper()
	u, err := f.budget.Usage(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return u.Today
}

// Every path that can cause an SMS goes through the budget: each one is recorded as a sent SMS, with
// the text of its purpose.
func TestSMSPaths_EveryPathGoesThroughTheBudget(t *testing.T) {
	f := newSMSPathFixture(t, generousLimits())
	ctx := context.Background()
	steps := []struct {
		name string
		run  func() error
		text string
	}{
		{"verification at sign-up / resend", func() error { _, err := f.otp.Generate(ctx, "+5511999990000", 9); return err }, "verificacao"},
		{"password change", func() error {
			_, err := f.svc.InitiatePasswordChange(ctx, 7, "oldpass", "newpass1", "newpass1", "10.0.0.1", "ua")
			return err
		}, "troca de senha"},
		{"forgot password by e-mail and phone", func() error {
			svc := NewPasswordChangeService(mocks.NewMockPasswordChangeRepository(), mocks.NewMockPasswordHistoryRepository(), mocks.NewMockForgotPasswordRepository(),
				f.svc.userRepo, mocks.NewMockPasswordService(), f.otp, mocks.NewMockSessionRepository(), nil, DefaultPasswordChangeConfig())
			_, err := svc.InitiateForgotPassword(ctx, f.user.Email, f.user.Phone, "10.0.0.2", "ua")
			return err
		}, "redefinir a senha"},
		{"forgot password by phone", func() error {
			_, err := f.svc.InitiateForgotPasswordByPhone(ctx, "", f.user.Phone)
			return err
		}, "redefinir a senha"},
	}
	for i, step := range steps {
		f.mr.FastForward(10 * time.Minute) // clear resend window and per-phone interval between paths
		if err := step.run(); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		if got := f.usage(t); got != int64(i+1) {
			t.Fatalf("%s: the budget recorded %d sent SMS, want %d (the path bypassed it)", step.name, got, i+1)
		}
		f.sms.mu.Lock()
		msg := f.sms.sent[len(f.sms.sent)-1].msg
		f.sms.mu.Unlock()
		if !strings.Contains(msg, step.text) {
			t.Errorf("%s: unexpected text %q", step.name, msg)
		}
	}
}

// With the installation cap exhausted nothing is sent by any path.
func TestSMSPaths_ExhaustedBudgetStopsEveryPath(t *testing.T) {
	limits := generousLimits()
	limits.GlobalDailyCap = 0
	f := newSMSPathFixture(t, limits)
	ctx := context.Background()

	if _, err := f.otp.Generate(ctx, "+5511999990000", 9); !errors.Is(err, domain.ErrSMSUnavailable) {
		t.Errorf("verification: expected ErrSMSUnavailable, got %v", err)
	}
	if _, err := f.svc.InitiatePasswordChange(ctx, 7, "oldpass", "newpass1", "newpass1", "10.0.0.1", "ua"); !errors.Is(err, domain.ErrSMSUnavailable) {
		t.Errorf("password change: expected ErrSMSUnavailable, got %v", err)
	}
	if _, err := f.svc.InitiateForgotPasswordByPhone(ctx, "", f.user.Phone); err != nil {
		t.Errorf("phone reset must keep its generic answer, got %v", err)
	}
	if f.sms.count() != 0 {
		t.Errorf("%d SMS went out with the budget exhausted", f.sms.count())
	}
}

// The phone-only reset answers identically for an unknown phone, for a known one, and for a known one
// whose SMS was refused by a cap; and only the known, un-capped one sends.
func TestSMSPaths_PhoneResetKeepsItsGenericAnswer(t *testing.T) {
	limits := generousLimits()
	f := newSMSPathFixture(t, limits)
	ctx := context.Background()
	asJSON := func(v interface{}) string { raw, _ := json.Marshal(v); return string(raw) }

	unknown, err := f.svc.InitiateForgotPasswordByPhone(ctx, "", "+14155550999")
	if err != nil {
		t.Fatal(err)
	}
	if f.sms.count() != 0 {
		t.Fatalf("an unknown phone received %d SMS", f.sms.count())
	}
	known, err := f.svc.InitiateForgotPasswordByPhone(ctx, "", f.user.Phone)
	if err != nil || f.sms.count() != 1 {
		t.Fatalf("known phone: err=%v sms=%d", err, f.sms.count())
	}
	capped, err := f.svc.InitiateForgotPasswordByPhone(ctx, "", f.user.Phone) // valid code out: nothing sent
	if err != nil || f.sms.count() != 1 {
		t.Fatalf("repeat: err=%v sms=%d", err, f.sms.count())
	}
	if asJSON(unknown) != asJSON(known) || asJSON(known) != asJSON(capped) {
		t.Errorf("answers differ: %s | %s | %s", asJSON(unknown), asJSON(known), asJSON(capped))
	}
}

// A reset request while a valid code is out sends nothing, and the code that was sent still completes
// the e-mail+phone flow (the request row defers to the OTP service).
func TestSMSPaths_RepeatedForgotPasswordSendsNothingAndStillCompletes(t *testing.T) {
	f := newSMSPathFixture(t, generousLimits())
	ctx := context.Background()
	forgot := mocks.NewMockForgotPasswordRepository()
	rows := map[string]*domain.ForgotPasswordRequest{}
	forgot.CreateFunc = func(ctx context.Context, r *domain.ForgotPasswordRequest) error { rows[r.ID] = r; return nil }
	forgot.UpdateFunc = func(ctx context.Context, r *domain.ForgotPasswordRequest) error { rows[r.ID] = r; return nil }
	forgot.GetByIDFunc = func(ctx context.Context, id string) (*domain.ForgotPasswordRequest, error) { return rows[id], nil }
	svc := NewPasswordChangeService(mocks.NewMockPasswordChangeRepository(), mocks.NewMockPasswordHistoryRepository(), forgot,
		f.svc.userRepo, mocks.NewMockPasswordService(), f.otp, mocks.NewMockSessionRepository(), nil, DefaultPasswordChangeConfig(),
		WithPasswordChangePolicy(domain.NewPasswordPolicy(6, false)), WithPasswordChangeOTPDigester(NewOTPDigester("s")))

	if _, err := svc.InitiateForgotPassword(ctx, f.user.Email, f.user.Phone, "10.0.0.2", "ua"); err != nil {
		t.Fatal(err)
	}
	code := f.sms.lastCode(t)
	second, err := svc.InitiateForgotPassword(ctx, f.user.Email, f.user.Phone, "10.0.0.2", "ua")
	if err != nil || f.sms.count() != 1 {
		t.Fatalf("the repeat must answer normally and send nothing: err=%v sms=%d", err, f.sms.count())
	}
	if _, err := svc.CompleteForgotPassword(ctx, second.RequestID, code, second.Nonce, "newpass1", "newpass1"); err != nil {
		t.Errorf("the code already sent must complete the second request: %v", err)
	}
}

func TestSMSPaths_PerCallerAddressIsCarriedToTheBudget(t *testing.T) {
	limits := generousLimits()
	limits.MaxPerIPPerDay = 1
	f := newSMSPathFixture(t, limits)
	ctx := domain.WithClientIP(context.Background(), "203.0.113.9")
	if _, err := f.otp.Generate(ctx, "+5511999990000", 9); err != nil {
		t.Fatal(err)
	}
	_, err := f.otp.Generate(ctx, "+5511999990001", 10)
	var le *domain.SMSLimitError
	if !errors.As(err, &le) || le.Kind != domain.SMSLimitIPDay {
		t.Errorf("expected the per-address cap, got %v", err)
	}
}

// The mock provider (no credentials) sends nothing real and consumes no budget.
func TestSMSPaths_MockProviderDoesNotConsumeBudget(t *testing.T) {
	t.Chdir(t.TempDir())
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	budget := smsbudget.NewRedisBudget(rdb, generousLimits(), "secret")
	notifier := notifications.NewBudgetedNotifier(notifications.NewTwilioService("", "", ""), budget)
	otp := NewOTPService(notifier, mocks.NewMockUserRepository(), rdb, OTPConfig{Length: 6, TTL: time.Minute, MaxAttempts: 3, ResendWindow: time.Minute})
	if _, err := otp.Generate(context.Background(), "+5511999990000", 9); err != nil {
		t.Fatal(err)
	}
	for _, key := range mr.Keys() {
		if strings.HasPrefix(key, "sms:") {
			t.Errorf("the mock provider consumed budget: key %s", key)
		}
	}
}

// Structural guard: the only code that calls SendSMS is the OTP service, and the application wires it
// with the budgeted notifier, so a new path cannot reach the provider around the budget.
func TestSMSPaths_OnlyTheOTPServiceSendsSMS(t *testing.T) {
	root := filepath.Join("..", "..")
	allowed := map[string]bool{
		filepath.Join("internal", "services", "otp_service.go"):                                  true,
		filepath.Join("internal", "infrastructure", "notifications", "twilio_service.go"):        true,
		filepath.Join("internal", "infrastructure", "notifications", "budgeted_notifier.go"):     true,
		filepath.Join("domain", "interfaces.go"):                                                 true,
		filepath.Join("internal", "mocks", "mock_notification_service.go"):                       true,
	}
	_ = filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case "node_modules", "old_architecture", ".git", "tests":
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") || allowed[rel] {
			return nil
		}
		raw, _ := os.ReadFile(p)
		if strings.Contains(string(raw), ".SendSMS(") || strings.Contains(string(raw), ".SendSMSContext(") {
			t.Errorf("%s calls the SMS provider directly; SMS must go through OTPServiceImpl and the budget", rel)
		}
		return nil
	})
}

// Every code SMS is a single GSM-7 segment: only characters of the GSM 03.38 basic alphabet, at most
// 160, also with the longest allowed brand.
func TestOTPMessages_AreSingleGSM7Segments(t *testing.T) {
	brands := []string{"", domain.DefaultSMSBrand, "WWWWWWWWWWW" /* 11, the longest */, "ÅÆÉÑÜÖÄØÇÉ§"}
	for _, brand := range brands {
		if brand != "" {
			if err := domain.ValidateSMSBrand(brand); err != nil {
				t.Fatalf("test brand %q must be valid: %v", brand, err)
			}
		}
		for _, purpose := range []domain.OTPPurpose{domain.OTPPurposeVerification, domain.OTPPurposePasswordReset, domain.OTPPurposePasswordChange, ""} {
			msg := OTPMessage(brand, purpose, "123456", 5*time.Minute)
			t.Log(msg)
			if !domain.IsGSM7(msg) {
				t.Errorf("%q has a character outside the GSM-7 alphabet (forces UCS-2)", msg)
			}
			if utf8.RuneCountInString(msg) > 160 || !strings.Contains(msg, "123456") {
				t.Errorf("%q: too long or missing the code", msg)
			}
			want := brand
			if want == "" {
				want = domain.DefaultSMSBrand
			}
			if !strings.HasPrefix(msg, want+": ") {
				t.Errorf("%q must open with the brand %q", msg, want)
			}
		}
	}
	if !strings.Contains(OTPMessage("", domain.OTPPurposeVerification, "1", 30*time.Second), "1 min") {
		t.Error("a lifetime under a minute is shown as 1 min")
	}
	if strings.Contains(OTPMessage("", domain.OTPPurposeVerification, "1", time.Minute), "Eldery") {
		t.Error("the product is TocomVC")
	}
}
