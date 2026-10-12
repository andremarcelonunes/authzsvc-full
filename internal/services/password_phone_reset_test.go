package services

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// smsBox is a fake SMS gateway: tests read the reset code from here.
type smsBox struct {
	mu   sync.Mutex
	sent []struct{ to, msg string }
}

func (b *smsBox) SendSMS(to, message string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sent = append(b.sent, struct{ to, msg string }{to, message})
	return nil
}
func (b *smsBox) SendEmail(to, subject, body string) error { return nil }
func (b *smsBox) count() int                               { b.mu.Lock(); defer b.mu.Unlock(); return len(b.sent) }
func (b *smsBox) lastCode(t *testing.T) string {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.sent) == 0 {
		t.Fatal("no SMS sent")
	}
	return regexp.MustCompile(`\d{6}`).FindString(b.sent[len(b.sent)-1].msg)
}

type resetFixture struct {
	svc     *PasswordChangeService
	mr      *miniredis.Miniredis
	sms     *smsBox
	user    *domain.User
	users   map[string]*domain.User
	deleted []uint
	updated int
	lookups int
}

const fixturePhone = "+14155550100"

func newResetFixture(t *testing.T, phoneOnly bool, extra ...PasswordChangeOption) *resetFixture {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })

	f := &resetFixture{mr: mr, sms: &smsBox{}, users: map[string]*domain.User{}}
	f.user = &domain.User{ID: 7, Phone: fixturePhone, PasswordHash: "hashed_oldpass", IsActive: true, Role: "user"}
	f.users[fixturePhone] = f.user

	userRepo := mocks.NewMockUserRepository()
	userRepo.FindByPhoneFunc = func(ctx context.Context, phone string) (*domain.User, error) {
		f.lookups++
		if u, ok := f.users[phone]; ok {
			return u, nil
		}
		return nil, domain.ErrUserNotFound
	}
	userRepo.UpdateFunc = func(ctx context.Context, u *domain.User) error { f.updated++; return nil }
	sessions := mocks.NewMockSessionRepository()
	sessions.DeleteAllForUserFunc = func(ctx context.Context, id uint) error { f.deleted = append(f.deleted, id); return nil }
	history := mocks.NewMockPasswordHistoryRepository()
	history.GetRecentPasswordsFunc = func(ctx context.Context, userID uint, count int) ([]string, error) { return nil, nil }

	otp := NewOTPService(f.sms, userRepo, rdb, OTPConfig{Length: 6, TTL: 5 * time.Minute, MaxAttempts: 5, ResendWindow: 60 * time.Second})
	opts := append([]PasswordChangeOption{
		WithPasswordChangePolicy(domain.NewPasswordPolicy(6, false)),
		WithPasswordResetRequireEmail(!phoneOnly),
	}, extra...)
	f.svc = NewPasswordChangeService(
		mocks.NewMockPasswordChangeRepository(), history, mocks.NewMockForgotPasswordRepository(),
		userRepo, mocks.NewMockPasswordService(), otp, sessions, nil, DefaultPasswordChangeConfig(), opts...)
	return f
}

func asJSON(t *testing.T, v interface{}) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestPhoneReset_InitiateAnswersIdenticallyForKnownAndUnknownPhone(t *testing.T) {
	f := newResetFixture(t, true)
	ctx := context.Background()
	known, err1 := f.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone)
	unknown, err2 := f.svc.InitiateForgotPasswordByPhone(ctx, "", "+14155550999")
	if err1 != nil || err2 != nil {
		t.Fatalf("errors: %v %v", err1, err2)
	}
	if asJSON(t, known) != asJSON(t, unknown) {
		t.Errorf("responses differ: %s vs %s", asJSON(t, known), asJSON(t, unknown))
	}
	if f.sms.count() != 1 {
		t.Errorf("only the known phone may receive an SMS, got %d", f.sms.count())
	}
}

func TestPhoneReset_InitiateTreatsInactiveAndEmailMismatchAsUnknown(t *testing.T) {
	f := newResetFixture(t, true)
	ctx := context.Background()
	f.user.Email = "ana@example.com"

	resp, err := f.svc.InitiateForgotPasswordByPhone(ctx, "other@example.com", fixturePhone)
	if err != nil || resp == nil || f.sms.count() != 0 {
		t.Fatalf("a sent e-mail must still match: resp=%v err=%v sms=%d", resp, err, f.sms.count())
	}
	if _, err := f.svc.InitiateForgotPasswordByPhone(ctx, " ANA@example.com ", fixturePhone); err != nil || f.sms.count() != 1 {
		t.Fatalf("a matching e-mail (case/space-insensitive) must work: %v sms=%d", err, f.sms.count())
	}
	f.mr.FastForward(2 * time.Minute)
	f.user.IsActive = false
	if _, err := f.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone); err != nil || f.sms.count() != 1 {
		t.Fatalf("an inactive account must not receive a code: %v sms=%d", err, f.sms.count())
	}
}

func TestPhoneReset_PhoneIsNormalisedLikeAtLogin(t *testing.T) {
	f := newResetFixture(t, true)
	// stored "+14155550100"; the person types it without the country code, as login accepts
	if _, err := f.svc.InitiateForgotPasswordByPhone(context.Background(), "", "415 555 0100"); err != nil {
		t.Fatal(err)
	}
	if f.sms.count() != 1 {
		t.Fatal("a differently formatted phone must resolve to the same account")
	}
	if _, err := f.svc.ResetPasswordByPhone(context.Background(), "(415) 555-0100", f.sms.lastCode(t), "newpass", "", ""); err != nil {
		t.Fatalf("reset with a differently formatted phone: %v", err)
	}
}

func TestPhoneReset_FullFlowResetsPasswordAndKillsSessions(t *testing.T) {
	f := newResetFixture(t, true)
	ctx := context.Background()
	if _, err := f.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone); err != nil {
		t.Fatal(err)
	}
	resp, err := f.svc.ResetPasswordByPhone(ctx, fixturePhone, f.sms.lastCode(t), "newpass", "", "")
	if err != nil || resp.Status != "completed" {
		t.Fatalf("reset failed: %v %v", resp, err)
	}
	if f.user.PasswordHash != "hashed_newpass" || f.updated != 1 {
		t.Errorf("password not updated (hash=%q updates=%d)", f.user.PasswordHash, f.updated)
	}
	if len(f.deleted) != 1 || f.deleted[0] != f.user.ID {
		t.Errorf("all sessions of the user must be deleted, got %v", f.deleted)
	}
}

func TestPhoneReset_CodeIsSingleUse(t *testing.T) {
	f := newResetFixture(t, true)
	ctx := context.Background()
	_, _ = f.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone)
	code := f.sms.lastCode(t)
	if _, err := f.svc.ResetPasswordByPhone(ctx, fixturePhone, code, "newpass", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.ResetPasswordByPhone(ctx, fixturePhone, code, "another", "", ""); !errors.Is(err, domain.ErrResetCodeInvalid) {
		t.Errorf("reuse must be refused with ErrResetCodeInvalid, got %v", err)
	}
	if f.user.PasswordHash != "hashed_newpass" {
		t.Error("a reused code must not change the password again")
	}
}

func TestPhoneReset_FiveWrongCodesBurnTheCode(t *testing.T) {
	f := newResetFixture(t, true)
	ctx := context.Background()
	_, _ = f.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone)
	code := f.sms.lastCode(t)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for i := 0; i < 5; i++ {
		if _, err := f.svc.ResetPasswordByPhone(ctx, fixturePhone, wrong, "newpass", "", ""); !errors.Is(err, domain.ErrResetCodeInvalid) {
			t.Fatalf("attempt %d: want ErrResetCodeInvalid, got %v", i+1, err)
		}
	}
	// the correct code no longer works
	if _, err := f.svc.ResetPasswordByPhone(ctx, fixturePhone, code, "newpass", "", ""); !errors.Is(err, domain.ErrResetCodeInvalid) {
		t.Errorf("the code must be burned after 5 wrong attempts, got %v", err)
	}
	if f.updated != 0 || len(f.deleted) != 0 {
		t.Error("nothing may change when the code is burned")
	}
}

func TestPhoneReset_FourWrongCodesDoNotBurnTheCode(t *testing.T) {
	f := newResetFixture(t, true)
	ctx := context.Background()
	_, _ = f.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone)
	code := f.sms.lastCode(t)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for i := 0; i < 4; i++ {
		_, _ = f.svc.ResetPasswordByPhone(ctx, fixturePhone, wrong, "newpass", "", "")
	}
	if _, err := f.svc.ResetPasswordByPhone(ctx, fixturePhone, code, "newpass", "", ""); err != nil {
		t.Errorf("the right code must still work after 4 wrong attempts: %v", err)
	}
}

func TestPhoneReset_CodeExpires(t *testing.T) {
	f := newResetFixture(t, true)
	ctx := context.Background()
	_, _ = f.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone)
	code := f.sms.lastCode(t)
	f.mr.FastForward(5*time.Minute + time.Second)
	if _, err := f.svc.ResetPasswordByPhone(ctx, fixturePhone, code, "newpass", "", ""); !errors.Is(err, domain.ErrResetCodeInvalid) {
		t.Errorf("an expired code must be refused, got %v", err)
	}
}

func TestPhoneReset_ResendCooldownIsSilent(t *testing.T) {
	f := newResetFixture(t, true)
	ctx := context.Background()
	first, _ := f.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone)
	second, err := f.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone)
	if err != nil {
		t.Fatalf("a throttled resend must look like any other answer, got %v", err)
	}
	if asJSON(t, first) != asJSON(t, second) {
		t.Error("the throttled answer must be identical")
	}
	if f.sms.count() != 1 {
		t.Errorf("no second SMS inside the cooldown, got %d", f.sms.count())
	}
	f.mr.FastForward(61 * time.Second)
	_, _ = f.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone)
	if f.sms.count() != 2 {
		t.Errorf("a new code is sent once the cooldown passed, got %d", f.sms.count())
	}
}

func TestPhoneReset_NewPasswordGoesThroughThePolicyWithoutBurningTheCode(t *testing.T) {
	f := newResetFixture(t, true)
	ctx := context.Background()
	_, _ = f.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone)
	code := f.sms.lastCode(t)
	if _, err := f.svc.ResetPasswordByPhone(ctx, fixturePhone, code, "abcde", "", ""); !errors.Is(err, domain.ErrPasswordStrengthInsufficient) {
		t.Fatalf("5 chars is below the minimum of 6: %v", err)
	}
	if _, err := f.svc.ResetPasswordByPhone(ctx, fixturePhone, code, "abcdef", "", ""); err != nil {
		t.Errorf("the code must survive a rejected password: %v", err)
	}
}

func TestPhoneReset_ComplexityOnAppliesToTheNewPassword(t *testing.T) {
	f := newResetFixture(t, true, WithPasswordChangePolicy(domain.NewPasswordPolicy(6, true)))
	ctx := context.Background()
	_, _ = f.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone)
	code := f.sms.lastCode(t)
	if _, err := f.svc.ResetPasswordByPhone(ctx, fixturePhone, code, "abcdefgh", "", ""); !errors.Is(err, domain.ErrPasswordStrengthInsufficient) {
		t.Errorf("complexity on must refuse a lowercase-only password: %v", err)
	}
	if _, err := f.svc.ResetPasswordByPhone(ctx, fixturePhone, code, "Abcdefg1", "", ""); err != nil {
		t.Errorf("a compliant password is accepted: %v", err)
	}
}

func TestPhoneReset_UnknownPhoneAndWrongCodeAreIndistinguishable(t *testing.T) {
	f := newResetFixture(t, true)
	ctx := context.Background()
	_, e1 := f.svc.ResetPasswordByPhone(ctx, "+14155550999", "123456", "newpass", "", "")
	_, _ = f.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone)
	_, e2 := f.svc.ResetPasswordByPhone(ctx, fixturePhone, "not-it", "newpass", "", "")
	if !errors.Is(e1, domain.ErrResetCodeInvalid) || e1 != e2 {
		t.Errorf("both failures must be the same error: %v / %v", e1, e2)
	}
}

func TestPhoneReset_StrictDefaultKeepsTheEmailAndPhoneContract(t *testing.T) {
	f := newResetFixture(t, false)
	ctx := context.Background()
	if !f.svc.ResetRequiresEmail() {
		t.Fatal("the default must require the e-mail")
	}
	if _, err := f.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone); !errors.Is(err, domain.ErrPhoneResetNotEnabled) {
		t.Errorf("phone-only initiate must be off: %v", err)
	}
	if _, err := f.svc.ResetPasswordByPhone(ctx, fixturePhone, "123456", "newpass", "", ""); !errors.Is(err, domain.ErrPhoneResetNotEnabled) {
		t.Errorf("phone-only confirm must be off: %v", err)
	}
	if f.sms.count() != 0 || f.lookups != 0 {
		t.Error("with the switch on, the phone-only path must do nothing")
	}
}

// New default service built without any option keeps requiring the e-mail.
func TestPasswordChangeService_DefaultRequiresEmailForReset(t *testing.T) {
	svc := NewPasswordChangeService(nil, nil, nil, nil, nil, nil, nil, nil, DefaultPasswordChangeConfig())
	if !svc.ResetRequiresEmail() {
		t.Error("the default must be PASSWORD_RESET_REQUIRE_EMAIL=true")
	}
}

func TestPasswordChangeService_PolicyOptionReplacesLegacyRules(t *testing.T) {
	legacy := NewPasswordChangeService(nil, nil, nil, nil, nil, nil, nil, nil, DefaultPasswordChangeConfig())
	if err := legacy.validatePasswordStrength("abcdef", ""); err == nil {
		t.Error("legacy config requires 8 chars with composition")
	}
	relaxed := NewPasswordChangeService(nil, nil, nil, nil, nil, nil, nil, nil, DefaultPasswordChangeConfig(), WithPasswordChangePolicy(domain.NewPasswordPolicy(6, false)))
	if err := relaxed.validatePasswordStrength("abcdef", "abc@x.com"); err != nil {
		t.Errorf("complexity off must accept 6 lowercase chars even inside the e-mail: %v", err)
	}
	strict := NewPasswordChangeService(nil, nil, nil, nil, nil, nil, nil, nil, DefaultPasswordChangeConfig(), WithPasswordChangePolicy(domain.StrictPasswordPolicy()))
	if err := strict.validatePasswordStrength("Abcdef12", "abcdef@x.com"); !errors.Is(err, domain.ErrPasswordContainsUserInfo) {
		t.Errorf("strict policy keeps the e-mail rule for change/reset: %v", err)
	}
	if err := strict.validatePasswordStrength("Admin", ""); err == nil {
		t.Error("too short must fail")
	}
	if err := NewPasswordChangeService(nil, nil, nil, nil, nil, nil, nil, nil, DefaultPasswordChangeConfig(), WithPasswordChangePolicy(domain.NewPasswordPolicy(4, true))).validatePasswordStrength("admin", ""); err == nil {
		t.Error("a common password must fail under the strict policy")
	}
}

// The e-mail flow no longer tells an unknown account apart from a wrong code.
func TestCompleteForgotPassword_UnknownAccountLooksLikeWrongCode(t *testing.T) {
	forgot := mocks.NewMockForgotPasswordRepository()
	attempts := 0
	forgot.GetByIDFunc = func(ctx context.Context, id string) (*domain.ForgotPasswordRequest, error) {
		return &domain.ForgotPasswordRequest{ID: id, Status: "initiated", ExpiresAt: time.Now().Add(time.Minute), Nonce: "n", UserID: nil, OTPCode: "123456"}, nil
	}
	forgot.UpdateOTPAttemptsFunc = func(ctx context.Context, id string, a int) error { attempts = a; return nil }
	svc := NewPasswordChangeService(nil, nil, forgot, nil, nil, nil, nil, nil, DefaultPasswordChangeConfig())
	_, err := svc.CompleteForgotPassword(context.Background(), "id", "123456", "n", "Abcdef12", "Abcdef12")
	if !errors.Is(err, domain.ErrForgotPasswordInvalidOTP) {
		t.Fatalf("want ErrForgotPasswordInvalidOTP, got %v", err)
	}
	if attempts != 1 {
		t.Errorf("an unknown account must consume attempts like a known one, got %d", attempts)
	}
}
