package services

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

func newAtRestOTP(t *testing.T) (domain.OTPService, *miniredis.Miniredis, *smsBox) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	sms := &smsBox{}
	otp := NewOTPService(sms, mocks.NewMockUserRepository(), rdb, OTPConfig{Length: 6, TTL: time.Minute, MaxAttempts: 3, ResendWindow: time.Minute})
	return otp, mr, sms
}

func TestOTPAtRest_RedisHoldsNoClearCode(t *testing.T) {
	otp, mr, sms := newAtRestOTP(t)
	if _, err := otp.Generate(context.Background(), "+5511999990000", 7); err != nil {
		t.Fatal(err)
	}
	code := sms.lastCode(t)
	stored, err := mr.Get("otp:+5511999990000:7")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, code) {
		t.Errorf("Redis holds the clear code %q: %q", code, stored)
	}
	for _, key := range mr.Keys() {
		if v, _ := mr.Get(key); v == code {
			t.Errorf("key %s holds the clear code", key)
		}
	}
}

func TestOTPAtRest_NoCodeIsWrittenToAFile(t *testing.T) {
	t.Chdir(t.TempDir())
	otp, _, _ := newAtRestOTP(t)
	if _, err := otp.Generate(context.Background(), "+5511999990000", 7); err != nil {
		t.Fatal(err)
	}
	var found []string
	_ = filepath.Walk(".", func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			found = append(found, p)
		}
		return nil
	})
	if len(found) != 0 {
		t.Errorf("generating a code must not create files, found %v", found)
	}
}

func TestOTPAtRest_ForgotPasswordRequestStoresNoClearCode(t *testing.T) {
	t.Chdir(t.TempDir())
	otp, _, sms := newAtRestOTP(t)
	user := &domain.User{ID: 7, Email: "a@b.co", Phone: "+14155550100", IsActive: true}
	userRepo := mocks.NewMockUserRepository()
	userRepo.FindByEmailFunc = func(ctx context.Context, e string) (*domain.User, error) { return user, nil }
	userRepo.FindByPhoneFunc = func(ctx context.Context, p string) (*domain.User, error) { return user, nil }
	forgot := mocks.NewMockForgotPasswordRepository()
	var stored []string
	forgot.CreateFunc = func(ctx context.Context, r *domain.ForgotPasswordRequest) error { stored = append(stored, r.OTPCode); return nil }
	forgot.UpdateFunc = func(ctx context.Context, r *domain.ForgotPasswordRequest) error { stored = append(stored, r.OTPCode); return nil }
	svc := NewPasswordChangeService(mocks.NewMockPasswordChangeRepository(), mocks.NewMockPasswordHistoryRepository(), forgot,
		userRepo, mocks.NewMockPasswordService(), otp, mocks.NewMockSessionRepository(), nil, DefaultPasswordChangeConfig())

	if _, err := svc.InitiateForgotPassword(context.Background(), user.Email, user.Phone, "10.0.0.1", "ua"); err != nil {
		t.Fatal(err)
	}
	code := sms.lastCode(t)
	for _, v := range stored {
		if v == code {
			t.Errorf("the reset request row holds the clear code %q", code)
		}
	}
}

func TestOTPDigest_Properties(t *testing.T) {
	d := NewOTPDigester("jwt-secret")
	a := d.Digest("otp:+1:7", "123456")
	if a == d.Digest("otp:+1:7", "123457") || a == d.Digest("otp:+1:8", "123456") {
		t.Error("digest must depend on code and scope")
	}
	if a != NewOTPDigester("jwt-secret").Digest("otp:+1:7", "123456") {
		t.Error("digest must be stable for the same secret")
	}
	if a == NewOTPDigester("other-secret").Digest("otp:+1:7", "123456") {
		t.Error("digest must depend on the secret")
	}
	if strings.Contains(a, "123456") {
		t.Error("digest must not contain the code")
	}
	if !otpMatches(d, a, "otp:+1:7", "123456") || otpMatches(d, a, "otp:+1:7", "000000") || otpMatches(d, a, "otp:+1:8", "123456") {
		t.Error("otpMatches must accept only the right code in the right scope")
	}
	// Legacy clear values keep working during the transition; a digest never matches without a digester.
	if !otpMatches(d, "123456", "x", "123456") || otpMatches(d, "123456", "x", "654321") {
		t.Error("legacy clear values must still be compared")
	}
	if otpMatches(nil, a, "otp:+1:7", "123456") {
		t.Error("a digest cannot match without a digester")
	}
	if NewOTPDigester("").Digest("s", "c") == NewOTPDigester("").Digest("s", "c") {
		t.Error("an empty secret must give a random key per digester")
	}
}

func TestOTPAtRest_VerifyStillWorksAndKeepsItsBehaviour(t *testing.T) {
	t.Chdir(t.TempDir())
	otp, mr, sms := newAtRestOTP(t)
	ctx := context.Background()
	if _, err := otp.Generate(ctx, "+5511999990000", 7); err != nil {
		t.Fatal(err)
	}
	code := sms.lastCode(t)

	if ok, err := otp.Verify(ctx, "+5511999990000", "000000", 7); ok || err != domain.ErrOTPInvalid {
		t.Errorf("wrong code: ok=%v err=%v", ok, err)
	}
	if mr.Exists("otp:att:+5511999990000:7") == false {
		t.Error("attempts counter must exist")
	}
	if ok, err := otp.Verify(ctx, "+5511999990000", code, 7); !ok || err != nil {
		t.Errorf("right code: ok=%v err=%v", ok, err)
	}
	if mr.Exists("otp:+5511999990000:7") {
		t.Error("a verified code must be removed")
	}
	if _, err := otp.Verify(ctx, "+5511999990000", code, 7); err != domain.ErrOTPNotFound {
		t.Errorf("a used code: err=%v", err)
	}
	if ttl := mr.TTL("otp:res:+5511999990000"); ttl <= 0 {
		t.Errorf("resend window must be kept, ttl=%v", ttl)
	}
}

func TestOTPAtRest_CodeIssuedBeforeTheDeployStillVerifies(t *testing.T) {
	otp, mr, _ := newAtRestOTP(t)
	_ = mr.Set("otp:+5511999990000:7", "654321") // written by the previous release, in clear
	mr.SetTTL("otp:+5511999990000:7", time.Minute)
	if ok, err := otp.Verify(context.Background(), "+5511999990000", "654321", 7); !ok || err != nil {
		t.Errorf("a clear legacy code must verify: ok=%v err=%v", ok, err)
	}
}

func TestOTPAtRest_PasswordChangeRowsHoldOnlyADigest(t *testing.T) {
	t.Chdir(t.TempDir())
	otp, _, sms := newAtRestOTP(t)
	user := &domain.User{ID: 7, Email: "a@b.co", Phone: "+14155550100", IsActive: true}
	userRepo := mocks.NewMockUserRepository()
	userRepo.FindByEmailFunc = func(ctx context.Context, e string) (*domain.User, error) { return user, nil }
	userRepo.FindByPhoneFunc = func(ctx context.Context, p string) (*domain.User, error) { return user, nil }
	userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) { return user, nil }
	forgot := mocks.NewMockForgotPasswordRepository()
	var row *domain.ForgotPasswordRequest
	forgot.CreateFunc = func(ctx context.Context, r *domain.ForgotPasswordRequest) error { row = r; return nil }
	forgot.UpdateFunc = func(ctx context.Context, r *domain.ForgotPasswordRequest) error { row = r; return nil }
	forgot.GetByIDFunc = func(ctx context.Context, id string) (*domain.ForgotPasswordRequest, error) { return row, nil }
	svc := NewPasswordChangeService(mocks.NewMockPasswordChangeRepository(), mocks.NewMockPasswordHistoryRepository(), forgot,
		userRepo, mocks.NewMockPasswordService(), otp, mocks.NewMockSessionRepository(), nil, DefaultPasswordChangeConfig(),
		WithPasswordChangeOTPDigester(NewOTPDigester("jwt-secret")), WithPasswordChangePolicy(domain.NewPasswordPolicy(6, false)))

	resp, err := svc.InitiateForgotPassword(context.Background(), user.Email, user.Phone, "10.0.0.1", "ua")
	if err != nil {
		t.Fatal(err)
	}
	code := sms.lastCode(t)
	if !strings.HasPrefix(row.OTPCode, "hmac1:") || strings.Contains(row.OTPCode, code) {
		t.Fatalf("the row must hold a digest, got %q", row.OTPCode)
	}
	// The flow still completes with the code, and rejects a wrong one.
	if _, err := svc.CompleteForgotPassword(context.Background(), resp.RequestID, "000000", resp.Nonce, "newpass1", "newpass1"); err != domain.ErrForgotPasswordInvalidOTP {
		t.Errorf("wrong code: %v", err)
	}
	if _, err := svc.CompleteForgotPassword(context.Background(), resp.RequestID, code, resp.Nonce, "newpass1", "newpass1"); err != nil {
		t.Errorf("right code must complete the reset: %v", err)
	}
}
