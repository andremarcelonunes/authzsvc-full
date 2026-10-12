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
