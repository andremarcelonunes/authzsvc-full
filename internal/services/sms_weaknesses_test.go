package services

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// newWeaknessOTP builds the OTP service the way production does today (resend window 60s, code lifetime 5m).
func newWeaknessOTP(t *testing.T) (domain.OTPService, *miniredis.Miniredis, *smsBox) {
	t.Helper()
	t.Chdir(t.TempDir())
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	sms := &smsBox{}
	otp := NewOTPService(sms, mocks.NewMockUserRepository(), rdb, OTPConfig{Length: 6, TTL: 5 * time.Minute, MaxAttempts: 3, ResendWindow: 60 * time.Second})
	return otp, mr, sms
}

// Asking again while a valid code exists must send nothing and answer like a fresh request.
func TestSMSWeakness_RepeatedRequestWhileCodeValidSendsNothing(t *testing.T) {
	otp, mr, sms := newWeaknessOTP(t)
	ctx := context.Background()
	if _, err := otp.Generate(ctx, "+5511999990000", 7); err != nil {
		t.Fatal(err)
	}
	if _, err := otp.Generate(ctx, "+5511999990000", 7); err != nil {
		t.Errorf("a repeated request must get the same answer as a fresh one, got %v", err)
	}
	mr.FastForward(61 * time.Second) // past the 60s resend window, code still valid
	_, _ = otp.Generate(ctx, "+5511999990000", 7)
	if sms.count() != 1 {
		t.Errorf("only one SMS may go out while the code is valid and the minimum interval has not passed, got %d", sms.count())
	}
}

// A phone must not receive more than 2 SMS in a day, all asking spaced out past every existing window.
func TestSMSWeakness_NoPerPhoneDailyCap(t *testing.T) {
	otp, mr, sms := newWeaknessOTP(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, _ = otp.Generate(ctx, "+5511999990000", 7)
		mr.FastForward(6 * time.Minute) // the code expired, the resend window passed
	}
	if sms.count() > 2 {
		t.Errorf("a phone got %d SMS in 30 minutes; the daily cap is 2", sms.count())
	}
}

// One caller address must not make the service text more than 5 different phones a day.
func TestSMSWeakness_NoPerIPCap(t *testing.T) {
	otp, _, sms := newWeaknessOTP(t)
	ctx := context.WithValue(context.Background(), "client_ip", "203.0.113.9")
	for i := 0; i < 10; i++ {
		_, _ = otp.Generate(ctx, fmt.Sprintf("+55119999900%02d", i), uint(100+i))
	}
	if sms.count() > 5 {
		t.Errorf("one address triggered %d SMS; the cap is 5 a day", sms.count())
	}
}

// The phone-only reset must not text a phone that has no account (already true; guards against regressions).
func TestSMSWeakness_UnknownPhoneGetsNoSMS(t *testing.T) {
	f := newResetFixture(t, true)
	if _, err := f.svc.InitiateForgotPasswordByPhone(context.Background(), "", "+14155550999"); err != nil {
		t.Fatal(err)
	}
	if f.sms.count() != 0 {
		t.Errorf("an unknown phone received %d SMS", f.sms.count())
	}
}
