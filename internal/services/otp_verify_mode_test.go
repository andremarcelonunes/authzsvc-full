package services

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/infrastructure/notifications"
	"github.com/you/authzsvc/internal/mocks"
)

type vBudget struct{ reserved, sent int }

func (b *vBudget) Reserve(context.Context, domain.SMSTarget) error { b.reserved++; return nil }
func (b *vBudget) Release(context.Context, domain.SMSTarget) error { return nil }
func (b *vBudget) RecordSent(context.Context) error                { b.sent++; return nil }
func (b *vBudget) Usage(context.Context) (domain.SMSUsage, error)  { return domain.SMSUsage{}, nil }

type vVerifier struct {
	mu       sync.Mutex
	starts   int
	checks   int
	startErr error
	checkOK  bool
	checkErr error
	lastCode string
}

func (v *vVerifier) StartVerification(context.Context, string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.starts++
	return v.startErr
}
func (v *vVerifier) CheckVerification(_ context.Context, _ string, code string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.checks++
	v.lastCode = code
	return v.checkOK, v.checkErr
}

// directSMS is the inner direct-SMS sender; it must never be used in verify mode.
type directSMS struct{ calls int }

func (d *directSMS) SendSMS(string, string) error   { d.calls++; return nil }
func (d *directSMS) SendEmail(_, _, _ string) error { return nil }
func (d *directSMS) Live() bool                     { return true }

func newVerifyOTP(t *testing.T) (domain.OTPService, *miniredis.Miniredis, *vVerifier, *vBudget, *directSMS) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	v, b, d := &vVerifier{}, &vBudget{}, &directSMS{}
	n := notifications.NewBudgetedNotifier(d, b,
		notifications.WithTestPhonePrefixes([]string{"+5500000000", "+5511900000"}, false),
		notifications.WithPhoneCodeVerifier(v))
	otp := NewOTPService(n, mocks.NewMockUserRepository(), rdb, OTPConfig{Length: 6, TTL: time.Minute, MaxAttempts: 3, ResendWindow: time.Minute})
	return otp, mr, v, b, d
}

const realPhone = "+5511999990000"

func TestVerifyMode_GenerateSkipsLocalCodeAndDirectSMS(t *testing.T) {
	otp, mr, v, b, d := newVerifyOTP(t)
	req, err := otp.Generate(context.Background(), realPhone, 7)
	if err != nil {
		t.Fatal(err)
	}
	if req.Code != "" {
		t.Error("verify mode must not generate a local code")
	}
	if v.starts != 1 || d.calls != 0 || b.reserved != 1 || b.sent != 1 {
		t.Errorf("starts=%d direct=%d budget=%+v", v.starts, d.calls, b)
	}
	stored, _ := mr.Get("otp:" + realPhone + ":7")
	if stored != verifyPendingMarker {
		t.Errorf("stored %q", stored)
	}
	if ttl := mr.TTL("otp:" + realPhone + ":7"); ttl <= 0 {
		t.Error("the expiry rule must still apply")
	}
	if mr.TTL("otp:res:"+realPhone) <= 0 {
		t.Error("the resend window must still apply")
	}
}

func TestVerifyMode_ResendThrottleAndAlreadySentUnchanged(t *testing.T) {
	otp, _, v, _, _ := newVerifyOTP(t)
	if _, err := otp.Generate(context.Background(), realPhone, 7); err != nil {
		t.Fatal(err)
	}
	req, err := otp.Generate(context.Background(), realPhone, 7)
	if err != nil || !req.AlreadySent {
		t.Fatalf("second request inside the window: %+v %v", req, err)
	}
	if v.starts != 1 {
		t.Errorf("starts=%d, a throttled request must send nothing", v.starts)
	}
}

func TestVerifyMode_RateLimitFromProviderBecomesLimitError(t *testing.T) {
	otp, _, v, _, _ := newVerifyOTP(t)
	v.startErr = &domain.SMSLimitError{Kind: domain.SMSLimitPhoneInterval, RetryAfter: time.Minute}
	_, err := otp.Generate(context.Background(), realPhone, 7)
	var limit *domain.SMSLimitError
	if !errors.As(err, &limit) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyMode_InvalidPhoneFromProvider(t *testing.T) {
	otp, _, v, _, _ := newVerifyOTP(t)
	v.startErr = domain.ErrSMSInvalidPhone
	if _, err := otp.Generate(context.Background(), realPhone, 7); !errors.Is(err, domain.ErrSMSInvalidPhone) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyMode_LandlineRefusedBeforeAnySend(t *testing.T) {
	otp, mr, v, b, d := newVerifyOTP(t)
	_, err := otp.Generate(context.Background(), "+551133334444", 7)
	if !errors.Is(err, domain.ErrPhoneNotMobile) {
		t.Fatalf("got %v", err)
	}
	if v.starts != 0 || d.calls != 0 || b.reserved != 0 || len(mr.Keys()) != 0 {
		t.Errorf("nothing may happen: starts=%d direct=%d budget=%+v keys=%v", v.starts, d.calls, b, mr.Keys())
	}
}

func TestVerifyMode_TestPrefixesKeepTheLocalMockPath(t *testing.T) {
	otp, _, v, b, d := newVerifyOTP(t)
	for _, phone := range []string{"+5500000000123", "+5511900000800"} {
		req, err := otp.Generate(context.Background(), phone, 9)
		if err != nil {
			t.Fatalf("%s: %v", phone, err)
		}
		if req.Code == "" {
			t.Errorf("%s: test numbers keep the local code", phone)
		}
		ok, err := otp.Verify(context.Background(), phone, req.Code, 9)
		if err != nil || !ok {
			t.Errorf("%s: local verify %v %v", phone, ok, err)
		}
	}
	if v.starts != 0 || v.checks != 0 || d.calls != 0 || b.reserved != 0 {
		t.Errorf("a test number reached a provider: %+v %+v %d", v, b, d.calls)
	}
}

func TestVerifyMode_CheckApprovedConsumes(t *testing.T) {
	otp, mr, v, _, _ := newVerifyOTP(t)
	_, _ = otp.Generate(context.Background(), realPhone, 7)
	v.checkOK = true
	ok, err := otp.Verify(context.Background(), realPhone, "123456", 7)
	if err != nil || !ok {
		t.Fatalf("%v %v", ok, err)
	}
	if v.lastCode != "123456" {
		t.Error("the typed code must be sent to the provider")
	}
	if len(mr.Keys()) != 1 { // only the resend window remains
		t.Errorf("code and attempts must be consumed: %v", mr.Keys())
	}
}

func TestVerifyMode_CheckPendingIsInvalidAndCountsAttempts(t *testing.T) {
	otp, _, v, _, _ := newVerifyOTP(t)
	_, _ = otp.Generate(context.Background(), realPhone, 7)
	for i := 0; i < 3; i++ {
		if ok, err := otp.Verify(context.Background(), realPhone, "000000", 7); ok || !errors.Is(err, domain.ErrOTPInvalid) {
			t.Fatalf("try %d: %v %v", i, ok, err)
		}
	}
	// MaxAttempts is 3: the fourth try is refused by our own counter, without asking the provider
	checks := v.checks
	if _, err := otp.Verify(context.Background(), realPhone, "000000", 7); !errors.Is(err, domain.ErrOTPMaxAttempts) {
		t.Fatalf("got %v", err)
	}
	if v.checks != checks {
		t.Error("the local attempt cap must stop before the provider")
	}
}

func TestVerifyMode_ProviderErrorsAreMapped(t *testing.T) {
	for _, want := range []error{domain.ErrOTPMaxAttempts, domain.ErrOTPExpired} {
		otp, mr, v, _, _ := newVerifyOTP(t)
		_, _ = otp.Generate(context.Background(), realPhone, 7)
		v.checkErr = want
		if _, err := otp.Verify(context.Background(), realPhone, "123456", 7); !errors.Is(err, want) {
			t.Errorf("want %v got %v", want, err)
		}
		if mr.Exists("otp:" + realPhone + ":7") {
			t.Error("a dead verification must be cleaned up")
		}
	}
	otp, _, v, _, _ := newVerifyOTP(t)
	_, _ = otp.Generate(context.Background(), realPhone, 7)
	v.checkErr = errors.New("twilio down")
	if _, err := otp.Verify(context.Background(), realPhone, "123456", 7); err == nil || errors.Is(err, domain.ErrOTPInvalid) {
		t.Errorf("an unknown failure is not a wrong code: %v", err)
	}
}

func TestVerifyMode_MalformedCodeNeverReachesProvider(t *testing.T) {
	otp, _, v, _, _ := newVerifyOTP(t)
	_, _ = otp.Generate(context.Background(), realPhone, 7)
	for _, bad := range []string{"12", "abcdef", strings.Repeat("1", 11)} {
		if _, err := otp.Verify(context.Background(), realPhone, bad, 7); !errors.Is(err, domain.ErrOTPInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if v.checks != 0 {
		t.Error("malformed codes must not cost a provider check")
	}
}

func TestVerifyMode_VerifyKeepAllowsASecondCheckWithoutTheProvider(t *testing.T) {
	otp, _, v, _, _ := newVerifyOTP(t)
	_, _ = otp.Generate(context.Background(), realPhone, 7)
	v.checkOK = true
	keeper := otp.(*OTPServiceImpl)
	if ok, err := keeper.VerifyKeep(context.Background(), realPhone, "123456", 7); !ok || err != nil {
		t.Fatalf("%v %v", ok, err)
	}
	v.checkOK = false // the provider would now refuse a second use
	if ok, err := keeper.VerifyKeep(context.Background(), realPhone, "123456", 7); !ok || err != nil {
		t.Errorf("the approved code must stay usable: %v %v", ok, err)
	}
	if ok, _ := keeper.VerifyKeep(context.Background(), realPhone, "654321", 7); ok {
		t.Error("a different code must not pass")
	}
	if v.checks != 1 {
		t.Errorf("checks=%d", v.checks)
	}
	keeper.Consume(context.Background(), realPhone, 7)
	if _, err := keeper.VerifyKeep(context.Background(), realPhone, "123456", 7); !errors.Is(err, domain.ErrOTPNotFound) {
		t.Errorf("after Consume: %v", err)
	}
}
