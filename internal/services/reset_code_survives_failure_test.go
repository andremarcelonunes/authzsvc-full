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

type failingResetEnv struct {
	svc     *PasswordChangeService
	otp     domain.OTPService
	sms     *smsBox
	user    *domain.User
	updated int
}

func newFailingResetEnv(t *testing.T, historyErr, updateErr error) *failingResetEnv {
	t.Helper()
	t.Chdir(t.TempDir())
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	e := &failingResetEnv{sms: &smsBox{}, user: &domain.User{ID: 7, Phone: fixturePhone, PasswordHash: "hashed_oldpass", IsActive: true, Role: "user"}}

	userRepo := mocks.NewMockUserRepository()
	userRepo.FindByPhoneFunc = func(ctx context.Context, p string) (*domain.User, error) { return e.user, nil }
	userRepo.UpdateFunc = func(ctx context.Context, u *domain.User) error { e.updated++; return updateErr }
	history := mocks.NewMockPasswordHistoryRepository()
	history.GetRecentPasswordsFunc = func(ctx context.Context, id uint, n int) ([]string, error) { return nil, historyErr }

	e.otp = NewOTPService(e.sms, userRepo, rdb, OTPConfig{Length: 6, TTL: 5 * time.Minute, MaxAttempts: 5, ResendWindow: 60 * time.Second})
	e.svc = NewPasswordChangeService(mocks.NewMockPasswordChangeRepository(), history, mocks.NewMockForgotPasswordRepository(),
		userRepo, mocks.NewMockPasswordService(), e.otp, mocks.NewMockSessionRepository(), nil, DefaultPasswordChangeConfig(),
		WithPasswordChangePolicy(domain.NewPasswordPolicy(6, false)), WithPasswordResetRequireEmail(false))
	return e
}

// An internal failure after the code was accepted (here: the password history table is unreachable)
// must not burn the code: the person retries with the SMS they already paid for.
func TestResetByPhone_InternalFailureAfterTheCodeDoesNotBurnIt(t *testing.T) {
	for name, tc := range map[string]struct{ history, update error }{
		"history lookup fails": {history: errors.New(`relation "auth.password_history" does not exist`)},
		"password update fails": {update: errors.New("db down")},
	} {
		t.Run(name, func(t *testing.T) {
			e := newFailingResetEnv(t, tc.history, tc.update)
			ctx := context.Background()
			if _, err := e.svc.InitiateForgotPasswordByPhone(ctx, "", fixturePhone); err != nil {
				t.Fatal(err)
			}
			code := e.sms.lastCode(t)

			if _, err := e.svc.ResetPasswordByPhone(ctx, fixturePhone, code, "newpass1", "10.0.0.1", "ua"); err == nil {
				t.Fatal("the reset must fail while the dependency is down")
			}
			// Same code again: it must still be the same, unburned code.
			if _, err := e.svc.ResetPasswordByPhone(ctx, fixturePhone, code, "newpass1", "10.0.0.1", "ua"); errors.Is(err, domain.ErrResetCodeInvalid) {
				t.Errorf("the code was burned by an internal failure: the second try answered %v", err)
			}
		})
	}
}
