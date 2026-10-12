package services

import (
	"context"
	"errors"
	"testing"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// Whether a phone is registered-but-unverified must not be learnable without the password: a wrong
// password on an unverified account answers like any other wrong password.
func TestPhoneLogin_WrongPasswordOnUnverifiedAccountIsInvalidCredentials(t *testing.T) {
	user := &domain.User{ID: 7, Phone: "+15551234567", PasswordHash: "hashed_right", IsActive: true, PhoneVerified: false}
	userRepo := mocks.NewMockUserRepository()
	userRepo.FindByPhoneFunc = func(ctx context.Context, p string) (*domain.User, error) { return user, nil }
	s := NewPhoneAuthStrategy(userRepo, mocks.NewMockPasswordService(), mocks.NewMockIdentifierResolutionService())

	if _, err := s.Authenticate(context.Background(), "+15551234567", "wrong1"); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("wrong password: expected ErrInvalidCredentials, got %v", err)
	}
	_, err := s.Authenticate(context.Background(), "+15551234567", "right")
	var failure *domain.AuthFailureError
	if !errors.Is(err, domain.ErrPhoneNotVerified) || !errors.As(err, &failure) || failure.UserID != 7 {
		t.Errorf("right password: expected ErrPhoneNotVerified carrying user 7, got %v", err)
	}
}
