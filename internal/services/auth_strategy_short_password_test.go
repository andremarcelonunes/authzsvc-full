package services

import (
	"context"
	"errors"
	"testing"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// Password length is a registration policy. A user whose stored password is shorter
// than 8 characters must still be able to log in, and a wrong short password must
// be an invalid-credentials error (HTTP 401), not an untyped error (HTTP 500).
func TestAuthStrategies_ShortStoredPassword(t *testing.T) {
	const storedPassword = "abc123" // 6 characters

	newPasswordSvc := func() *mocks.MockPasswordService {
		passwordSvc := mocks.NewMockPasswordService()
		passwordSvc.VerifyFunc = func(hashedPassword, password string) bool {
			return hashedPassword == "hashed_"+password
		}
		return passwordSvc
	}
	storedUser := &domain.User{
		ID: 7, Email: "short@example.com", Phone: "+15551234567",
		PasswordHash: "hashed_" + storedPassword, IsActive: true, PhoneVerified: true,
	}

	strategies := []struct {
		name       string
		identifier string
		build      func() domain.AuthenticationStrategy
	}{
		{
			name:       "email strategy",
			identifier: "short@example.com",
			build: func() domain.AuthenticationStrategy {
				userRepo := mocks.NewMockUserRepository()
				userRepo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
					return storedUser, nil
				}
				return NewEmailAuthStrategy(userRepo, newPasswordSvc(), mocks.NewMockIdentifierResolutionService())
			},
		},
		{
			name:       "phone strategy",
			identifier: "+15551234567",
			build: func() domain.AuthenticationStrategy {
				userRepo := mocks.NewMockUserRepository()
				userRepo.FindByPhoneFunc = func(ctx context.Context, phone string) (*domain.User, error) {
					return storedUser, nil
				}
				return NewPhoneAuthStrategy(userRepo, newPasswordSvc(), mocks.NewMockIdentifierResolutionService())
			},
		},
	}

	for _, tt := range strategies {
		t.Run(tt.name+" correct short password authenticates", func(t *testing.T) {
			user, err := tt.build().Authenticate(context.Background(), tt.identifier, storedPassword)
			if err != nil {
				t.Fatalf("expected successful authentication, got %v", err)
			}
			if user == nil || user.ID != storedUser.ID {
				t.Errorf("expected user %d, got %+v", storedUser.ID, user)
			}
		})

		t.Run(tt.name+" wrong short password is invalid credentials", func(t *testing.T) {
			user, err := tt.build().Authenticate(context.Background(), tt.identifier, "wrong1")
			if !errors.Is(err, domain.ErrInvalidCredentials) {
				t.Fatalf("expected domain.ErrInvalidCredentials, got %v", err)
			}
			if user != nil {
				t.Errorf("expected nil user, got %+v", user)
			}
		})

		t.Run(tt.name+" empty password is still rejected", func(t *testing.T) {
			if err := tt.build().ValidateCredentials(context.Background(), tt.identifier, ""); err == nil {
				t.Error("expected error for empty password")
			}
		})
	}
}
