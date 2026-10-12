package services

import (
	"context"
	"testing"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

func TestAuthenticateUser_FailedLoginIsAuditedWithTheUsersID(t *testing.T) {
	user := &domain.User{ID: 7, Email: "ana@example.com", Phone: "+14155550100", PasswordHash: "hashed_right", IsActive: true, PhoneVerified: true}
	run := func(email string) uint {
		userRepo := mocks.NewMockUserRepository()
		userRepo.FindByEmailFunc = func(ctx context.Context, e string) (*domain.User, error) {
			if e == user.Email {
				return user, nil
			}
			return nil, domain.ErrUserNotFound
		}
		resolver := mocks.NewMockIdentifierResolutionService()
		resolver.ResolveIdentifierFunc = func(ctx context.Context, id string) (*domain.IdentifierResolution, error) {
			return &domain.IdentifierResolution{Type: domain.IdentifierTypeEmail, OriginalValue: id, NormalizedValue: id, IsValid: true}, nil
		}
		auditSvc := mocks.NewMockComprehensiveAuditService()
		audited := uint(999)
		auditSvc.LogLoginAttemptFunc = func(ctx context.Context, userID uint, email, ip string, success bool, reason string) error {
			audited = userID
			return nil
		}
		svc := &AuthServiceImpl{
			userRepo: userRepo, sessionRepo: mocks.NewMockSessionRepository(), passwordSvc: mocks.NewMockPasswordService(),
			tokenSvc: mocks.NewMockTokenService(), auditSvc: auditSvc, identifierResolver: resolver,
			emailAuthStrategy: NewEmailAuthStrategy(userRepo, mocks.NewMockPasswordService(), resolver),
		}
		if _, err := svc.AuthenticateUser(context.Background(), &domain.AuthRequest{Email: email, Password: "wrongpassword"}); err == nil {
			t.Fatal("login must fail")
		}
		return audited
	}
	if got := run("ana@example.com"); got != 7 {
		t.Errorf("wrong password for an existing user must be audited with its id, got %d", got)
	}
	if got := run("ghost@example.com"); got != 0 {
		t.Errorf("an unknown identifier stays 0, got %d", got)
	}
}
