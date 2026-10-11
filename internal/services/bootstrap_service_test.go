package services

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// fakeUserStore is a tiny in-memory UserRepository behind the mock funcs.
type fakeUserStore struct {
	users  []*domain.User
	repo   *mocks.MockUserRepository
	nextID uint
}

func newFakeUserStore() *fakeUserStore {
	f := &fakeUserStore{repo: mocks.NewMockUserRepository(), nextID: 1}
	f.repo.CreateFunc = func(ctx context.Context, u *domain.User) error {
		u.ID = f.nextID
		f.nextID++
		cp := *u
		f.users = append(f.users, &cp)
		return nil
	}
	f.repo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
		for _, u := range f.users {
			if u.Email == email {
				return u, nil
			}
		}
		return nil, domain.ErrUserNotFound
	}
	f.repo.FindByPhoneFunc = func(ctx context.Context, phone string) (*domain.User, error) {
		for _, u := range f.users {
			if u.Phone == phone {
				return u, nil
			}
		}
		return nil, domain.ErrUserNotFound
	}
	f.repo.ExistsByRoleFunc = func(ctx context.Context, role string) (bool, error) {
		for _, u := range f.users {
			if u.Role == role {
				return true, nil
			}
		}
		return false, nil
	}
	return f
}

func newBootstrapForTest(f *fakeUserStore) (*BootstrapService, *bytes.Buffer, *mocks.MockComprehensiveAuditService) {
	buf := &bytes.Buffer{}
	pw := mocks.NewMockPasswordService()
	pw.HashFunc = func(p string) (string, error) { return "hashed:" + strings.Repeat("x", 8), nil }
	audit := mocks.NewMockComprehensiveAuditService()
	validator := NewBusinessValidationService(f.repo, BusinessValidationConfig{
		PasswordPolicy:  PasswordPolicy{MinLength: 8, MaxLength: 128, RequireUppercase: true, RequireLowercase: true, RequireNumbers: true, MaxRepeatingChars: 3},
		EmailValidation: EmailValidationConfig{MaxLength: 254},
	})
	return NewBootstrapService(f.repo, pw, validator, audit, log.New(buf, "", 0)), buf, audit
}

var rootAcct = BootstrapAccount{Email: "root@example.com", Phone: "+5511900000001", Password: "Sup3rSecretRoot"}

func TestBootstrap_CreatesRootOnceAndIsIdempotent(t *testing.T) {
	f := newFakeUserStore()
	svc, buf, audit := newBootstrapForTest(f)

	created, err := svc.EnsureRootAdmin(context.Background(), rootAcct)
	if err != nil || !created {
		t.Fatalf("expected root to be created, got created=%v err=%v", created, err)
	}
	root := f.users[0]
	if root.Role != domain.RoleRoot || !root.IsActive || !root.PhoneVerified || root.PasswordHash == rootAcct.Password || root.PasswordHash == "" {
		t.Errorf("unexpected root user: %+v", root)
	}
	if len(audit.LoggedEvents) != 1 || audit.LoggedEvents[0].EventType != "bootstrap_account_created" {
		t.Errorf("expected one audit event, got %+v", audit.LoggedEvents)
	}

	// second run, even with different credentials: nothing changes
	other := BootstrapAccount{Email: "other@example.com", Phone: "+5511900000002", Password: "An0therSecret"}
	created, err = svc.EnsureRootAdmin(context.Background(), other)
	if err != nil || created || len(f.users) != 1 {
		t.Fatalf("second run must do nothing (created=%v err=%v users=%d)", created, err, len(f.users))
	}
	if strings.Contains(buf.String(), rootAcct.Password) {
		t.Error("password leaked into logs")
	}
}

func TestBootstrap_AbsentConfigWarnsOnce(t *testing.T) {
	f := newFakeUserStore()
	svc, buf, _ := newBootstrapForTest(f)
	svc.Run(context.Background(), BootstrapAccount{}, BootstrapAccount{})
	if len(f.users) != 0 {
		t.Fatal("nothing must be created")
	}
	if n := strings.Count(buf.String(), "no root administrator configured"); n != 1 {
		t.Errorf("expected exactly one warning, got %d: %q", n, buf.String())
	}
}

func TestBootstrap_InvalidConfigCreatesNothingAndLeaksNoPassword(t *testing.T) {
	cases := map[string]BootstrapAccount{
		"bad email":     {Email: "not-an-email", Phone: "+5511900000001", Password: "Sup3rSecretRoot"},
		"bad phone":     {Email: "root@example.com", Phone: "abc", Password: "Sup3rSecretRoot"},
		"weak password": {Email: "root@example.com", Phone: "+5511900000001", Password: "weakpw"},
		"incomplete":    {Email: "root@example.com", Phone: "+5511900000001"},
	}
	for name, acct := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFakeUserStore()
			svc, buf, _ := newBootstrapForTest(f)
			created, err := svc.EnsureRootAdmin(context.Background(), acct)
			if created || err == nil || len(f.users) != 0 {
				t.Fatalf("expected failure without creation (created=%v err=%v)", created, err)
			}
			out := buf.String()
			if !strings.Contains(out, "ERROR") {
				t.Errorf("expected an error log line, got %q", out)
			}
			if acct.Password != "" && strings.Contains(out, acct.Password) {
				t.Error("password leaked into logs")
			}
			if err != nil && acct.Password != "" && strings.Contains(err.Error(), acct.Password) {
				t.Error("password leaked into error")
			}
		})
	}
}

func TestBootstrap_RootEmailOwnedByNonRootUserNotCreated(t *testing.T) {
	f := newFakeUserStore()
	f.users = append(f.users, &domain.User{ID: 9, Email: rootAcct.Email, Phone: "+5511911111111", Role: domain.RoleUser})
	svc, buf, _ := newBootstrapForTest(f)
	created, err := svc.EnsureRootAdmin(context.Background(), rootAcct)
	if created || err == nil || len(f.users) != 1 || f.users[0].Role != domain.RoleUser {
		t.Fatalf("existing user must be untouched (created=%v err=%v)", created, err)
	}
	if strings.Contains(buf.String(), rootAcct.Password) {
		t.Error("password leaked into logs")
	}
}

func TestBootstrap_ServiceAdminByEmail(t *testing.T) {
	svcAcct := BootstrapAccount{Email: "svc@example.com", Phone: "+5511900000003", Password: "Sv1cePassword"}

	f := newFakeUserStore()
	svc, _, _ := newBootstrapForTest(f)
	created, err := svc.EnsureServiceAdmin(context.Background(), svcAcct)
	if err != nil || !created || f.users[0].Role != domain.RoleAdmin || !f.users[0].PhoneVerified || !f.users[0].IsActive {
		t.Fatalf("service admin not created correctly: created=%v err=%v users=%+v", created, err, f.users)
	}
	if created, _ = svc.EnsureServiceAdmin(context.Background(), svcAcct); created || len(f.users) != 1 {
		t.Error("second run must do nothing")
	}

	// email owned by a user of another role: not modified
	f2 := newFakeUserStore()
	f2.users = append(f2.users, &domain.User{ID: 5, Email: svcAcct.Email, Role: domain.RoleClient, PasswordHash: "orig"})
	svc2, buf2, _ := newBootstrapForTest(f2)
	created, err = svc2.EnsureServiceAdmin(context.Background(), svcAcct)
	if created || err != nil || len(f2.users) != 1 || f2.users[0].Role != domain.RoleClient || f2.users[0].PasswordHash != "orig" {
		t.Fatalf("existing user must not be modified: %+v", f2.users[0])
	}
	if !strings.Contains(buf2.String(), "not modified") {
		t.Errorf("expected a warning, got %q", buf2.String())
	}

	// absent service admin config: silent no-op
	f3 := newFakeUserStore()
	svc3, buf3, _ := newBootstrapForTest(f3)
	if created, _ = svc3.EnsureServiceAdmin(context.Background(), BootstrapAccount{}); created || buf3.Len() != 0 {
		t.Error("absent service admin config must be a silent no-op")
	}
}

func TestBusinessValidation_RoleRule(t *testing.T) {
	f := newFakeUserStore()
	validator := NewBusinessValidationService(f.repo, BusinessValidationConfig{
		PasswordPolicy:  PasswordPolicy{MinLength: 8, MaxLength: 128},
		EmailValidation: EmailValidationConfig{MaxLength: 254},
	})
	for role, want := range map[string]bool{"": true, "user": true, "client": true, "contact": true, "attendant": true, "admin": true, "root": true, "moderator": false, "x": false} {
		res, err := validator.ValidateRegistrationRules(context.Background(), "a@example.com", "+5511900000009", "Passw0rd123", role)
		if err != nil {
			t.Fatal(err)
		}
		hasRoleErr := false
		for _, e := range res.Errors {
			if e.Code == "ROLE_INVALID" {
				hasRoleErr = true
			}
		}
		if hasRoleErr == want {
			t.Errorf("role %q: ROLE_INVALID=%v, valid expected=%v", role, hasRoleErr, want)
		}
	}
}
