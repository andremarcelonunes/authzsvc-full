package repositories

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/you/authzsvc/domain"
)

func countNullEmails(t *testing.T, repo *UserRepositoryImpl) int64 {
	t.Helper()
	var n int64
	if err := repo.db.Raw("SELECT COUNT(*) FROM users WHERE email IS NULL").Scan(&n).Error; err != nil {
		t.Fatal(err)
	}
	return n
}

func TestUserRepository_UsersWithoutEmailCoexist(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db).(*UserRepositoryImpl)
	ctx := context.Background()

	for i, phone := range []string{"+5511999990001", "+5511999990002", "+5511999990003"} {
		u := &domain.User{Phone: phone, PasswordHash: "h", Role: "user", IsActive: true}
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("user %d without email must be created: %v", i, err)
		}
	}
	// The three rows are stored with NULL, not ""
	if got := countNullEmails(t, repo); got != 3 {
		t.Errorf("expected 3 rows with NULL email, got %d", got)
	}
	var empties int64
	if err := db.Raw("SELECT COUNT(*) FROM users WHERE email = ''").Scan(&empties).Error; err != nil || empties != 0 {
		t.Errorf("no row may store an empty string as email (count=%d err=%v)", empties, err)
	}
}

func TestUserRepository_FindByEmailEmptyFindsNothing(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)
	ctx := context.Background()
	if err := repo.Create(ctx, &domain.User{Phone: "+5511999990001", PasswordHash: "h", Role: "user", IsActive: true}); err != nil {
		t.Fatal(err)
	}

	// a legacy row that stored "" instead of NULL must not be reachable by an empty e-mail either
	if err := db.Exec("INSERT INTO users (email, phone, password, role, is_active) VALUES ('', '+5511999990099', 'h', 'user', true)").Error; err != nil {
		t.Fatal(err)
	}

	if _, err := repo.FindByEmail(ctx, ""); !errors.Is(err, domain.ErrUserNotFound) {
		t.Errorf("FindByEmail(\"\") must not match a user without e-mail, got %v", err)
	}
	if _, err := repo.FindByIdentifier(ctx, "", domain.IdentifierTypeEmail); !errors.Is(err, domain.ErrUserNotFound) {
		t.Errorf("FindByIdentifier(\"\", email) must not match, got %v", err)
	}
	if _, err := repo.FindByPhone(ctx, ""); !errors.Is(err, domain.ErrUserNotFound) {
		t.Errorf("FindByPhone(\"\") must not match, got %v", err)
	}
}

func TestUserRepository_NoEmailReadsBackAsEmptyString(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)
	ctx := context.Background()
	u := &domain.User{Phone: "+5511999990001", PasswordHash: "h", Role: "user", IsActive: true}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	for name, find := range map[string]func() (*domain.User, error){
		"by id":    func() (*domain.User, error) { return repo.FindByID(ctx, u.ID) },
		"by phone": func() (*domain.User, error) { return repo.FindByPhone(ctx, "+5511999990001") },
		"by ident": func() (*domain.User, error) {
			return repo.FindByIdentifier(ctx, "+5511999990001", domain.IdentifierTypePhone)
		},
	} {
		got, err := find()
		if err != nil || got.Email != "" || got.Phone != "+5511999990001" {
			t.Errorf("%s: got %+v err=%v", name, got, err)
		}
	}
}

func TestUserRepository_EmailUniquenessStillEnforced(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)
	ctx := context.Background()
	if err := repo.Create(ctx, &domain.User{Email: "a@example.com", Phone: "+5511999990001", PasswordHash: "h", Role: "user", IsActive: true}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, &domain.User{Email: "a@example.com", Phone: "+5511999990002", PasswordHash: "h", Role: "user", IsActive: true}); err == nil {
		t.Error("a duplicate e-mail must still be rejected by the unique index")
	}
	got, err := repo.FindByEmail(ctx, "a@example.com")
	if err != nil || got.Email != "a@example.com" {
		t.Errorf("lookup by a real e-mail must work: %+v %v", got, err)
	}
}

func TestUserRepository_UpdateKeepsNullEmailAndOtherColumns(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db).(*UserRepositoryImpl)
	ctx := context.Background()
	u := &domain.User{Phone: "+5511999990001", PasswordHash: "h", Role: "user", IsActive: true}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	before, _ := repo.FindByID(ctx, u.ID)

	u2 := *before
	u2.Role = domain.RoleClient
	if err := repo.Update(ctx, &u2); err != nil {
		t.Fatal(err)
	}
	after, err := repo.FindByID(ctx, u.ID)
	if err != nil || after.Role != domain.RoleClient || after.Email != "" {
		t.Fatalf("role change must persist and e-mail stay empty: %+v %v", after, err)
	}
	if got := countNullEmails(t, repo); got != 1 {
		t.Errorf("e-mail must still be NULL after Update, NULL rows=%d", got)
	}
	if after.CreatedAt.IsZero() || after.CreatedAt.Before(before.CreatedAt.Add(-time.Second)) {
		t.Errorf("Update must not reset created_at: before=%v after=%v", before.CreatedAt, after.CreatedAt)
	}
}
