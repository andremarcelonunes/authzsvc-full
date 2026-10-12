package services

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/infrastructure/auth"
	"github.com/you/authzsvc/internal/infrastructure/repositories"
	"github.com/you/authzsvc/internal/mocks"
)

// profileEnv wires the real auth service on top of a real (sqlite) user repository, real JWT
// service, real password service and a miniredis-backed session repository, so that the
// switches REQUIRE_PHONE_VERIFICATION and the role flow are tested end to end below the HTTP layer.
type profileEnv struct {
	svc      domain.AuthService
	userRepo domain.UserRepository
	tokenSvc domain.TokenService
	otpCalls int
	otpErr   error
	events   []string
}

func newProfileEnv(t *testing.T, requirePhoneVerification bool) *profileEnv {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if sqlDB, err := db.DB(); err == nil {
		sqlDB.SetMaxOpenConns(1) // one in-memory database for every query
	}
	if err := db.AutoMigrate(&repositories.DBUser{}); err != nil {
		t.Fatal(err)
	}

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })

	env := &profileEnv{}
	env.userRepo = repositories.NewUserRepository(db)
	env.tokenSvc = auth.NewJWTService("test-secret-for-unit-tests", "authzsvc-test", 15*time.Minute, time.Hour)
	passwordSvc := auth.NewPasswordService()
	sessionRepo := repositories.NewSessionRepository(rdb, time.Hour)
	resolver := NewIdentifierResolutionService()

	otpSvc := mocks.NewMockOTPService()
	otpSvc.GenerateFunc = func(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) {
		env.otpCalls++
		if env.otpErr != nil {
			return nil, env.otpErr
		}
		return &domain.OTPRequest{Phone: phone, UserID: userID}, nil
	}
	audit := mocks.NewMockComprehensiveAuditService()
	audit.LogSystemEventFunc = func(ctx context.Context, eventType, description string, metadata map[string]interface{}) error {
		env.events = append(env.events, eventType)
		return nil
	}

	policy := domain.PhoneVerificationRule{Required: requirePhoneVerification}
	env.svc = NewAuthService(env.userRepo, sessionRepo, passwordSvc, env.tokenSvc, otpSvc,
		mocks.NewMockPolicyService(), rdb, nil, audit, resolver,
		NewEmailAuthStrategy(env.userRepo, passwordSvc, resolver, WithStrategyPhoneVerificationPolicy(policy)),
		NewPhoneAuthStrategy(env.userRepo, passwordSvc, resolver, WithStrategyPhoneVerificationPolicy(policy)),
		WithPhoneVerificationPolicy(policy))
	return env
}

const testPassword = "Passw0rd!"

func (e *profileEnv) loginByPhone(t *testing.T, phone string) (*domain.AuthResult, error) {
	t.Helper()
	return e.svc.AuthenticateUser(context.Background(), &domain.AuthRequest{Identifier: phone, Password: testPassword})
}

// ---- users without e-mail ----

func TestRegister_WithoutEmail_UsersCoexistAndPhoneIsUnique(t *testing.T) {
	env := newProfileEnv(t, false)
	ctx := context.Background()

	u1, err := env.svc.Register(ctx, "", "+5511999990001", testPassword, "")
	if err != nil {
		t.Fatalf("first user without e-mail: %v", err)
	}
	u2, err := env.svc.Register(ctx, "", "+5511999990002", testPassword, "")
	if err != nil {
		t.Fatalf("second user without e-mail must not collide with the first: %v", err)
	}
	if u1.ID == u2.ID {
		t.Fatal("expected two distinct users")
	}

	// the same phone again: the existing "already exists" path (HTTP 409)
	if _, err := env.svc.Register(ctx, "", "+5511999990001", testPassword, ""); !errors.Is(err, domain.ErrUserAlreadyExists) {
		t.Errorf("duplicate phone must return ErrUserAlreadyExists, got %v", err)
	}
	// ... also when the second request brings an e-mail
	if _, err := env.svc.Register(ctx, "new@example.com", "+5511999990001", testPassword, ""); !errors.Is(err, domain.ErrUserAlreadyExists) {
		t.Errorf("duplicate phone with an e-mail must return ErrUserAlreadyExists, got %v", err)
	}
	// the failed attempts left no extra user behind
	if _, err := env.userRepo.FindByEmail(ctx, "new@example.com"); !errors.Is(err, domain.ErrUserNotFound) {
		t.Errorf("rejected registration must not create a user, got %v", err)
	}
}

func TestLogin_UserWithoutEmailByPhone(t *testing.T) {
	env := newProfileEnv(t, true) // strict: verify the phone first, then log in
	ctx := context.Background()
	user, err := env.svc.Register(ctx, "", "+5511999990001", testPassword, domain.RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.userRepo.ActivatePhone(ctx, user.ID); err != nil {
		t.Fatal(err)
	}

	res, err := env.loginByPhone(t, "+5511999990001")
	if err != nil {
		t.Fatalf("login by phone of a user without e-mail: %v", err)
	}
	if res.User.Email != "" || res.User.ID != user.ID {
		t.Errorf("unexpected user %+v", res.User)
	}
	claims, err := env.tokenSvc.ValidateAccessToken(res.AccessToken)
	if err != nil || claims.UserID != user.ID || claims.Role != domain.RoleClient || !claims.PhoneVerified {
		t.Errorf("claims %+v err=%v", claims, err)
	}

	// wrong password and an e-mail login attempt never match the user without e-mail
	if _, err := env.svc.AuthenticateUser(ctx, &domain.AuthRequest{Identifier: "+5511999990001", Password: "wrong"}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("wrong password: %v", err)
	}
	if _, err := env.svc.AuthenticateUser(ctx, &domain.AuthRequest{Email: "nobody@example.com", Password: testPassword}); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("unknown e-mail must be invalid credentials: %v", err)
	}
	if _, err := env.svc.Login(ctx, "", testPassword); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Errorf("legacy Login with an empty e-mail must not match the user without e-mail: %v", err)
	}
}

// ---- REQUIRE_PHONE_VERIFICATION ----

func TestPhoneVerificationSwitch_Strict(t *testing.T) {
	env := newProfileEnv(t, true)
	ctx := context.Background()

	if _, err := env.svc.Register(ctx, "a@example.com", "+5511999990001", testPassword, ""); err != nil {
		t.Fatal(err)
	}
	if env.otpCalls != 1 {
		t.Errorf("strict: registration must send one OTP, got %d", env.otpCalls)
	}
	if _, err := env.loginByPhone(t, "+5511999990001"); !errors.Is(err, domain.ErrPhoneNotVerified) {
		t.Errorf("strict: phone login of an unverified user must be refused, got %v", err)
	}
	if _, err := env.svc.AuthenticateUser(ctx, &domain.AuthRequest{Email: "a@example.com", Password: testPassword}); !errors.Is(err, domain.ErrPhoneNotVerified) {
		t.Errorf("strict: e-mail login of an unverified user must be refused, got %v", err)
	}
	if _, err := env.svc.Login(ctx, "a@example.com", testPassword); !errors.Is(err, domain.ErrPhoneNotVerified) {
		t.Errorf("strict: legacy Login of an unverified user must be refused, got %v", err)
	}

	// OTP failure still fails registration in strict mode (today's behaviour)
	env.otpErr = domain.ErrOTPResendThrottled
	if _, err := env.svc.Register(ctx, "b@example.com", "+5511999990002", testPassword, ""); !errors.Is(err, domain.ErrOTPResendThrottled) {
		t.Errorf("strict: OTP throttling must still surface, got %v", err)
	}
}

func TestPhoneVerificationSwitch_Relaxed(t *testing.T) {
	env := newProfileEnv(t, false)
	ctx := context.Background()

	// OTP sending would fail (throttled), but registration must not even try
	env.otpErr = domain.ErrOTPResendThrottled
	user, err := env.svc.Register(ctx, "a@example.com", "+5511999990001", testPassword, "")
	if err != nil {
		t.Fatalf("relaxed: registration must not fail because of OTP: %v", err)
	}
	if env.otpCalls != 0 {
		t.Errorf("relaxed: no OTP may be sent, got %d calls", env.otpCalls)
	}
	if user.PhoneVerified {
		t.Error("phone_verified must keep being stored as false")
	}

	phoneRes, err := env.loginByPhone(t, "+5511999990001")
	if err != nil {
		t.Fatalf("relaxed: unverified user must log in by phone: %v", err)
	}
	claims, err := env.tokenSvc.ValidateAccessToken(phoneRes.AccessToken)
	if err != nil || claims.PhoneVerified {
		t.Errorf("relaxed: token must carry phone_verified=false, got %+v err=%v", claims, err)
	}
	if _, err := env.svc.AuthenticateUser(ctx, &domain.AuthRequest{Email: "a@example.com", Password: testPassword}); err != nil {
		t.Errorf("relaxed: unverified user must log in by e-mail: %v", err)
	}
	if _, err := env.svc.Login(ctx, "a@example.com", testPassword); err != nil {
		t.Errorf("relaxed: legacy Login of an unverified user: %v", err)
	}

	// once the phone is verified, new tokens say so
	if err := env.userRepo.ActivatePhone(ctx, user.ID); err != nil {
		t.Fatal(err)
	}
	res, err := env.loginByPhone(t, "+5511999990001")
	if err != nil {
		t.Fatal(err)
	}
	claims, _ = env.tokenSvc.ValidateAccessToken(res.AccessToken)
	if claims == nil || !claims.PhoneVerified {
		t.Errorf("token after verification must carry phone_verified=true, got %+v", claims)
	}
}

// ---- roles ----

func TestAddProfile_PersistsRoleAndAudits(t *testing.T) {
	env := newProfileEnv(t, false)
	ctx := context.Background()
	user, _ := env.svc.Register(ctx, "", "+5511999990001", testPassword, "")

	got, err := env.svc.AddProfile(ctx, user.ID, domain.RoleClient)
	if err != nil || got.Role != domain.RoleClient {
		t.Fatalf("user -> client: %+v %v", got, err)
	}
	got, err = env.svc.AddProfile(ctx, user.ID, domain.RoleContact)
	if err != nil || got.Role != domain.RoleClientContact {
		t.Fatalf("client + contact -> client_contact: %+v %v", got, err)
	}
	stored, _ := env.userRepo.FindByID(ctx, user.ID)
	if stored.Role != domain.RoleClientContact {
		t.Errorf("role must be stored in the database, got %q", stored.Role)
	}
	if stored.CreatedAt.IsZero() {
		t.Error("the role update must not reset created_at")
	}
	changes := 0
	for _, e := range env.events {
		if e == domain.EventTypeRoleChange {
			changes++
		}
	}
	if changes != 2 {
		t.Errorf("expected 2 role_change audit events, got %d (%v)", changes, env.events)
	}

	// holding the profile already: 200 no-op, no new audit event
	before := len(env.events)
	got, err = env.svc.AddProfile(ctx, user.ID, domain.RoleClient)
	if err != nil || got.Role != domain.RoleClientContact || len(env.events) != before {
		t.Errorf("no-op: %+v %v events=%d->%d", got, err, before, len(env.events))
	}
}

func TestAddProfile_Rejections(t *testing.T) {
	env := newProfileEnv(t, false)
	ctx := context.Background()

	for _, role := range []string{domain.RoleAttendant, domain.RoleAdmin, domain.RoleRoot} {
		u := &domain.User{Phone: "+551199999" + role, PasswordHash: "h", Role: role, IsActive: true}
		if err := env.userRepo.Create(ctx, u); err != nil {
			t.Fatal(err)
		}
		if _, err := env.svc.AddProfile(ctx, u.ID, domain.RoleClient); !errors.Is(err, domain.ErrRoleTransitionNotAllowed) {
			t.Errorf("caller %s must be refused, got %v", role, err)
		}
		stored, _ := env.userRepo.FindByID(ctx, u.ID)
		if stored.Role != role {
			t.Errorf("caller %s: role must stay %s, got %s", role, role, stored.Role)
		}
	}

	user, _ := env.svc.Register(ctx, "", "+5511999990001", testPassword, "")
	for _, target := range []string{domain.RoleAttendant, domain.RoleAdmin, domain.RoleRoot, domain.RoleClientContact, "x"} {
		if _, err := env.svc.AddProfile(ctx, user.ID, target); !errors.Is(err, domain.ErrRoleTransitionNotAllowed) {
			t.Errorf("target %q must be refused, got %v", target, err)
		}
	}
	if _, err := env.svc.AddProfile(ctx, 9999, domain.RoleClient); !errors.Is(err, domain.ErrUserNotFound) {
		t.Errorf("unknown user: %v", err)
	}
}

// The role lives in the JWT: a refresh after the change must issue a token with the NEW role,
// read from the database and not copied from the old token.
func TestRefreshToken_AfterRoleChangeCarriesNewRole(t *testing.T) {
	env := newProfileEnv(t, false)
	ctx := context.Background()
	user, _ := env.svc.Register(ctx, "", "+5511999990001", testPassword, "")

	login, err := env.loginByPhone(t, "+5511999990001")
	if err != nil {
		t.Fatal(err)
	}
	old, _ := env.tokenSvc.ValidateAccessToken(login.AccessToken)
	if old.Role != domain.RoleUser {
		t.Fatalf("setup: role %q", old.Role)
	}

	if _, err := env.svc.AddProfile(ctx, user.ID, domain.RoleClient); err != nil {
		t.Fatal(err)
	}
	// the phone gets verified meanwhile: refresh must also read phone_verified from the database
	if err := env.userRepo.ActivatePhone(ctx, user.ID); err != nil {
		t.Fatal(err)
	}

	refreshed, err := env.svc.RefreshToken(ctx, login.RefreshToken)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	claims, err := env.tokenSvc.ValidateAccessToken(refreshed.AccessToken)
	if err != nil || claims.Role != domain.RoleClient || !claims.PhoneVerified {
		t.Fatalf("refreshed token must carry role client and phone_verified=true: %+v err=%v", claims, err)
	}
	if refreshed.User.Role != domain.RoleClient {
		t.Errorf("result user role %q", refreshed.User.Role)
	}

	// second change, second refresh (rotation: use the new refresh token)
	if _, err := env.svc.AddProfile(ctx, user.ID, domain.RoleContact); err != nil {
		t.Fatal(err)
	}
	refreshed, err = env.svc.RefreshToken(ctx, refreshed.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	claims, _ = env.tokenSvc.ValidateAccessToken(refreshed.AccessToken)
	if claims == nil || claims.Role != domain.RoleClientContact {
		t.Errorf("second refresh must carry client_contact, got %+v", claims)
	}
}

// ---- admin creation of the dual role ----

func TestCreateUserByAdmin_ClientContact(t *testing.T) {
	env := newProfileEnv(t, false)
	ctx := context.Background()
	root := &domain.User{ID: 1, Role: domain.RoleRoot}
	u, err := env.svc.CreateUserByAdmin(ctx, root, "", "+5511999990001", testPassword, domain.RoleClientContact)
	if err != nil || u.Role != domain.RoleClientContact {
		t.Fatalf("root creating client_contact: %+v %v", u, err)
	}
	attendant := &domain.User{ID: 2, Role: domain.RoleAttendant}
	if _, err := env.svc.CreateUserByAdmin(ctx, attendant, "", "+5511999990002", testPassword, domain.RoleClientContact); !errors.Is(err, domain.ErrRoleCreationNotAllowed) {
		t.Errorf("attendant must not create client_contact: %v", err)
	}
	if _, err := env.svc.Register(ctx, "", "+5511999990003", testPassword, domain.RoleClientContact); !errors.Is(err, domain.ErrRoleNotAllowedForRegistration) {
		t.Errorf("public registration of client_contact must be refused: %v", err)
	}
}
