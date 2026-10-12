package services

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/infrastructure/auth"
	"github.com/you/authzsvc/internal/infrastructure/identity"
	"github.com/you/authzsvc/internal/mocks"
)

const (
	selfDeletionPhone    = "+5511999990000"
	selfDeletionPassword = "correct horse"
)

type fakeInvalidator struct {
	calls []string
	err   error
	log   *[]string
	ids   []uint
	phone []string
}

func (f *fakeInvalidator) InvalidateAccount(ctx context.Context, userID uint, phone string) error {
	*f.log = append(*f.log, "cache.invalidate")
	f.ids = append(f.ids, userID)
	f.phone = append(f.phone, phone)
	return f.err
}

// selfDeletionFixture wires UserDeletionService over mocks and records every side effect in order.
type selfDeletionFixture struct {
	t            *testing.T
	mocks        *testDeletionServiceMocks
	svc          *UserDeletionService
	user         *domain.User
	invalidator  *fakeInvalidator
	calls        []string
	created      []*domain.DeletionRequest
	updates      []domain.DeletionRequestStatus
	audits       []*domain.DeletionAuditLog
	anonymized   *domain.AnonymizedUser
	revokeCalls  int
	passwordSvc  *mocks.MockPasswordService
}

func newSelfDeletionFixture(t *testing.T, mutate func(cfg *UserDeletionConfig)) *selfDeletionFixture {
	t.Helper()
	f := &selfDeletionFixture{t: t, mocks: createDeletionServiceMocks(t)}
	f.user = &domain.User{ID: 7, Email: "a@b.c", Phone: selfDeletionPhone, PasswordHash: "hashed_" + selfDeletionPassword, Role: domain.RoleUser, IsActive: true, CreatedAt: time.Now().Add(-72 * time.Hour)}
	f.invalidator = &fakeInvalidator{log: &f.calls}
	f.passwordSvc = mocks.NewMockPasswordService()

	m := f.mocks
	m.userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) { return f.user, nil }
	m.complianceChecker.CanDeleteUserFunc = func(ctx context.Context, id uint) (bool, string, error) { return true, "", nil }
	m.complianceChecker.GetRetentionRequirementsFunc = func(ctx context.Context, id uint) ([]domain.DataRetentionPolicy, error) {
		return nil, nil
	}
	m.deletionRepo.CreateFunc = func(ctx context.Context, r *domain.DeletionRequest) error {
		f.calls = append(f.calls, "request.create")
		f.created = append(f.created, r)
		return nil
	}
	m.deletionRepo.UpdateFunc = func(ctx context.Context, r *domain.DeletionRequest) error {
		f.calls = append(f.calls, "request.update:"+string(r.Status))
		f.updates = append(f.updates, r.Status)
		return nil
	}
	m.auditRepo.CreateFunc = func(ctx context.Context, l *domain.DeletionAuditLog) error {
		f.calls = append(f.calls, "audit:"+l.Action)
		f.audits = append(f.audits, l)
		return nil
	}
	m.sessionRepo.DeleteAllForUserFunc = func(ctx context.Context, id uint) error {
		f.revokeCalls++
		f.calls = append(f.calls, "sessions.revoke")
		return nil
	}
	m.userRepo.AnonymizeFunc = func(ctx context.Context, id uint, a *domain.AnonymizedUser) error {
		f.calls = append(f.calls, "user.anonymize")
		f.anonymized = a
		return nil
	}
	m.cascadeDeletor.DeleteOrAnonymizeAuditLogsFunc = func(ctx context.Context, id uint, anonymize bool) (int, error) {
		f.calls = append(f.calls, "audit_logs.anonymize")
		return 0, nil
	}

	cfg := DefaultUserDeletionConfig()
	if mutate != nil {
		mutate(cfg)
	}
	f.svc = NewUserDeletionService(m.userRepo, m.deletionRepo, m.exportRepo, m.auditRepo, m.cascadeDeletor,
		m.complianceChecker, m.auditService, m.sessionRepo, cfg,
		WithDeletionPasswordService(f.passwordSvc), WithAccountStateInvalidator(f.invalidator))
	return f
}

func immediateConfig(cfg *UserDeletionConfig) { cfg.SelfDeletionImmediate = true }

func (f *selfDeletionFixture) index(call string) int {
	for i, c := range f.calls {
		if c == call {
			return i
		}
	}
	return -1
}

func (f *selfDeletionFixture) has(call string) bool { return f.index(call) >= 0 }

func (f *selfDeletionFixture) request(reason, password string, typ domain.DeletionRequestType) (*domain.DeletionRequest, bool, error) {
	return f.svc.RequestSelfDeletion(context.Background(), 7, typ, reason, password)
}

func TestSelfDeletion_DefaultsKeepTheScheduledFlow(t *testing.T) {
	cfg := DefaultUserDeletionConfig()
	if cfg.SelfDeletionImmediate || cfg.RequirePassword {
		t.Fatalf("defaults must keep today's behaviour: %+v", cfg)
	}
	f := newSelfDeletionFixture(t, nil)
	if f.svc.Immediate() {
		t.Error("Immediate() must default to false")
	}
	if f.svc.GracePeriod() != 30*24*time.Hour {
		t.Errorf("unexpected grace period %v", f.svc.GracePeriod())
	}

	// No password is asked, the requested type is kept, nothing is processed.
	req, existing, err := f.request("a perfectly good reason", "", domain.DeletionTypeFullDelete)
	if err != nil || existing {
		t.Fatalf("unexpected result: existing=%v err=%v", existing, err)
	}
	if req.Status != domain.DeletionStatusScheduled || req.ScheduledFor == nil || req.RequestType != domain.DeletionTypeFullDelete {
		t.Errorf("expected a scheduled full_delete request, got %+v", req)
	}
	if f.has("sessions.revoke") || f.has("user.anonymize") {
		t.Errorf("nothing may be processed in scheduled mode: %v", f.calls)
	}
}

func TestSelfDeletion_ImmediateHappyPath(t *testing.T) {
	f := newSelfDeletionFixture(t, immediateConfig)

	req, existing, err := f.request("", "", domain.DeletionTypeFullDelete)
	if err != nil || existing {
		t.Fatalf("unexpected result: existing=%v err=%v", existing, err)
	}
	if req.Status != domain.DeletionStatusCompleted || req.CompletedAt == nil {
		t.Errorf("request must be completed: %+v", req)
	}
	if req.RequestType != domain.DeletionTypeAnonymization {
		t.Errorf("effective type must be anonymization, got %s", req.RequestType)
	}
	if req.Reason != SelfServiceDeletionReason {
		t.Errorf("reason must default to %q, got %q", SelfServiceDeletionReason, req.Reason)
	}
	if req.ScheduledFor != nil {
		t.Error("an immediate request is not scheduled")
	}

	// Order: request row, sessions revoked, THEN anonymised, then completed, then audit rows.
	create, revoke, anon, completed, auditDone := f.index("request.create"), f.index("sessions.revoke"), f.index("user.anonymize"), f.index("request.update:completed"), f.index("audit:deletion_completed")
	if !(create >= 0 && create < revoke && revoke < anon && anon < completed && completed < auditDone) {
		t.Errorf("unexpected order of calls: %v", f.calls)
	}
	if f.index("audit:deletion_requested") > revoke {
		t.Errorf("the request audit row must be written before anything destructive: %v", f.calls)
	}

	// Identifiers released, password unusable.
	if f.anonymized == nil || !strings.HasPrefix(f.anonymized.Phone, "+00000") || !strings.HasSuffix(f.anonymized.Email, "@anonymous.local") {
		t.Errorf("identifiers must be replaced: %+v", f.anonymized)
	}
	if f.anonymized.PasswordHash != domain.UnusablePasswordHash {
		t.Errorf("password must be made unusable, got %q", f.anonymized.PasswordHash)
	}

	// The requested type is in the audit metadata.
	var meta map[string]interface{}
	for _, a := range f.audits {
		if a.Action == "deletion_requested" {
			_ = json.Unmarshal(a.Metadata, &meta)
		}
	}
	if meta["requested_type"] != "full_delete" || meta["request_type"] != "anonymization" || meta["immediate"] != true {
		t.Errorf("audit metadata must record requested and effective type: %v", meta)
	}

	// Cache invalidated with the phone the user had before anonymisation.
	if len(f.invalidator.ids) != 1 || f.invalidator.ids[0] != 7 || f.invalidator.phone[0] != selfDeletionPhone {
		t.Errorf("cache must be invalidated for user 7 and %s: %+v", selfDeletionPhone, f.invalidator)
	}
	wantUpdates := []domain.DeletionRequestStatus{domain.DeletionStatusProcessing, domain.DeletionStatusCompleted}
	if len(f.updates) != 2 || f.updates[0] != wantUpdates[0] || f.updates[1] != wantUpdates[1] {
		t.Errorf("request must go processing -> completed, got %v", f.updates)
	}
}

func TestSelfDeletion_ImmediateKeepsGivenReason(t *testing.T) {
	f := newSelfDeletionFixture(t, immediateConfig)
	req, _, err := f.request("I do not use the app anymore", "", domain.DeletionTypeAnonymization)
	if err != nil || req.Reason != "I do not use the app anymore" {
		t.Errorf("a given reason must be kept: %v %+v", err, req)
	}
}

func TestSelfDeletion_SessionRevocationFailureAbortsBeforeAnonymising(t *testing.T) {
	f := newSelfDeletionFixture(t, immediateConfig)
	f.mocks.sessionRepo.DeleteAllForUserFunc = func(ctx context.Context, id uint) error {
		f.calls = append(f.calls, "sessions.revoke")
		return errors.New("redis down")
	}

	req, _, err := f.request("", "", domain.DeletionTypeAnonymization)
	var pe *DeletionProcessingError
	if !errors.As(err, &pe) || pe.Stage != "sessions" || pe.AccountChanged {
		t.Fatalf("expected a sessions-stage DeletionProcessingError with the account intact, got %v", err)
	}
	if f.has("user.anonymize") || f.has("audit_logs.anonymize") || f.has("cache.invalidate") {
		t.Errorf("nothing may be anonymised after a failed revocation: %v", f.calls)
	}
	if req.Status != domain.DeletionStatusFailed || f.updates[len(f.updates)-1] != domain.DeletionStatusFailed {
		t.Errorf("the request must be left failed: %+v", req)
	}
	if !strings.Contains(string(req.AnonymizationLog), "redis down") {
		t.Errorf("the error must be recorded on the request: %s", req.AnonymizationLog)
	}
	last := f.audits[len(f.audits)-1]
	if last.Action != "deletion_failed" || !strings.Contains(last.ErrorMessage, "redis down") {
		t.Errorf("a deletion_failed audit row with the error is expected: %+v", last)
	}
}

func TestSelfDeletion_AnonymizationFailureLeavesAccountIntact(t *testing.T) {
	f := newSelfDeletionFixture(t, immediateConfig)
	f.mocks.userRepo.AnonymizeFunc = func(ctx context.Context, id uint, a *domain.AnonymizedUser) error {
		return errors.New("tx aborted")
	}
	req, _, err := f.request("", "", domain.DeletionTypeAnonymization)
	var pe *DeletionProcessingError
	if !errors.As(err, &pe) || pe.Stage != "anonymization" || pe.AccountChanged {
		t.Fatalf("expected an anonymization-stage error with the account intact, got %v", err)
	}
	if req.Status != domain.DeletionStatusFailed {
		t.Errorf("request must be failed, got %s", req.Status)
	}
}

func TestSelfDeletion_FailureAfterAnonymizationLeavesRequestFailed(t *testing.T) {
	t.Run("second session sweep fails", func(t *testing.T) {
		f := newSelfDeletionFixture(t, immediateConfig)
		f.mocks.sessionRepo.DeleteAllForUserFunc = func(ctx context.Context, id uint) error {
			f.revokeCalls++
			if f.revokeCalls == 2 {
				return errors.New("redis flapping")
			}
			return nil
		}
		req, _, err := f.request("", "", domain.DeletionTypeAnonymization)
		var pe *DeletionProcessingError
		if !errors.As(err, &pe) || pe.Stage != "anonymization" || !pe.AccountChanged {
			t.Fatalf("expected an error flagged AccountChanged, got %v", err)
		}
		if req.Status != domain.DeletionStatusFailed || !strings.Contains(string(req.AnonymizationLog), "redis flapping") {
			t.Errorf("request must be failed with the error recorded: %+v %s", req.Status, req.AnonymizationLog)
		}
		// The anonymisation details gathered so far must not be lost.
		if !strings.Contains(string(req.AnonymizationLog), "account_changed") {
			t.Errorf("failure record missing: %s", req.AnonymizationLog)
		}
	})

	t.Run("marking the request completed fails", func(t *testing.T) {
		f := newSelfDeletionFixture(t, immediateConfig)
		f.mocks.deletionRepo.UpdateFunc = func(ctx context.Context, r *domain.DeletionRequest) error {
			f.updates = append(f.updates, r.Status)
			if r.Status == domain.DeletionStatusCompleted {
				return errors.New("db gone")
			}
			return nil
		}
		req, _, err := f.request("", "", domain.DeletionTypeAnonymization)
		var pe *DeletionProcessingError
		if !errors.As(err, &pe) || pe.Stage != "finalize" || !pe.AccountChanged {
			t.Fatalf("expected a finalize-stage error flagged AccountChanged, got %v", err)
		}
		if req.Status != domain.DeletionStatusFailed {
			t.Errorf("request must be failed, got %s", req.Status)
		}
	})
}

func TestSelfDeletion_AuditRowFailureBeforeDestructiveStepsAborts(t *testing.T) {
	f := newSelfDeletionFixture(t, immediateConfig)
	f.mocks.auditRepo.CreateFunc = func(ctx context.Context, l *domain.DeletionAuditLog) error {
		f.calls = append(f.calls, "audit:"+l.Action)
		if l.Action == "deletion_requested" {
			return errors.New("audit table locked")
		}
		return nil
	}
	_, _, err := f.request("", "", domain.DeletionTypeAnonymization)
	var pe *DeletionProcessingError
	if !errors.As(err, &pe) || pe.Stage != "audit" || pe.AccountChanged {
		t.Fatalf("expected an audit-stage error, got %v", err)
	}
	if f.has("sessions.revoke") || f.has("user.anonymize") {
		t.Errorf("nothing destructive may run without the audit trail: %v", f.calls)
	}
}

func TestSelfDeletion_AuxiliaryFailuresAreWarningsNotErrors(t *testing.T) {
	f := newSelfDeletionFixture(t, immediateConfig)
	f.invalidator.err = errors.New("redis timeout")
	f.mocks.cascadeDeletor.DeleteOrAnonymizeAuditLogsFunc = func(ctx context.Context, id uint, anonymize bool) (int, error) {
		return 0, errors.New("audit repo busy")
	}
	req, _, err := f.request("", "", domain.DeletionTypeAnonymization)
	if err != nil || req.Status != domain.DeletionStatusCompleted {
		t.Fatalf("the deletion must still complete: %v %+v", err, req)
	}
	log := string(req.AnonymizationLog)
	if !strings.Contains(log, "redis timeout") || !strings.Contains(log, "audit repo busy") {
		t.Errorf("warnings must be recorded on the request: %s", log)
	}
}

func TestSelfDeletion_PasswordConfirmation(t *testing.T) {
	both := func(cfg *UserDeletionConfig) { cfg.RequirePassword = true }
	both2 := func(cfg *UserDeletionConfig) { cfg.RequirePassword = true; cfg.SelfDeletionImmediate = true }
	for name, mutate := range map[string]func(*UserDeletionConfig){"scheduled": both, "immediate": both2} {
		t.Run(name+"/missing", func(t *testing.T) {
			f := newSelfDeletionFixture(t, mutate)
			if _, _, err := f.request("a perfectly good reason", "", domain.DeletionTypeAnonymization); !errors.Is(err, domain.ErrDeletionPasswordConfirmation) {
				t.Fatalf("expected ErrDeletionPasswordConfirmation, got %v", err)
			}
			if len(f.created) != 0 || f.has("user.anonymize") {
				t.Errorf("nothing may happen without the password: %v", f.calls)
			}
		})
		t.Run(name+"/wrong", func(t *testing.T) {
			f := newSelfDeletionFixture(t, mutate)
			if _, _, err := f.request("a perfectly good reason", "nope", domain.DeletionTypeAnonymization); !errors.Is(err, domain.ErrDeletionPasswordConfirmation) {
				t.Fatalf("expected ErrDeletionPasswordConfirmation, got %v", err)
			}
			if len(f.created) != 0 {
				t.Error("no request may be stored")
			}
		})
		t.Run(name+"/right", func(t *testing.T) {
			f := newSelfDeletionFixture(t, mutate)
			if _, _, err := f.request("a perfectly good reason", selfDeletionPassword, domain.DeletionTypeAnonymization); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(f.created) != 1 {
				t.Error("a request must be stored")
			}
		})
	}

	t.Run("switch off: a wrong password is not even looked at", func(t *testing.T) {
		f := newSelfDeletionFixture(t, nil)
		f.passwordSvc.VerifyFunc = func(h, p string) bool { t.Error("Verify must not be called"); return false }
		if _, _, err := f.request("a perfectly good reason", "whatever", domain.DeletionTypeAnonymization); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("no password service wired fails closed", func(t *testing.T) {
		f := newSelfDeletionFixture(t, both)
		f.svc.passwordService = nil
		if _, _, err := f.request("a perfectly good reason", selfDeletionPassword, domain.DeletionTypeAnonymization); !errors.Is(err, domain.ErrDeletionPasswordConfirmation) {
			t.Fatalf("expected ErrDeletionPasswordConfirmation, got %v", err)
		}
	})
}

func TestSelfDeletion_RoleGuardOnlyInImmediateMode(t *testing.T) {
	for _, role := range []string{domain.RoleAdmin, domain.RoleRoot, domain.RoleAttendant} {
		t.Run(role+"/immediate", func(t *testing.T) {
			f := newSelfDeletionFixture(t, immediateConfig)
			f.user.Role = role
			_, _, err := f.request("", "", domain.DeletionTypeAnonymization)
			if !errors.Is(err, domain.ErrDeletionRoleBlocked) {
				t.Fatalf("expected ErrDeletionRoleBlocked, got %v", err)
			}
			if len(f.created) != 0 || f.has("sessions.revoke") || f.has("user.anonymize") {
				t.Errorf("nothing may happen: %v", f.calls)
			}
		})
		t.Run(role+"/scheduled still allowed", func(t *testing.T) {
			f := newSelfDeletionFixture(t, nil)
			f.user.Role = role
			req, _, err := f.request("a perfectly good reason", "", domain.DeletionTypeAnonymization)
			if err != nil || req.Status != domain.DeletionStatusScheduled {
				t.Fatalf("the scheduled flow stays open to this role: %v %+v", err, req)
			}
		})
	}
	for _, role := range []string{domain.RoleUser, domain.RoleClient, domain.RoleContact} {
		t.Run(role+"/immediate allowed", func(t *testing.T) {
			f := newSelfDeletionFixture(t, immediateConfig)
			f.user.Role = role
			if _, _, err := f.request("", "", domain.DeletionTypeAnonymization); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestSelfDeletion_ComplianceBlockStillApplies(t *testing.T) {
	f := newSelfDeletionFixture(t, immediateConfig)
	f.mocks.complianceChecker.CanDeleteUserFunc = func(ctx context.Context, id uint) (bool, string, error) {
		return false, "Account too new: 1h0m0s old, minimum 24h0m0s required", nil
	}
	_, _, err := f.request("", "", domain.DeletionTypeAnonymization)
	if err == nil || !strings.HasPrefix(err.Error(), "deletion blocked: ") {
		t.Fatalf("expected a deletion blocked error, got %v", err)
	}
	if len(f.created) != 0 || f.has("user.anonymize") {
		t.Errorf("nothing may happen: %v", f.calls)
	}
}

// The minimum account age is a switch of the compliance checker: refused while young, allowed with 0.
func TestLGPDCompliance_MinimumAccountAge(t *testing.T) {
	young := &domain.User{ID: 1, IsActive: true, CreatedAt: time.Now().Add(-time.Hour)}
	check := func(minAge time.Duration) (bool, string) {
		userRepo := mocks.NewMockUserRepository()
		userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) { return young, nil }
		cfg := &LGPDComplianceConfig{MinimumAccountAge: minAge}
		ok, reason, err := NewLGPDComplianceService(userRepo, mocks.NewMockAuditRepository(), cfg).CanDeleteUser(context.Background(), 1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return ok, reason
	}
	if ok, reason := check(24 * time.Hour); ok || !strings.Contains(reason, "Account too new") {
		t.Errorf("a 1h old account must be refused with a 24h minimum: %v %q", ok, reason)
	}
	if ok, reason := check(0); !ok {
		t.Errorf("a 1h old account must be allowed with a minimum of 0: %q", reason)
	}
	if ok, _ := check(30 * time.Minute); !ok {
		t.Error("a 1h old account must be allowed with a 30m minimum")
	}
}

func TestSelfDeletion_ScheduledModeReturnsTheOpenRequest(t *testing.T) {
	f := newSelfDeletionFixture(t, nil)
	open := &domain.DeletionRequest{ID: uuid.New(), UserID: 7, Status: domain.DeletionStatusScheduled}
	f.mocks.deletionRepo.FindByUserIDFunc = func(ctx context.Context, id uint) ([]*domain.DeletionRequest, error) {
		return []*domain.DeletionRequest{open}, nil
	}
	req, existing, err := f.request("a perfectly good reason", "", domain.DeletionTypeAnonymization)
	if err != nil || !existing || req.ID != open.ID || len(f.created) != 0 {
		t.Errorf("expected the open request back (existing=true), got %+v existing=%v err=%v", req, existing, err)
	}

	f.mocks.deletionRepo.FindByUserIDFunc = func(ctx context.Context, id uint) ([]*domain.DeletionRequest, error) {
		return nil, errors.New("db down")
	}
	if _, _, err := f.request("a perfectly good reason", "", domain.DeletionTypeAnonymization); err == nil {
		t.Error("a failure to look up open requests must not be ignored")
	}
}

func TestSelfDeletion_ImmediateModeDoesNotLookForOpenRequests(t *testing.T) {
	f := newSelfDeletionFixture(t, immediateConfig)
	f.mocks.deletionRepo.FindByUserIDFunc = func(ctx context.Context, id uint) ([]*domain.DeletionRequest, error) {
		t.Error("FindByUserID must not be called in immediate mode")
		return nil, nil
	}
	if _, _, err := f.request("", "", domain.DeletionTypeAnonymization); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The admin / scheduled anonymisation path makes the password unusable too, and still works
// without the optional collaborators.
func TestAnonymizeUser_MakesPasswordUnusable(t *testing.T) {
	f := newSelfDeletionFixture(t, nil)
	if err := f.svc.AnonymizeUser(context.Background(), 7, false); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.anonymized == nil || f.anonymized.PasswordHash != domain.UnusablePasswordHash {
		t.Errorf("password must be made unusable: %+v", f.anonymized)
	}
	if len(f.invalidator.ids) != 1 || f.invalidator.phone[0] != selfDeletionPhone {
		t.Errorf("cached state must be dropped on this path too: %+v", f.invalidator)
	}

	bare := createDeletionServiceForTest(t, createDeletionServiceMocks(t))
	if err := bare.AnonymizeUser(context.Background(), 8, false); err != nil {
		t.Errorf("anonymisation without invalidator or password service must still work: %v", err)
	}
}

func TestUnusablePasswordHashNeverVerifies(t *testing.T) {
	// The repository writes this marker; bcrypt must reject it for every input.
	for _, candidate := range []string{"", "!", domain.UnusablePasswordHash, selfDeletionPassword} {
		if auth.NewPasswordService().Verify(domain.UnusablePasswordHash, candidate) {
			t.Errorf("the marker must never match %q", candidate)
		}
	}
}

// Pins the Redis key formats of identity.AccountInvalidator to the ones OTPServiceImpl writes.
func TestAccountInvalidator_RemovesTheKeysTheOTPServiceWrites(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	ctx := context.Background()

	userRepo := mocks.NewMockUserRepository()
	notifications := mocks.NewMockNotificationService()
	otp := NewOTPService(notifications, userRepo, rdb, OTPConfig{Length: 6, TTL: time.Minute, MaxAttempts: 3, ResendWindow: time.Minute})
	if _, err := otp.Generate(ctx, selfDeletionPhone, 7); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	rdb.Set(ctx, "otp:att:"+selfDeletionPhone+":7", "1", time.Minute)
	rdb.Set(ctx, identity.KeyPrefix+"7", "1:220", time.Minute)
	rdb.Set(ctx, identity.KeyPrefix+"8", "1:221", time.Minute) // another user: must stay
	rdb.Set(ctx, "otp:"+selfDeletionPhone+":8", "x", time.Minute)

	if err := identity.NewAccountInvalidator(rdb).InvalidateAccount(ctx, 7, selfDeletionPhone); err != nil {
		t.Fatal(err)
	}
	for _, key := range mr.Keys() {
		if key == identity.KeyPrefix+"8" || key == "otp:"+selfDeletionPhone+":8" {
			continue
		}
		t.Errorf("key %s of user 7 survived the invalidation", key)
	}
	if !mr.Exists(identity.KeyPrefix+"8") || !mr.Exists("otp:"+selfDeletionPhone+":8") {
		t.Error("another user's keys must stay")
	}
}

// In production the audit-log retention policy always applies, which already turns full_delete into
// anonymization; the audit row must still say what the client asked for.
func TestSelfDeletion_RetentionDowngradeKeepsTheClientsRequestedType(t *testing.T) {
	f := newSelfDeletionFixture(t, immediateConfig)
	f.mocks.complianceChecker.GetRetentionRequirementsFunc = func(ctx context.Context, id uint) ([]domain.DataRetentionPolicy, error) {
		return []domain.DataRetentionPolicy{{DataType: "audit_logs", RetentionPeriod: time.Hour, LegalBasis: "LGPD Article 16"}}, nil
	}
	req, _, err := f.request("", "", domain.DeletionTypeFullDelete)
	if err != nil || req.RequestType != domain.DeletionTypeAnonymization || !req.RetentionRequired {
		t.Fatalf("unexpected result: %v %+v", err, req)
	}
	var meta map[string]interface{}
	for _, a := range f.audits {
		if a.Action == "deletion_requested" {
			_ = json.Unmarshal(a.Metadata, &meta)
		}
	}
	if meta["requested_type"] != "full_delete" {
		t.Errorf("the audit row must keep the type the client sent: %v", meta)
	}
}
