package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
	"github.com/you/authzsvc/internal/services"
)

type deletionHandlerFixture struct {
	user     *domain.User
	m        *deletionHandlerMocks
	svc      *services.UserDeletionService
	created  int
	anon     int
	sessions error
}

type deletionHandlerMocks struct {
	userRepo   *mocks.MockExtendedUserRepository
	deletion   *mocks.MockDeletionRequestRepository
	compliance *mocks.MockLGPDComplianceChecker
	session    *mocks.MockSessionRepository
	passwords  *mocks.MockPasswordService
}

func newDeletionHandlerFixture(t *testing.T, mutate func(*services.UserDeletionConfig)) *deletionHandlerFixture {
	t.Helper()
	f := &deletionHandlerFixture{
		user: &domain.User{ID: 7, Phone: "+5511999990000", PasswordHash: "hashed_secret", Role: domain.RoleUser, IsActive: true},
		m: &deletionHandlerMocks{
			userRepo:   mocks.NewMockExtendedUserRepository(),
			deletion:   mocks.NewMockDeletionRequestRepository(),
			compliance: mocks.NewMockLGPDComplianceChecker(),
			session:    mocks.NewMockSessionRepository(),
			passwords:  mocks.NewMockPasswordService(),
		},
	}
	f.m.userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) { return f.user, nil }
	f.m.userRepo.AnonymizeFunc = func(ctx context.Context, id uint, a *domain.AnonymizedUser) error { f.anon++; return nil }
	f.m.compliance.CanDeleteUserFunc = func(ctx context.Context, id uint) (bool, string, error) { return true, "", nil }
	f.m.compliance.GetRetentionRequirementsFunc = func(ctx context.Context, id uint) ([]domain.DataRetentionPolicy, error) { return nil, nil }
	f.m.deletion.CreateFunc = func(ctx context.Context, r *domain.DeletionRequest) error { f.created++; return nil }
	f.m.session.DeleteAllForUserFunc = func(ctx context.Context, id uint) error { return f.sessions }

	cfg := services.DefaultUserDeletionConfig()
	if mutate != nil {
		mutate(cfg)
	}
	f.svc = services.NewUserDeletionService(f.m.userRepo, f.m.deletion, mocks.NewMockDataExportRepository(),
		mocks.NewMockDeletionAuditRepository(), mocks.NewMockDataCascadeDeletor(), f.m.compliance,
		mocks.NewMockComprehensiveAuditService(), f.m.session, cfg,
		services.WithDeletionPasswordService(f.m.passwords))
	return f
}

func (f *deletionHandlerFixture) post(t *testing.T, body string) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("user_id", uint(7)); c.Next() })
	r.POST("/users/me/deletion", NewUserDeletionHandlers(f.svc, nil).RequestDeletion)

	req := httptest.NewRequest(http.MethodPost, "/users/me/deletion", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON (%d): %q", w.Code, w.Body.String())
	}
	return w.Code, out
}

func immediate(cfg *services.UserDeletionConfig) { cfg.SelfDeletionImmediate = true }

func data(t *testing.T, body map[string]interface{}) map[string]interface{} {
	t.Helper()
	d, ok := body["data"].(map[string]interface{})
	if !ok {
		t.Fatalf("response has no data object: %v", body)
	}
	return d
}

func TestRequestDeletionHandler_ScheduledDefaultResponseUnchanged(t *testing.T) {
	f := newDeletionHandlerFixture(t, nil)
	code, body := f.post(t, `{"deletion_type":"full_delete","reason":"I want my data erased","confirm":true}`)
	if code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %v", code, body)
	}
	d := data(t, body)
	if d["status"] != "scheduled" || d["type"] != "full_delete" || d["scheduled_for"] == nil {
		t.Errorf("unexpected data: %v", d)
	}
	if d["message"] != "Deletion request created. You have 30 days to cancel this request." {
		t.Errorf("unexpected message: %v", d["message"])
	}
	if d["lgpd_rights"] == nil || d["retention_required"] == nil || d["request_id"] == nil {
		t.Errorf("legacy keys missing: %v", d)
	}
	if f.anon != 0 {
		t.Error("nothing may be anonymised in scheduled mode")
	}
}

func TestRequestDeletionHandler_ScheduledMessageFollowsGracePeriod(t *testing.T) {
	for grace, want := range map[time.Duration]string{
		7 * 24 * time.Hour: "Deletion request created. You have 7 days to cancel this request.",
		24 * time.Hour:     "Deletion request created. You have 1 day to cancel this request.",
		36 * time.Hour:     "Deletion request created. You have 36h0m0s to cancel this request.",
		0:                  "Deletion request created.",
	} {
		f := newDeletionHandlerFixture(t, func(cfg *services.UserDeletionConfig) { cfg.GracePeriod = grace })
		_, body := f.post(t, `{"deletion_type":"anonymization","reason":"I want my data erased","confirm":true}`)
		if got := data(t, body)["message"]; got != want {
			t.Errorf("grace %v: expected %q, got %v", grace, want, got)
		}
	}
}

func TestRequestDeletionHandler_ScheduledValidationUnchanged(t *testing.T) {
	f := newDeletionHandlerFixture(t, nil)
	for name, body := range map[string]string{
		"reason too short": `{"deletion_type":"full_delete","reason":"short","confirm":true}`,
		"reason missing":   `{"deletion_type":"full_delete","confirm":true}`,
		"type missing":     `{"reason":"I want my data erased","confirm":true}`,
		"confirm false":    `{"deletion_type":"full_delete","reason":"I want my data erased","confirm":false}`,
		"bad type":         `{"deletion_type":"nuke","reason":"I want my data erased","confirm":true}`,
	} {
		code, out := f.post(t, body)
		if code != http.StatusBadRequest || out["error"] == nil {
			t.Errorf("%s: expected 400, got %d %v", name, code, out)
		}
	}
	if f.created != 0 {
		t.Error("no request may be stored for an invalid body")
	}
}

func TestRequestDeletionHandler_ScheduledSecondRequestReturnsTheOpenOne(t *testing.T) {
	f := newDeletionHandlerFixture(t, nil)
	open := &domain.DeletionRequest{ID: uuid.New(), UserID: 7, RequestType: domain.DeletionTypeAnonymization, Status: domain.DeletionStatusScheduled}
	f.m.deletion.FindByUserIDFunc = func(ctx context.Context, id uint) ([]*domain.DeletionRequest, error) {
		return []*domain.DeletionRequest{open}, nil
	}
	code, body := f.post(t, `{"deletion_type":"anonymization","reason":"I want my data erased","confirm":true}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", code, body)
	}
	if data(t, body)["request_id"] != open.ID.String() || f.created != 0 {
		t.Errorf("the open request must be returned without storing another: %v created=%d", body, f.created)
	}
}

func TestRequestDeletionHandler_ImmediateSuccess(t *testing.T) {
	f := newDeletionHandlerFixture(t, immediate)

	// Minimal body: no type, no reason.
	code, body := f.post(t, `{"confirm":true}`)
	if code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %v", code, body)
	}
	d := data(t, body)
	if len(d) != 4 || d["status"] != "completed" || d["type"] != "anonymization" || d["message"] != "Account deleted." {
		t.Errorf("unexpected data: %v", d)
	}
	if _, err := uuid.Parse(d["request_id"].(string)); err != nil {
		t.Errorf("request_id must be a uuid: %v", d["request_id"])
	}
	if f.anon != 1 {
		t.Errorf("account must be anonymised once, got %d", f.anon)
	}

	// Whatever type the client sends, the answer says anonymization.
	f = newDeletionHandlerFixture(t, immediate)
	code, body = f.post(t, `{"deletion_type":"full_delete","reason":"bye","confirm":true}`)
	if code != http.StatusOK || data(t, body)["type"] != "anonymization" {
		t.Errorf("expected 200 anonymization, got %d %v", code, body)
	}
}

func TestRequestDeletionHandler_ImmediateValidation(t *testing.T) {
	f := newDeletionHandlerFixture(t, immediate)
	for name, body := range map[string]string{
		"confirm missing": `{}`,
		"confirm false":   `{"confirm":false}`,
		"bad type":        `{"deletion_type":"nuke","confirm":true}`,
		"reason too long": `{"reason":"` + strings.Repeat("x", 501) + `","confirm":true}`,
	} {
		code, out := f.post(t, body)
		if code != http.StatusBadRequest || out["error"] == nil {
			t.Errorf("%s: expected 400, got %d %v", name, code, out)
		}
	}
	if f.anon != 0 || f.created != 0 {
		t.Error("nothing may happen for an invalid body")
	}
}

func TestRequestDeletionHandler_PasswordConfirmation(t *testing.T) {
	f := newDeletionHandlerFixture(t, func(cfg *services.UserDeletionConfig) { cfg.SelfDeletionImmediate = true; cfg.RequirePassword = true })

	for name, body := range map[string]string{
		"missing": `{"confirm":true}`,
		"wrong":   `{"confirm":true,"password":"nope"}`,
	} {
		code, out := f.post(t, body)
		if code != http.StatusUnauthorized || out["error"] != "password confirmation failed" || len(out) != 1 {
			t.Errorf("%s: expected 401 {error: password confirmation failed}, got %d %v", name, code, out)
		}
	}
	if f.anon != 0 {
		t.Error("nothing may be anonymised without the password")
	}

	code, body := f.post(t, `{"confirm":true,"password":"secret"}`)
	if code != http.StatusOK || data(t, body)["status"] != "completed" {
		t.Errorf("the right password must work: %d %v", code, body)
	}
}

func TestRequestDeletionHandler_RoleGuard(t *testing.T) {
	for _, role := range []string{domain.RoleAdmin, domain.RoleRoot, domain.RoleAttendant} {
		f := newDeletionHandlerFixture(t, immediate)
		f.user.Role = role
		code, out := f.post(t, `{"confirm":true}`)
		if code != http.StatusForbidden || out["error"] != "deletion_blocked" || out["message"] != "this kind of account cannot be deleted here" || len(out) != 2 {
			t.Errorf("%s: expected the exact 403 body, got %d %v", role, code, out)
		}
		if f.anon != 0 {
			t.Errorf("%s: nothing may be anonymised", role)
		}
	}
}

func TestRequestDeletionHandler_ComplianceBlockKeepsItsBody(t *testing.T) {
	f := newDeletionHandlerFixture(t, immediate)
	f.m.compliance.CanDeleteUserFunc = func(ctx context.Context, id uint) (bool, string, error) {
		return false, "Account too new", nil
	}
	code, out := f.post(t, `{"confirm":true}`)
	if code != http.StatusForbidden || out["error"] != "deletion_blocked" || out["message"] != "deletion blocked: Account too new" || out["lgpd_article"] == nil {
		t.Errorf("unexpected response: %d %v", code, out)
	}
}

func TestRequestDeletionHandler_ImmediateFailures(t *testing.T) {
	t.Run("nothing changed", func(t *testing.T) {
		f := newDeletionHandlerFixture(t, immediate)
		f.sessions = errors.New("redis down")
		code, out := f.post(t, `{"confirm":true}`)
		if code != http.StatusInternalServerError || out["error"] != "deletion_failed" || out["request_id"] == nil {
			t.Fatalf("unexpected response: %d %v", code, out)
		}
		if !strings.Contains(out["message"].(string), "nothing was deleted") || f.anon != 0 {
			t.Errorf("message must say nothing was deleted and nothing may be anonymised: %v anon=%d", out, f.anon)
		}
		if strings.Contains(out["message"].(string), "redis") {
			t.Error("internal error text must not leak to the client")
		}
	})

	t.Run("after anonymization", func(t *testing.T) {
		f := newDeletionHandlerFixture(t, immediate)
		calls := 0
		f.m.session.DeleteAllForUserFunc = func(ctx context.Context, id uint) error {
			calls++
			if calls == 2 {
				return errors.New("redis flapping")
			}
			return nil
		}
		code, out := f.post(t, `{"confirm":true}`)
		if code != http.StatusInternalServerError || out["error"] != "deletion_failed" || out["request_id"] == nil {
			t.Fatalf("unexpected response: %d %v", code, out)
		}
		if !strings.Contains(out["message"].(string), "Contact support") {
			t.Errorf("message must point to support: %v", out["message"])
		}
	})
}
