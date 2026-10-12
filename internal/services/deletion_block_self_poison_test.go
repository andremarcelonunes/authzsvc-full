package services

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// One refused deletion (account too young) must not block the person once the account is old enough.
func TestSelfDeletion_RefusedOnceForAgeIsAllowedWhenOldEnough(t *testing.T) {
	var mu sync.Mutex
	var events []*domain.ComprehensiveAuditEvent
	auditRepo := mocks.NewMockAuditRepository()
	auditRepo.CreateFunc = func(ctx context.Context, e *domain.ComprehensiveAuditEvent) error {
		mu.Lock()
		defer mu.Unlock()
		events = append(events, e)
		return nil
	}
	auditRepo.FindByUserIDFunc = func(ctx context.Context, userID uint, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
		mu.Lock()
		defer mu.Unlock()
		var out []*domain.ComprehensiveAuditEvent
		for _, e := range events {
			if e.UserID != nil && *e.UserID == userID {
				out = append(out, e)
			}
		}
		return out, nil
	}
	auditSvc := NewComprehensiveAuditService(auditRepo, nil, nil, nil, nil, nil, nil, nil)

	user := &domain.User{ID: 7, Role: domain.RoleUser, IsActive: true, CreatedAt: time.Now().Add(-time.Hour)}
	userRepo := mocks.NewMockExtendedUserRepository()
	userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) { return user, nil }
	compliance := NewLGPDComplianceService(userRepo, auditRepo, &LGPDComplianceConfig{MinimumAccountAge: 24 * time.Hour})

	m := createDeletionServiceMocks(t)
	svc := NewUserDeletionService(userRepo, m.deletionRepo, m.exportRepo, m.auditRepo, m.cascadeDeletor, compliance, auditSvc, m.sessionRepo, DefaultUserDeletionConfig())

	_, _, err := svc.RequestSelfDeletion(context.Background(), 7, domain.DeletionTypeAnonymization, "a perfectly good reason", "")
	if err == nil || !strings.Contains(err.Error(), "Account too new") {
		t.Fatalf("expected the young account to be refused, got %v", err)
	}

	user.CreatedAt = time.Now().Add(-48 * time.Hour) // the account grows up
	if _, _, err := svc.RequestSelfDeletion(context.Background(), 7, domain.DeletionTypeAnonymization, "a perfectly good reason", ""); err != nil {
		t.Fatalf("once old enough the request must be accepted, got %v", err)
	}
}

// Events written by the deletion flow before this fix (security category, action deletion_blocked) are ignored too.
func TestLGPDCompliance_IgnoresDeletionFlowSecurityEvents(t *testing.T) {
	uid := uint(7)
	auditRepo := mocks.NewMockAuditRepository()
	auditRepo.FindByUserIDFunc = func(ctx context.Context, userID uint, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
		return []*domain.ComprehensiveAuditEvent{{
			EventType: domain.EventTypeSecurityViolation, EventCategory: domain.CategoryAuditSecurity,
			Action: "deletion_blocked", UserID: &uid, Timestamp: time.Now().Add(-time.Hour),
		}}, nil
	}
	userRepo := mocks.NewMockUserRepository()
	userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
		return &domain.User{ID: 7, IsActive: true, CreatedAt: time.Now().Add(-100 * time.Hour)}, nil
	}
	ok, reason, err := NewLGPDComplianceService(userRepo, auditRepo, &LGPDComplianceConfig{}).CanDeleteUser(context.Background(), 7)
	if err != nil || !ok {
		t.Errorf("a deletion-flow event must not count as a security incident: ok=%v reason=%q err=%v", ok, reason, err)
	}

	// A real incident still blocks.
	auditRepo.FindByUserIDFunc = func(ctx context.Context, userID uint, limit, offset int) ([]*domain.ComprehensiveAuditEvent, error) {
		return []*domain.ComprehensiveAuditEvent{{
			EventType: domain.EventTypeSuspiciousActivity, EventCategory: domain.CategoryAuditSecurity,
			Action: "suspicious_activity", UserID: &uid, Timestamp: time.Now().Add(-time.Hour),
		}}, nil
	}
	if ok, _, _ := NewLGPDComplianceService(userRepo, auditRepo, &LGPDComplianceConfig{}).CanDeleteUser(context.Background(), 7); ok {
		t.Error("a real security incident must still block deletion")
	}
}
