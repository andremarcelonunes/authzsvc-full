package services

import (
	"context"
	"errors"
	"testing"

	"github.com/you/authzsvc/internal/mocks"
)

func TestCascade_DeletePasswordHistoryReallyDeletes(t *testing.T) {
	history := mocks.NewMockPasswordHistoryRepository()
	var deletedFor uint
	history.DeleteAllForUserFunc = func(ctx context.Context, userID uint) (int64, error) { deletedFor = userID; return 3, nil }
	svc := NewCascadeDeletionService(mocks.NewMockSessionRepository(), mocks.NewMockAuditRepository(), mocks.NewMockPasswordChangeRepository(), history, mocks.NewMockForgotPasswordRepository())

	n, err := svc.DeletePasswordHistory(context.Background(), 7)
	if err != nil || n != 3 {
		t.Errorf("expected 3 deleted rows, got %d (err %v)", n, err)
	}
	if deletedFor != 7 {
		t.Errorf("the repository must be asked to delete user 7's history, got %d", deletedFor)
	}
}

func TestCascade_DeletePasswordHistoryReportsRepositoryErrors(t *testing.T) {
	history := mocks.NewMockPasswordHistoryRepository()
	history.DeleteAllForUserFunc = func(ctx context.Context, userID uint) (int64, error) { return 0, errors.New("db down") }
	svc := NewCascadeDeletionService(mocks.NewMockSessionRepository(), mocks.NewMockAuditRepository(), mocks.NewMockPasswordChangeRepository(), history, mocks.NewMockForgotPasswordRepository())
	if _, err := svc.DeletePasswordHistory(context.Background(), 7); err == nil {
		t.Error("a repository failure must be returned")
	}
}
