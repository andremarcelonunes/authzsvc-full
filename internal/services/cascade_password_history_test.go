package services

import (
	"context"
	"testing"

	"github.com/you/authzsvc/internal/mocks"
)

func TestCascade_DeletePasswordHistoryReallyDeletes(t *testing.T) {
	history := mocks.NewMockPasswordHistoryRepository()
	history.CountUserHistoryFunc = func(ctx context.Context, userID uint) (int64, error) { return 3, nil }
	svc := NewCascadeDeletionService(mocks.NewMockSessionRepository(), mocks.NewMockAuditRepository(), mocks.NewMockPasswordChangeRepository(), history, mocks.NewMockForgotPasswordRepository())

	n, err := svc.DeletePasswordHistory(context.Background(), 7)
	if err != nil || n != 3 {
		t.Errorf("expected 3 deleted rows, got %d (err %v)", n, err)
	}
}
