package services

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
)

// A second POST /users/me/deletion while one request is still open must hand back that request,
// not store another one (scheduled mode).
func TestUserDeletionService_RequestDeletion_DoesNotStackOpenRequests(t *testing.T) {
	for _, status := range []domain.DeletionRequestStatus{domain.DeletionStatusPending, domain.DeletionStatusScheduled} {
		t.Run(string(status), func(t *testing.T) {
			mocks := createDeletionServiceMocks(t)
			setupSuccessfulDeletionRequest(t, mocks, 42)
			open := &domain.DeletionRequest{ID: uuid.New(), UserID: 42, RequestType: domain.DeletionTypeAnonymization, Status: status}
			mocks.deletionRepo.FindByUserIDFunc = func(ctx context.Context, userID uint) ([]*domain.DeletionRequest, error) {
				return []*domain.DeletionRequest{
					{ID: uuid.New(), UserID: 42, Status: domain.DeletionStatusCancelled},
					open,
				}, nil
			}
			created := 0
			mocks.deletionRepo.CreateFunc = func(ctx context.Context, request *domain.DeletionRequest) error {
				created++
				return nil
			}
			service := createDeletionServiceForTest(t, mocks)

			got, err := service.RequestDeletion(context.Background(), 42, domain.DeletionTypeFullDelete, "second tap on the button")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if created != 0 {
				t.Errorf("a second request was stacked (%d created)", created)
			}
			if got == nil || got.ID != open.ID {
				t.Errorf("expected the open request %s back, got %+v", open.ID, got)
			}
		})
	}
}

// Closed requests (cancelled, failed, completed) do not count as open.
func TestUserDeletionService_RequestDeletion_ClosedRequestsDoNotBlockANewOne(t *testing.T) {
	mocks := createDeletionServiceMocks(t)
	setupSuccessfulDeletionRequest(t, mocks, 43)
	mocks.deletionRepo.FindByUserIDFunc = func(ctx context.Context, userID uint) ([]*domain.DeletionRequest, error) {
		return []*domain.DeletionRequest{
			{ID: uuid.New(), UserID: 43, Status: domain.DeletionStatusCancelled},
			{ID: uuid.New(), UserID: 43, Status: domain.DeletionStatusFailed},
		}, nil
	}
	created := 0
	mocks.deletionRepo.CreateFunc = func(ctx context.Context, request *domain.DeletionRequest) error {
		created++
		return nil
	}
	service := createDeletionServiceForTest(t, mocks)

	if _, err := service.RequestDeletion(context.Background(), 43, domain.DeletionTypeAnonymization, "changed my mind again"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created != 1 {
		t.Errorf("expected one new request, got %d", created)
	}
}
