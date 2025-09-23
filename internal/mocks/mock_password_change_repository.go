package mocks

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
)

// MockPasswordChangeRepository implements a mock for testing password change repository operations
type MockPasswordChangeRepository struct {
	CreateFunc                 func(ctx context.Context, request *domain.PasswordChangeRequest) error
	GetByIDFunc                func(ctx context.Context, id string) (*domain.PasswordChangeRequest, error)
	GetByUserIDFunc            func(ctx context.Context, userID uint, limit int) ([]*domain.PasswordChangeRequest, error)
	GetActiveByUserIDFunc      func(ctx context.Context, userID uint) (*domain.PasswordChangeRequest, error)
	UpdateFunc                 func(ctx context.Context, request *domain.PasswordChangeRequest) error
	UpdateStatusFunc           func(ctx context.Context, id string, status string, reason string) error
	UpdateOTPAttemptsFunc      func(ctx context.Context, id string, attempts int) error
	DeleteExpiredFunc          func(ctx context.Context) error
	CountActiveByUserIDFunc    func(ctx context.Context, userID uint) (int64, error)
	CountRecentByUserIDFunc    func(ctx context.Context, userID uint, since time.Time) (int64, error)
}

// NewMockPasswordChangeRepository creates a new mock password change repository
func NewMockPasswordChangeRepository() *MockPasswordChangeRepository {
	return &MockPasswordChangeRepository{
		CreateFunc: func(ctx context.Context, request *domain.PasswordChangeRequest) error {
			return nil // Default: success
		},
		GetByIDFunc: func(ctx context.Context, id string) (*domain.PasswordChangeRequest, error) {
			return &domain.PasswordChangeRequest{
				ID:          id,
				UserID:      1,
				Status:      "initiated",
				RequestedAt: time.Now(),
				ExpiresAt:   time.Now().Add(15 * time.Minute),
				Nonce:       "test-nonce",
			}, nil
		},
		GetByUserIDFunc: func(ctx context.Context, userID uint, limit int) ([]*domain.PasswordChangeRequest, error) {
			return []*domain.PasswordChangeRequest{
				{
					ID:          "test-id",
					UserID:      userID,
					Status:      "completed",
					RequestedAt: time.Now().Add(-time.Hour),
					ExpiresAt:   time.Now().Add(-45 * time.Minute),
					CompletedAt: func() *time.Time { t := time.Now().Add(-30 * time.Minute); return &t }(),
				},
			}, nil
		},
		GetActiveByUserIDFunc: func(ctx context.Context, userID uint) (*domain.PasswordChangeRequest, error) {
			return nil, nil // Default: no active request
		},
		UpdateFunc: func(ctx context.Context, request *domain.PasswordChangeRequest) error {
			return nil // Default: success
		},
		UpdateStatusFunc: func(ctx context.Context, id string, status string, reason string) error {
			return nil // Default: success
		},
		UpdateOTPAttemptsFunc: func(ctx context.Context, id string, attempts int) error {
			return nil // Default: success
		},
		DeleteExpiredFunc: func(ctx context.Context) error {
			return nil // Default: success
		},
		CountActiveByUserIDFunc: func(ctx context.Context, userID uint) (int64, error) {
			return 0, nil // Default: no active requests
		},
		CountRecentByUserIDFunc: func(ctx context.Context, userID uint, since time.Time) (int64, error) {
			return 0, nil // Default: no recent requests
		},
	}
}

// Create creates a new password change request
func (m *MockPasswordChangeRepository) Create(ctx context.Context, request *domain.PasswordChangeRequest) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, request)
	}
	return nil
}

// GetByID retrieves a password change request by ID
func (m *MockPasswordChangeRepository) GetByID(ctx context.Context, id string) (*domain.PasswordChangeRequest, error) {
	if m.GetByIDFunc != nil {
		return m.GetByIDFunc(ctx, id)
	}
	return &domain.PasswordChangeRequest{
		ID:          id,
		UserID:      1,
		Status:      "initiated",
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(15 * time.Minute),
		Nonce:       "test-nonce",
	}, nil
}

// GetByUserID retrieves password change requests for a user
func (m *MockPasswordChangeRepository) GetByUserID(ctx context.Context, userID uint, limit int) ([]*domain.PasswordChangeRequest, error) {
	if m.GetByUserIDFunc != nil {
		return m.GetByUserIDFunc(ctx, userID, limit)
	}
	return []*domain.PasswordChangeRequest{}, nil
}

// GetActiveByUserID retrieves active password change requests for a user
func (m *MockPasswordChangeRepository) GetActiveByUserID(ctx context.Context, userID uint) (*domain.PasswordChangeRequest, error) {
	if m.GetActiveByUserIDFunc != nil {
		return m.GetActiveByUserIDFunc(ctx, userID)
	}
	return nil, nil
}

// Update updates a password change request
func (m *MockPasswordChangeRepository) Update(ctx context.Context, request *domain.PasswordChangeRequest) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, request)
	}
	return nil
}

// UpdateStatus updates the status of a password change request
func (m *MockPasswordChangeRepository) UpdateStatus(ctx context.Context, id string, status string, reason string) error {
	if m.UpdateStatusFunc != nil {
		return m.UpdateStatusFunc(ctx, id, status, reason)
	}
	return nil
}

// UpdateOTPAttempts updates the OTP attempts count
func (m *MockPasswordChangeRepository) UpdateOTPAttempts(ctx context.Context, id string, attempts int) error {
	if m.UpdateOTPAttemptsFunc != nil {
		return m.UpdateOTPAttemptsFunc(ctx, id, attempts)
	}
	return nil
}

// DeleteExpired deletes expired password change requests
func (m *MockPasswordChangeRepository) DeleteExpired(ctx context.Context) error {
	if m.DeleteExpiredFunc != nil {
		return m.DeleteExpiredFunc(ctx)
	}
	return nil
}

// CountActiveByUserID counts active password change requests for a user
func (m *MockPasswordChangeRepository) CountActiveByUserID(ctx context.Context, userID uint) (int64, error) {
	if m.CountActiveByUserIDFunc != nil {
		return m.CountActiveByUserIDFunc(ctx, userID)
	}
	return 0, nil
}

// CountRecentByUserID counts recent password change requests for rate limiting
func (m *MockPasswordChangeRepository) CountRecentByUserID(ctx context.Context, userID uint, since time.Time) (int64, error) {
	if m.CountRecentByUserIDFunc != nil {
		return m.CountRecentByUserIDFunc(ctx, userID, since)
	}
	return 0, nil
}