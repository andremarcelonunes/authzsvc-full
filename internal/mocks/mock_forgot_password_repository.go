package mocks

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
)

// MockForgotPasswordRepository implements a mock for testing forgot password repository operations
type MockForgotPasswordRepository struct {
	CreateFunc            func(ctx context.Context, request *domain.ForgotPasswordRequest) error
	GetByIDFunc           func(ctx context.Context, id string) (*domain.ForgotPasswordRequest, error)
	UpdateFunc            func(ctx context.Context, request *domain.ForgotPasswordRequest) error
	UpdateStatusFunc      func(ctx context.Context, id string, status string, reason string) error
	UpdateOTPAttemptsFunc func(ctx context.Context, id string, attempts int) error
	CountRecentByIPFunc   func(ctx context.Context, ipAddress string, since time.Time) (int64, error)
	DeleteExpiredFunc     func(ctx context.Context) error
}

// NewMockForgotPasswordRepository creates a new mock forgot password repository
func NewMockForgotPasswordRepository() *MockForgotPasswordRepository {
	return &MockForgotPasswordRepository{
		CreateFunc: func(ctx context.Context, request *domain.ForgotPasswordRequest) error {
			return nil // Default: success
		},
		GetByIDFunc: func(ctx context.Context, id string) (*domain.ForgotPasswordRequest, error) {
			userID := uint(1)
			return &domain.ForgotPasswordRequest{
				ID:          id,
				Email:       "user@example.com",
				Phone:       "+1234567890",
				UserID:      &userID,
				Status:      "initiated",
				RequestedAt: time.Now(),
				ExpiresAt:   time.Now().Add(15 * time.Minute),
				Nonce:       "test-nonce",
			}, nil
		},
		UpdateFunc: func(ctx context.Context, request *domain.ForgotPasswordRequest) error {
			return nil // Default: success
		},
		UpdateStatusFunc: func(ctx context.Context, id string, status string, reason string) error {
			return nil // Default: success
		},
		UpdateOTPAttemptsFunc: func(ctx context.Context, id string, attempts int) error {
			return nil // Default: success
		},
		CountRecentByIPFunc: func(ctx context.Context, ipAddress string, since time.Time) (int64, error) {
			return 0, nil // Default: no recent requests
		},
		DeleteExpiredFunc: func(ctx context.Context) error {
			return nil // Default: success
		},
	}
}

// Create creates a new forgot password request
func (m *MockForgotPasswordRepository) Create(ctx context.Context, request *domain.ForgotPasswordRequest) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, request)
	}
	return nil
}

// GetByID retrieves a forgot password request by ID
func (m *MockForgotPasswordRepository) GetByID(ctx context.Context, id string) (*domain.ForgotPasswordRequest, error) {
	if m.GetByIDFunc != nil {
		return m.GetByIDFunc(ctx, id)
	}
	return &domain.ForgotPasswordRequest{
		ID:          id,
		Email:       "user@example.com",
		Phone:       "+1234567890",
		Status:      "initiated",
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(15 * time.Minute),
		Nonce:       "test-nonce",
	}, nil
}

// Update updates a forgot password request
func (m *MockForgotPasswordRepository) Update(ctx context.Context, request *domain.ForgotPasswordRequest) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, request)
	}
	return nil
}

// UpdateStatus updates the status of a forgot password request
func (m *MockForgotPasswordRepository) UpdateStatus(ctx context.Context, id string, status string, reason string) error {
	if m.UpdateStatusFunc != nil {
		return m.UpdateStatusFunc(ctx, id, status, reason)
	}
	return nil
}

// UpdateOTPAttempts updates the OTP attempts count
func (m *MockForgotPasswordRepository) UpdateOTPAttempts(ctx context.Context, id string, attempts int) error {
	if m.UpdateOTPAttemptsFunc != nil {
		return m.UpdateOTPAttemptsFunc(ctx, id, attempts)
	}
	return nil
}

// CountRecentByIP counts recent forgot password requests by IP for rate limiting
func (m *MockForgotPasswordRepository) CountRecentByIP(ctx context.Context, ipAddress string, since time.Time) (int64, error) {
	if m.CountRecentByIPFunc != nil {
		return m.CountRecentByIPFunc(ctx, ipAddress, since)
	}
	return 0, nil
}

// DeleteExpired deletes expired forgot password requests
func (m *MockForgotPasswordRepository) DeleteExpired(ctx context.Context) error {
	if m.DeleteExpiredFunc != nil {
		return m.DeleteExpiredFunc(ctx)
	}
	return nil
}