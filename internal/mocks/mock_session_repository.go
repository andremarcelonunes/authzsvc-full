package mocks

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
)

// MockSessionRepository implements domain.SessionRepository interface for testing
type MockSessionRepository struct {
	CreateFunc        func(ctx context.Context, session *domain.Session) error
	FindByIDFunc      func(ctx context.Context, sessionID string) (*domain.Session, error)
	DeleteFunc        func(ctx context.Context, sessionID string) error
	DeleteExpiredFunc func(ctx context.Context) error
	ExtendTTLFunc     func(ctx context.Context, sessionID string, ttl time.Duration) error
	UpdateFunc        func(ctx context.Context, session *domain.Session) error
}

// NewMockSessionRepository creates a new MockSessionRepository with default behaviors
func NewMockSessionRepository() *MockSessionRepository {
	return &MockSessionRepository{}
}

// Create creates a new session
func (m *MockSessionRepository) Create(ctx context.Context, session *domain.Session) error {
	if m.CreateFunc != nil {
		return m.CreateFunc(ctx, session)
	}
	// Default behavior: success
	return nil
}

// FindByID finds a session by ID
func (m *MockSessionRepository) FindByID(ctx context.Context, sessionID string) (*domain.Session, error) {
	if m.FindByIDFunc != nil {
		return m.FindByIDFunc(ctx, sessionID)
	}
	// Default behavior: not found
	return nil, domain.ErrSessionNotFound
}

// Delete deletes a session by ID
func (m *MockSessionRepository) Delete(ctx context.Context, sessionID string) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, sessionID)
	}
	// Default behavior: success
	return nil
}

// DeleteExpired deletes all expired sessions
func (m *MockSessionRepository) DeleteExpired(ctx context.Context) error {
	if m.DeleteExpiredFunc != nil {
		return m.DeleteExpiredFunc(ctx)
	}
	// Default behavior: success
	return nil
}

// ExtendTTL extends the TTL of a session
func (m *MockSessionRepository) ExtendTTL(ctx context.Context, sessionID string, ttl time.Duration) error {
	if m.ExtendTTLFunc != nil {
		return m.ExtendTTLFunc(ctx, sessionID, ttl)
	}
	// Default behavior: success
	return nil
}

// Update updates a session
func (m *MockSessionRepository) Update(ctx context.Context, session *domain.Session) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(ctx, session)
	}
	// Default behavior: success
	return nil
}

// Compile-time interface compliance verification
var _ domain.SessionRepository = (*MockSessionRepository)(nil)