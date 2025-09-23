package mocks

import (
	"context"
)

// MockPasswordHistoryRepository implements a mock for testing password history repository operations
type MockPasswordHistoryRepository struct {
	AddFunc                func(ctx context.Context, userID uint, passwordHash string, source string) error
	GetRecentPasswordsFunc func(ctx context.Context, userID uint, count int) ([]string, error)
	CleanupOldHistoryFunc  func(ctx context.Context, userID uint, keepCount int) error
	CountUserHistoryFunc   func(ctx context.Context, userID uint) (int64, error)
}

// NewMockPasswordHistoryRepository creates a new mock password history repository
func NewMockPasswordHistoryRepository() *MockPasswordHistoryRepository {
	return &MockPasswordHistoryRepository{
		AddFunc: func(ctx context.Context, userID uint, passwordHash string, source string) error {
			return nil // Default: success
		},
		GetRecentPasswordsFunc: func(ctx context.Context, userID uint, count int) ([]string, error) {
			return []string{
				"$2a$10$oldPasswordHash1",
				"$2a$10$oldPasswordHash2", 
			}, nil // Default: return some mock hashes
		},
		CleanupOldHistoryFunc: func(ctx context.Context, userID uint, keepCount int) error {
			return nil // Default: success
		},
		CountUserHistoryFunc: func(ctx context.Context, userID uint) (int64, error) {
			return 2, nil // Default: 2 entries in history
		},
	}
}

// Add adds a password to the user's history
func (m *MockPasswordHistoryRepository) Add(ctx context.Context, userID uint, passwordHash string, source string) error {
	if m.AddFunc != nil {
		return m.AddFunc(ctx, userID, passwordHash, source)
	}
	return nil
}

// GetRecentPasswords gets recent password hashes for a user (for reuse prevention)
func (m *MockPasswordHistoryRepository) GetRecentPasswords(ctx context.Context, userID uint, count int) ([]string, error) {
	if m.GetRecentPasswordsFunc != nil {
		return m.GetRecentPasswordsFunc(ctx, userID, count)
	}
	return []string{}, nil
}

// CleanupOldHistory removes old password history entries (keep only recent N entries)
func (m *MockPasswordHistoryRepository) CleanupOldHistory(ctx context.Context, userID uint, keepCount int) error {
	if m.CleanupOldHistoryFunc != nil {
		return m.CleanupOldHistoryFunc(ctx, userID, keepCount)
	}
	return nil
}

// CountUserHistory counts password history entries for a user
func (m *MockPasswordHistoryRepository) CountUserHistory(ctx context.Context, userID uint) (int64, error) {
	if m.CountUserHistoryFunc != nil {
		return m.CountUserHistoryFunc(ctx, userID)
	}
	return 0, nil
}