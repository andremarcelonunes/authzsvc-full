package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
)

// SessionRepositoryImpl implements domain.SessionRepository using Redis
type SessionRepositoryImpl struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

// NewSessionRepository creates a new session repository
func NewSessionRepository(client *redis.Client, ttl time.Duration) domain.SessionRepository {
	return &SessionRepositoryImpl{
		client: client,
		prefix: "session:",
		ttl:    ttl,
	}
}

// Create implements domain.SessionRepository
func (r *SessionRepositoryImpl) Create(ctx context.Context, session *domain.Session) error {
	key := r.prefix + session.ID
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	return r.client.Set(ctx, key, data, r.ttl).Err()
}

// FindByID implements domain.SessionRepository
func (r *SessionRepositoryImpl) FindByID(ctx context.Context, sessionID string) (*domain.Session, error) {
	key := r.prefix + sessionID
	data, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, domain.ErrSessionNotFound
		}
		return nil, err
	}

	var session domain.Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	// Check if expired
	if session.ExpiresAt.Before(time.Now()) {
		// Clean up expired session
		r.client.Del(ctx, key)
		return nil, domain.ErrSessionExpired
	}

	return &session, nil
}

// Delete implements domain.SessionRepository
func (r *SessionRepositoryImpl) Delete(ctx context.Context, sessionID string) error {
	key := r.prefix + sessionID
	return r.client.Del(ctx, key).Err()
}

// DeleteExpired implements domain.SessionRepository
func (r *SessionRepositoryImpl) DeleteExpired(ctx context.Context) error {
	// Redis handles TTL automatically, so this is a no-op
	// In a database implementation, you'd scan and delete expired sessions
	return nil
}