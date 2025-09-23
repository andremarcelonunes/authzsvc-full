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

// ExtendTTL implements domain.SessionRepository
func (r *SessionRepositoryImpl) ExtendTTL(ctx context.Context, sessionID string, ttl time.Duration) error {
	key := r.prefix + sessionID
	
	// Check if session exists first
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check session existence: %w", err)
	}
	
	if exists == 0 {
		return domain.ErrSessionNotFound
	}
	
	// Extend TTL
	success, err := r.client.Expire(ctx, key, ttl).Result()
	if err != nil {
		return fmt.Errorf("failed to extend session TTL: %w", err)
	}
	
	if !success {
		return domain.ErrSessionNotFound
	}
	
	return nil
}

// Update implements domain.SessionRepository
func (r *SessionRepositoryImpl) Update(ctx context.Context, session *domain.Session) error {
	key := r.prefix + session.ID
	
	// Check if session exists
	exists, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check session existence: %w", err)
	}
	
	if exists == 0 {
		return domain.ErrSessionNotFound
	}
	
	// Update session data with current TTL
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}
	
	// Keep existing TTL when updating
	ttl, err := r.client.TTL(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to get session TTL: %w", err)
	}
	
	return r.client.Set(ctx, key, data, ttl).Err()
}

// DeleteAllForUser implements domain.SessionRepository
func (r *SessionRepositoryImpl) DeleteAllForUser(ctx context.Context, userID uint) error {
	// Get all session keys using pattern matching
	pattern := r.prefix + "*"
	iter := r.client.Scan(ctx, 0, pattern, 0).Iterator()
	
	var keysToDelete []string
	
	// Iterate through all session keys
	for iter.Next(ctx) {
		key := iter.Val()
		
		// Get session data
		data, err := r.client.Get(ctx, key).Result()
		if err != nil {
			if err == redis.Nil {
				continue // Session expired or already deleted
			}
			// Log error but continue processing other sessions
			continue
		}
		
		// Unmarshal session to check user ID
		var session domain.Session
		if err := json.Unmarshal([]byte(data), &session); err != nil {
			// Log error but continue processing other sessions
			continue
		}
		
		// If this session belongs to the target user, mark for deletion
		if session.UserID == userID {
			keysToDelete = append(keysToDelete, key)
		}
	}
	
	// Check for scan errors
	if err := iter.Err(); err != nil {
		return fmt.Errorf("failed to scan session keys: %w", err)
	}
	
	// Delete all sessions for the user
	if len(keysToDelete) > 0 {
		if err := r.client.Del(ctx, keysToDelete...).Err(); err != nil {
			return fmt.Errorf("failed to delete sessions for user %d: %w", userID, err)
		}
	}
	
	return nil
}