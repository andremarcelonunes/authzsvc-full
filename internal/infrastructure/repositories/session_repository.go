package repositories

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
)

// SessionRepositoryImpl implements domain.SessionRepository using Redis
//
// Besides session:<id> it keeps a per-user index, the Redis set user_sessions:<userID> holding the
// ids of that user's sessions, so DeleteAllForUser does not have to scan every session key.
// The marker key user_sessions:indexed_since records when the first indexed session was created;
// sessions older than that are not in any set (see DeleteAllForUser).
type SessionRepositoryImpl struct {
	client *redis.Client
	prefix string
	ttl    time.Duration
}

const (
	userSessionsPrefix      = "user_sessions:"
	userSessionsSinceMarker = "user_sessions:indexed_since"
)

func userSessionsKey(userID uint) string {
	return fmt.Sprintf("%s%d", userSessionsPrefix, userID)
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

	idx := userSessionsKey(session.UserID)
	pipe := r.client.TxPipeline()
	pipe.Set(ctx, key, data, r.ttl)
	pipe.SAdd(ctx, idx, session.ID)
	// The set must outlive its newest session; ExtendTTL raises it when a session is extended.
	pipe.Expire(ctx, idx, r.ttl)
	pipe.SetNX(ctx, userSessionsSinceMarker, time.Now().Unix(), 0)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("failed to store session: %w", err)
	}
	return nil
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
		r.client.SRem(ctx, userSessionsKey(session.UserID), sessionID)
		return nil, domain.ErrSessionExpired
	}

	return &session, nil
}

// Delete implements domain.SessionRepository
func (r *SessionRepositoryImpl) Delete(ctx context.Context, sessionID string) error {
	key := r.prefix + sessionID
	// Read the session first to know which user index to update; a missing or unreadable
	// session is still deleted (a stale index member is harmless: DEL of a missing key).
	if session, err := r.readSession(ctx, key); err == nil {
		pipe := r.client.TxPipeline()
		pipe.Del(ctx, key)
		pipe.SRem(ctx, userSessionsKey(session.UserID), sessionID)
		_, err := pipe.Exec(ctx)
		return err
	}
	return r.client.Del(ctx, key).Err()
}

func (r *SessionRepositoryImpl) readSession(ctx context.Context, key string) (*domain.Session, error) {
	data, err := r.client.Get(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	var session domain.Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, err
	}
	return &session, nil
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

	// Keep the user index alive at least as long as the extended session.
	if session, err := r.readSession(ctx, key); err == nil {
		idx := userSessionsKey(session.UserID)
		if current, err := r.client.TTL(ctx, idx).Result(); err == nil && current < ttl {
			r.client.Expire(ctx, idx, ttl)
		}
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

// DeleteAllForUser implements domain.SessionRepository.
//
// It deletes the sessions listed in the user index (user_sessions:<id>) and the index itself.
// It also falls back to scanning every session key, which is the only way to find sessions
// created before the index existed, when the index is missing or empty (it may have been
// evicted) or when indexing started less than one session lifetime ago (a legacy session may
// still be alive next to indexed ones).
func (r *SessionRepositoryImpl) DeleteAllForUser(ctx context.Context, userID uint) error {
	idx := userSessionsKey(userID)
	ids, err := r.client.SMembers(ctx, idx).Result()
	if err != nil {
		return fmt.Errorf("failed to read session index for user %d: %w", userID, err)
	}

	keys := make([]string, 0, len(ids)+1)
	for _, id := range ids {
		keys = append(keys, r.prefix+id)
	}

	if len(ids) == 0 || r.legacySessionsMayExist(ctx) {
		scanned, err := r.scanSessionKeysForUser(ctx, userID)
		if err != nil {
			return err
		}
		keys = append(keys, scanned...)
	}

	keys = append(keys, idx)
	if err := r.client.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("failed to delete sessions for user %d: %w", userID, err)
	}
	return nil
}

// legacySessionsMayExist reports whether sessions created before the index may still be alive:
// true when the marker is missing/unreadable or younger than the session lifetime.
func (r *SessionRepositoryImpl) legacySessionsMayExist(ctx context.Context) bool {
	raw, err := r.client.Get(ctx, userSessionsSinceMarker).Result()
	if err != nil {
		return true
	}
	since, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return true
	}
	return time.Since(time.Unix(since, 0)) < r.ttl
}

// scanSessionKeysForUser walks every session key and returns those that belong to userID.
func (r *SessionRepositoryImpl) scanSessionKeysForUser(ctx context.Context, userID uint) ([]string, error) {
	iter := r.client.Scan(ctx, 0, r.prefix+"*", 0).Iterator()

	var keys []string
	for iter.Next(ctx) {
		key := iter.Val()
		session, err := r.readSession(ctx, key)
		if err != nil {
			continue // expired meanwhile or not a session
		}
		if session.UserID == userID {
			keys = append(keys, key)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan session keys: %w", err)
	}
	return keys, nil
}
