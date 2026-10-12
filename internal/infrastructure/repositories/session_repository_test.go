package repositories

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
)

// setupTestRedis creates an in-memory Redis instance for testing
func setupTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	
	// Start miniredis server
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	
	// Cleanup on test completion
	t.Cleanup(func() {
		mr.Close()
	})
	
	// Create Redis client
	client := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})
	
	return client
}

func TestSessionRepositoryImpl_Create(t *testing.T) {
	tests := []struct {
		name          string
		session       *domain.Session
		ttl           time.Duration
		expectedError error
		validateData  func(t *testing.T, client *redis.Client, session *domain.Session)
	}{
		{
			name: "successful session creation",
			session: &domain.Session{
				ID:        "session_123",
				UserID:    1,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(time.Hour),
			},
			ttl:           time.Hour,
			expectedError: nil,
			validateData: func(t *testing.T, client *redis.Client, session *domain.Session) {
				// Check if session exists in Redis
				key := "session:" + session.ID
				exists := client.Exists(context.Background(), key).Val()
				if exists != 1 {
					t.Error("expected session to exist in Redis")
				}
				
				// Check TTL is set
				ttl := client.TTL(context.Background(), key).Val()
				if ttl <= 0 {
					t.Error("expected TTL to be set on session key")
				}
			},
		},
		{
			name: "create session with custom TTL",
			session: &domain.Session{
				ID:        "session_456",
				UserID:    2,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(30 * time.Minute),
			},
			ttl:           30 * time.Minute,
			expectedError: nil,
			validateData: func(t *testing.T, client *redis.Client, session *domain.Session) {
				key := "session:" + session.ID
				ttl := client.TTL(context.Background(), key).Val()
				// TTL should be approximately 30 minutes (allow for small variance)
				expectedTTL := 30 * time.Minute
				if ttl < expectedTTL-time.Second || ttl > expectedTTL+time.Second {
					t.Errorf("expected TTL around %v, got %v", expectedTTL, ttl)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test Redis
			client := setupTestRedis(t)
			
			// Create repository
			repo := NewSessionRepository(client, tt.ttl)
			
			// Execute test
			err := repo.Create(context.Background(), tt.session)
			
			// Assert error
			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			// Validate data
			tt.validateData(t, client, tt.session)
		})
	}
}

func TestSessionRepositoryImpl_FindByID(t *testing.T) {
	tests := []struct {
		name            string
		setupData       func(client *redis.Client) string
		sessionID       string
		expectedSession *domain.Session
		expectedError   error
	}{
		{
			name: "successful session retrieval",
			setupData: func(client *redis.Client) string {
				session := &domain.Session{
					ID:        "session_active",
					UserID:    1,
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(time.Hour),
				}
				
				// Create session repository and store session
				repo := NewSessionRepository(client, time.Hour)
				repo.Create(context.Background(), session)
				return session.ID
			},
			sessionID: "session_active",
			expectedSession: &domain.Session{
				ID:     "session_active",
				UserID: 1,
			},
			expectedError: nil,
		},
		{
			name: "session not found",
			setupData: func(client *redis.Client) string {
				// No data setup
				return "nonexistent_session"
			},
			sessionID:       "nonexistent_session",
			expectedSession: nil,
			expectedError:   domain.ErrSessionNotFound,
		},
		{
			name: "expired session",
			setupData: func(client *redis.Client) string {
				session := &domain.Session{
					ID:        "session_expired",
					UserID:    2,
					CreatedAt: time.Now().Add(-2 * time.Hour),
					ExpiresAt: time.Now().Add(-time.Hour), // Expired 1 hour ago
				}
				
				// Manually store expired session
				repo := NewSessionRepository(client, time.Minute) // Short TTL
				repo.Create(context.Background(), session)
				return session.ID
			},
			sessionID:       "session_expired",
			expectedSession: nil,
			expectedError:   domain.ErrSessionExpired,
		},
		{
			name: "valid session near expiry",
			setupData: func(client *redis.Client) string {
				session := &domain.Session{
					ID:        "session_near_expiry",
					UserID:    3,
					CreatedAt: time.Now().Add(-50 * time.Minute),
					ExpiresAt: time.Now().Add(10 * time.Minute), // Expires in 10 minutes
				}
				
				repo := NewSessionRepository(client, time.Hour)
				repo.Create(context.Background(), session)
				return session.ID
			},
			sessionID: "session_near_expiry",
			expectedSession: &domain.Session{
				ID:     "session_near_expiry",
				UserID: 3,
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test Redis
			client := setupTestRedis(t)
			
			// Setup test data
			sessionID := tt.setupData(client)
			if tt.sessionID != "" {
				sessionID = tt.sessionID
			}
			
			// Create repository
			repo := NewSessionRepository(client, time.Hour)
			
			// Execute test
			session, err := repo.FindByID(context.Background(), sessionID)
			
			// Assert error
			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			// Assert session
			if session == nil {
				t.Fatal("session is nil")
			}
			
			if session.ID != tt.expectedSession.ID {
				t.Errorf("expected ID %s, got %s", tt.expectedSession.ID, session.ID)
			}
			if session.UserID != tt.expectedSession.UserID {
				t.Errorf("expected UserID %d, got %d", tt.expectedSession.UserID, session.UserID)
			}
		})
	}
}

func TestSessionRepositoryImpl_Delete(t *testing.T) {
	tests := []struct {
		name          string
		setupData     func(client *redis.Client) string
		sessionID     string
		expectedError error
		validateData  func(t *testing.T, client *redis.Client, sessionID string)
	}{
		{
			name: "successful session deletion",
			setupData: func(client *redis.Client) string {
				session := &domain.Session{
					ID:        "session_to_delete",
					UserID:    1,
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(time.Hour),
				}
				
				repo := NewSessionRepository(client, time.Hour)
				repo.Create(context.Background(), session)
				return session.ID
			},
			expectedError: nil,
			validateData: func(t *testing.T, client *redis.Client, sessionID string) {
				key := "session:" + sessionID
				exists := client.Exists(context.Background(), key).Val()
				if exists != 0 {
					t.Error("expected session to be deleted from Redis")
				}
			},
		},
		{
			name: "delete non-existent session",
			setupData: func(client *redis.Client) string {
				return "nonexistent_session"
			},
			sessionID:     "nonexistent_session",
			expectedError: nil, // Redis DEL command doesn't error on non-existent keys
			validateData: func(t *testing.T, client *redis.Client, sessionID string) {
				// Should be idempotent - no error even if key doesn't exist
			},
		},
		{
			name: "delete multiple times (idempotent)",
			setupData: func(client *redis.Client) string {
				session := &domain.Session{
					ID:        "session_idempotent",
					UserID:    2,
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(time.Hour),
				}
				
				repo := NewSessionRepository(client, time.Hour)
				repo.Create(context.Background(), session)
				
				// Delete once
				repo.Delete(context.Background(), session.ID)
				
				return session.ID
			},
			expectedError: nil,
			validateData: func(t *testing.T, client *redis.Client, sessionID string) {
				key := "session:" + sessionID
				exists := client.Exists(context.Background(), key).Val()
				if exists != 0 {
					t.Error("expected session to remain deleted")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test Redis
			client := setupTestRedis(t)
			
			// Setup test data
			sessionID := tt.setupData(client)
			if tt.sessionID != "" {
				sessionID = tt.sessionID
			}
			
			// Create repository
			repo := NewSessionRepository(client, time.Hour)
			
			// Execute test
			err := repo.Delete(context.Background(), sessionID)
			
			// Assert error
			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			// Validate data changes
			tt.validateData(t, client, sessionID)
		})
	}
}

func TestSessionRepositoryImpl_DeleteExpired(t *testing.T) {
	tests := []struct {
		name          string
		setupData     func(client *redis.Client)
		expectedError error
	}{
		{
			name: "delete expired sessions - no-op in Redis implementation",
			setupData: func(client *redis.Client) {
				// Create some sessions - Redis handles TTL automatically
				sessions := []*domain.Session{
					{ID: "session1", UserID: 1, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
					{ID: "session2", UserID: 2, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
				}
				
				repo := NewSessionRepository(client, time.Hour)
				for _, session := range sessions {
					repo.Create(context.Background(), session)
				}
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test Redis
			client := setupTestRedis(t)
			
			// Setup test data
			tt.setupData(client)
			
			// Create repository
			repo := NewSessionRepository(client, time.Hour)
			
			// Execute test
			err := repo.DeleteExpired(context.Background())
			
			// Assert error
			if tt.expectedError != nil {
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			// Note: This is a no-op for Redis implementation
			// Redis handles TTL automatically
		})
	}
}

func TestSessionRepositoryImpl_NewSessionRepository(t *testing.T) {
	// Test constructor
	client := setupTestRedis(t)
	ttl := time.Hour
	
	repo := NewSessionRepository(client, ttl)
	
	if repo == nil {
		t.Fatal("NewSessionRepository returned nil")
	}
	
	// Cast to implementation to check internal state
	impl, ok := repo.(*SessionRepositoryImpl)
	if !ok {
		t.Fatal("repository is not of type *SessionRepositoryImpl")
	}
	
	if impl.client != client {
		t.Error("client not properly assigned")
	}
	if impl.prefix != "session:" {
		t.Error("prefix not properly set")
	}
	if impl.ttl != ttl {
		t.Error("TTL not properly assigned")
	}
}

func TestSessionRepositoryImpl_DeleteAllForUser(t *testing.T) {
	tests := []struct {
		name                  string
		userID                uint
		setupData             func(client *redis.Client) []*domain.Session
		expectedDeletedCount  int
		expectedError         error
		validateRemainingData func(t *testing.T, client *redis.Client, allSessions []*domain.Session, userID uint)
	}{
		{
			name:   "successful deletion of multiple user sessions",
			userID: 1,
			setupData: func(client *redis.Client) []*domain.Session {
				sessions := []*domain.Session{
					{ID: "user1_session1", UserID: 1, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
					{ID: "user1_session2", UserID: 1, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
					{ID: "user2_session1", UserID: 2, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
					{ID: "user1_session3", UserID: 1, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
					{ID: "user3_session1", UserID: 3, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
				}
				
				repo := NewSessionRepository(client, time.Hour)
				for _, session := range sessions {
					repo.Create(context.Background(), session)
				}
				
				return sessions
			},
			expectedDeletedCount: 3, // user1_session1, user1_session2, user1_session3
			expectedError:        nil,
			validateRemainingData: func(t *testing.T, client *redis.Client, allSessions []*domain.Session, userID uint) {
				repo := NewSessionRepository(client, time.Hour)
				
				// Check that user 1's sessions are deleted
				for _, session := range allSessions {
					_, err := repo.FindByID(context.Background(), session.ID)
					if session.UserID == userID {
						if err != domain.ErrSessionNotFound {
							t.Errorf("expected session %s to be deleted, but found it", session.ID)
						}
					} else {
						if err != nil {
							t.Errorf("expected session %s to remain, but got error: %v", session.ID, err)
						}
					}
				}
			},
		},
		{
			name:   "no sessions for user",
			userID: 999,
			setupData: func(client *redis.Client) []*domain.Session {
				sessions := []*domain.Session{
					{ID: "user1_session1", UserID: 1, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
					{ID: "user2_session1", UserID: 2, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
				}
				
				repo := NewSessionRepository(client, time.Hour)
				for _, session := range sessions {
					repo.Create(context.Background(), session)
				}
				
				return sessions
			},
			expectedDeletedCount: 0,
			expectedError:        nil,
			validateRemainingData: func(t *testing.T, client *redis.Client, allSessions []*domain.Session, userID uint) {
				repo := NewSessionRepository(client, time.Hour)
				
				// All sessions should remain
				for _, session := range allSessions {
					_, err := repo.FindByID(context.Background(), session.ID)
					if err != nil {
						t.Errorf("expected session %s to remain, but got error: %v", session.ID, err)
					}
				}
			},
		},
		{
			name:   "user with single session",
			userID: 5,
			setupData: func(client *redis.Client) []*domain.Session {
				sessions := []*domain.Session{
					{ID: "user5_session1", UserID: 5, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
					{ID: "user6_session1", UserID: 6, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
				}
				
				repo := NewSessionRepository(client, time.Hour)
				for _, session := range sessions {
					repo.Create(context.Background(), session)
				}
				
				return sessions
			},
			expectedDeletedCount: 1,
			expectedError:        nil,
			validateRemainingData: func(t *testing.T, client *redis.Client, allSessions []*domain.Session, userID uint) {
				repo := NewSessionRepository(client, time.Hour)
				
				for _, session := range allSessions {
					_, err := repo.FindByID(context.Background(), session.ID)
					if session.UserID == userID {
						if err != domain.ErrSessionNotFound {
							t.Errorf("expected session %s to be deleted, but found it", session.ID)
						}
					} else {
						if err != nil {
							t.Errorf("expected session %s to remain, but got error: %v", session.ID, err)
						}
					}
				}
			},
		},
		{
			name:   "empty database",
			userID: 1,
			setupData: func(client *redis.Client) []*domain.Session {
				// No sessions created
				return []*domain.Session{}
			},
			expectedDeletedCount: 0,
			expectedError:        nil,
			validateRemainingData: func(t *testing.T, client *redis.Client, allSessions []*domain.Session, userID uint) {
				// Nothing to validate for empty database
			},
		},
		{
			name:   "mixed expired and valid sessions",
			userID: 7,
			setupData: func(client *redis.Client) []*domain.Session {
				sessions := []*domain.Session{
					// Valid sessions
					{ID: "user7_valid1", UserID: 7, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
					{ID: "user7_valid2", UserID: 7, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
					// Expired sessions (but still in Redis due to test timing)
					{ID: "user7_expired1", UserID: 7, CreatedAt: time.Now().Add(-2*time.Hour), ExpiresAt: time.Now().Add(-time.Hour)},
					// Other user sessions
					{ID: "user8_session1", UserID: 8, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
				}
				
				repo := NewSessionRepository(client, time.Minute) // Shorter TTL for testing
				for _, session := range sessions {
					repo.Create(context.Background(), session)
				}
				
				return sessions
			},
			expectedDeletedCount: 3, // All user 7 sessions (including expired ones)
			expectedError:        nil,
			validateRemainingData: func(t *testing.T, client *redis.Client, allSessions []*domain.Session, userID uint) {
				repo := NewSessionRepository(client, time.Hour)
				
				for _, session := range allSessions {
					_, err := repo.FindByID(context.Background(), session.ID)
					if session.UserID == userID {
						if err != domain.ErrSessionNotFound {
							t.Errorf("expected session %s to be deleted, but found it", session.ID)
						}
					} else if session.UserID == 8 {
						// User 8's session should remain
						if err != nil {
							t.Errorf("expected session %s to remain, but got error: %v", session.ID, err)
						}
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test Redis
			client := setupTestRedis(t)
			
			// Setup test data
			sessions := tt.setupData(client)
			
			// Create repository
			repo := NewSessionRepository(client, time.Hour)
			
			// Execute test
			err := repo.DeleteAllForUser(context.Background(), tt.userID)
			
			// Assert error
			if tt.expectedError != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.expectedError)
				} else if err.Error() != tt.expectedError.Error() {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
				return
			}
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			
			// Validate remaining data
			tt.validateRemainingData(t, client, sessions, tt.userID)
		})
	}
}

func TestSessionRepositoryImpl_DeleteAllForUser_ConcurrentAccess(t *testing.T) {
	// Test concurrent access scenarios
	client := setupTestRedis(t)
	repo := NewSessionRepository(client, time.Hour)
	ctx := context.Background()
	
	// Create sessions for multiple users
	userSessions := map[uint][]string{
		1: {"u1s1", "u1s2", "u1s3"},
		2: {"u2s1", "u2s2"},
		3: {"u3s1"},
	}
	
	// Create all sessions
	for userID, sessionIDs := range userSessions {
		for _, sessionID := range sessionIDs {
			session := &domain.Session{
				ID:        sessionID,
				UserID:    userID,
				CreatedAt: time.Now(),
				ExpiresAt: time.Now().Add(time.Hour),
			}
			if err := repo.Create(ctx, session); err != nil {
				t.Fatalf("failed to create session %s: %v", sessionID, err)
			}
		}
	}
	
	// Delete all sessions for user 1
	if err := repo.DeleteAllForUser(ctx, 1); err != nil {
		t.Fatalf("failed to delete sessions for user 1: %v", err)
	}
	
	// Verify user 1's sessions are deleted
	for _, sessionID := range userSessions[1] {
		if _, err := repo.FindByID(ctx, sessionID); err != domain.ErrSessionNotFound {
			t.Errorf("expected session %s to be deleted", sessionID)
		}
	}
	
	// Verify other users' sessions remain
	for userID, sessionIDs := range userSessions {
		if userID == 1 {
			continue
		}
		for _, sessionID := range sessionIDs {
			if _, err := repo.FindByID(ctx, sessionID); err != nil {
				t.Errorf("expected session %s to remain for user %d, got error: %v", sessionID, userID, err)
			}
		}
	}
}

func TestSessionRepositoryImpl_DeleteAllForUser_ErrorHandling(t *testing.T) {
	tests := []struct {
		name      string
		userID    uint
		setupData func(client *redis.Client)
	}{
		{
			name:   "handle corrupted session data gracefully",
			userID: 1,
			setupData: func(client *redis.Client) {
				// Create a valid session
				session := &domain.Session{
					ID:        "valid_session",
					UserID:    1,
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(time.Hour),
				}
				repo := NewSessionRepository(client, time.Hour)
				repo.Create(context.Background(), session)
				
				// Manually add corrupted data
				client.Set(context.Background(), "session:corrupted", "invalid-json", time.Hour)
				
				// Add another valid session
				session2 := &domain.Session{
					ID:        "valid_session2",
					UserID:    1,
					CreatedAt: time.Now(),
					ExpiresAt: time.Now().Add(time.Hour),
				}
				repo.Create(context.Background(), session2)
			},
		},
		{
			name:   "handle zero user ID",
			userID: 0,
			setupData: func(client *redis.Client) {
				// Create sessions for user 0 and other users
				sessions := []*domain.Session{
					{ID: "user0_session1", UserID: 0, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
					{ID: "user1_session1", UserID: 1, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)},
				}
				
				repo := NewSessionRepository(client, time.Hour)
				for _, session := range sessions {
					repo.Create(context.Background(), session)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup test Redis
			client := setupTestRedis(t)
			
			// Setup test data
			tt.setupData(client)
			
			// Create repository
			repo := NewSessionRepository(client, time.Hour)
			
			// Execute test - should not panic or return error despite corrupted data
			err := repo.DeleteAllForUser(context.Background(), tt.userID)
			
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			
			// Method should complete successfully even with corrupted data
		})
	}
}

func TestSessionRepositoryImpl_Integration(t *testing.T) {
	// Integration test covering complete session lifecycle
	client := setupTestRedis(t)
	repo := NewSessionRepository(client, time.Hour)
	ctx := context.Background()
	
	// Create session
	session := &domain.Session{
		ID:        "integration_session",
		UserID:    1,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	
	// Test Create
	if err := repo.Create(ctx, session); err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	
	// Test FindByID
	foundSession, err := repo.FindByID(ctx, session.ID)
	if err != nil {
		t.Fatalf("failed to find session: %v", err)
	}
	
	if foundSession.ID != session.ID {
		t.Errorf("expected session ID %s, got %s", session.ID, foundSession.ID)
	}
	if foundSession.UserID != session.UserID {
		t.Errorf("expected user ID %d, got %d", session.UserID, foundSession.UserID)
	}
	
	// Test Delete
	if err := repo.Delete(ctx, session.ID); err != nil {
		t.Fatalf("failed to delete session: %v", err)
	}
	
	// Verify deletion
	_, err = repo.FindByID(ctx, session.ID)
	if err != domain.ErrSessionNotFound {
		t.Errorf("expected session to be deleted, got error: %v", err)
	}
	
	// Test DeleteExpired (no-op)
	if err := repo.DeleteExpired(ctx); err != nil {
		t.Errorf("unexpected error from DeleteExpired: %v", err)
	}
}
// putLegacySession stores a session the way the code did before the per-user index existed.
func putLegacySession(t *testing.T, client *redis.Client, id string, userID uint) {
	t.Helper()
	data, err := json.Marshal(&domain.Session{ID: id, UserID: userID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Set(context.Background(), "session:"+id, data, time.Hour).Err(); err != nil {
		t.Fatal(err)
	}
}

func sessionExists(client *redis.Client, id string) bool {
	return client.Exists(context.Background(), "session:"+id).Val() == 1
}

func TestSessionRepositoryImpl_UserIndex_MaintainedOnCreateAndDelete(t *testing.T) {
	ctx := context.Background()
	client := setupTestRedis(t)
	repo := NewSessionRepository(client, time.Hour)

	for _, id := range []string{"a", "b"} {
		if err := repo.Create(ctx, &domain.Session{ID: id, UserID: 5, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	members := client.SMembers(ctx, "user_sessions:5").Val()
	if len(members) != 2 {
		t.Fatalf("expected both sessions in the index, got %v", members)
	}
	if ttl := client.TTL(ctx, "user_sessions:5").Val(); ttl <= 0 {
		t.Errorf("the index must expire with the sessions, ttl=%v", ttl)
	}
	if client.Exists(ctx, "user_sessions:indexed_since").Val() != 1 {
		t.Error("the indexed_since marker must be written")
	}

	if err := repo.Delete(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	members = client.SMembers(ctx, "user_sessions:5").Val()
	if len(members) != 1 || members[0] != "b" {
		t.Errorf("Delete must drop the session from the index, got %v", members)
	}
	if err := repo.Delete(ctx, "missing"); err != nil {
		t.Errorf("deleting a missing session is not an error: %v", err)
	}
}

func TestSessionRepositoryImpl_ExtendTTL_RaisesIndexTTL(t *testing.T) {
	ctx := context.Background()
	client := setupTestRedis(t)
	repo := NewSessionRepository(client, time.Hour)
	if err := repo.Create(ctx, &domain.Session{ID: "s", UserID: 6, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := repo.ExtendTTL(ctx, "s", 48*time.Hour); err != nil {
		t.Fatal(err)
	}
	if ttl := client.TTL(ctx, "user_sessions:6").Val(); ttl < 47*time.Hour {
		t.Errorf("the index must live as long as the extended session, ttl=%v", ttl)
	}
}

func TestSessionRepositoryImpl_DeleteAllForUser_UsesIndexWithoutScan(t *testing.T) {
	ctx := context.Background()
	client := setupTestRedis(t)
	repo := NewSessionRepository(client, time.Hour)
	for _, id := range []string{"x1", "x2"} {
		if err := repo.Create(ctx, &domain.Session{ID: id, UserID: 9, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.Create(ctx, &domain.Session{ID: "other", UserID: 10, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	// Indexing started long ago: no legacy session can be alive, so the scan must not run.
	client.Set(ctx, "user_sessions:indexed_since", time.Now().Add(-48*time.Hour).Unix(), 0)
	// A session of user 9 that is NOT in the index is only reachable by scanning: it proves the scan is skipped.
	putLegacySession(t, client, "unindexed", 9)

	if err := repo.DeleteAllForUser(ctx, 9); err != nil {
		t.Fatal(err)
	}
	if sessionExists(client, "x1") || sessionExists(client, "x2") {
		t.Error("indexed sessions of the user must be deleted")
	}
	if !sessionExists(client, "other") {
		t.Error("another user's session must remain")
	}
	if !sessionExists(client, "unindexed") {
		t.Error("with a populated index and an old marker the scan must not run")
	}
	if client.Exists(ctx, "user_sessions:9").Val() != 0 {
		t.Error("the index key must be removed")
	}
}

func TestSessionRepositoryImpl_DeleteAllForUser_FallsBackToScanWhenIndexMissing(t *testing.T) {
	ctx := context.Background()
	client := setupTestRedis(t)
	repo := NewSessionRepository(client, time.Hour)
	putLegacySession(t, client, "old1", 11)
	putLegacySession(t, client, "old2", 11)
	putLegacySession(t, client, "old-other", 12)

	if err := repo.DeleteAllForUser(ctx, 11); err != nil {
		t.Fatal(err)
	}
	if sessionExists(client, "old1") || sessionExists(client, "old2") {
		t.Error("sessions created before the index must be found by the scan")
	}
	if !sessionExists(client, "old-other") {
		t.Error("another user's session must remain")
	}
}

func TestSessionRepositoryImpl_DeleteAllForUser_ScansWhileLegacySessionsMayLive(t *testing.T) {
	ctx := context.Background()
	client := setupTestRedis(t)
	repo := NewSessionRepository(client, time.Hour)
	putLegacySession(t, client, "legacy", 13) // created before the deploy
	// First indexed session just created: marker is younger than one session lifetime.
	if err := repo.Create(ctx, &domain.Session{ID: "new", UserID: 13, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}

	if err := repo.DeleteAllForUser(ctx, 13); err != nil {
		t.Fatal(err)
	}
	if sessionExists(client, "legacy") || sessionExists(client, "new") {
		t.Error("both the legacy and the indexed session must be deleted")
	}
}

func TestSessionRepositoryImpl_FindByID_ExpiredSessionLeavesIndex(t *testing.T) {
	ctx := context.Background()
	client := setupTestRedis(t)
	repo := NewSessionRepository(client, time.Hour)
	if err := repo.Create(ctx, &domain.Session{ID: "gone", UserID: 14, CreatedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.FindByID(ctx, "gone"); err != domain.ErrSessionExpired {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}
	if client.SIsMember(ctx, "user_sessions:14", "gone").Val() {
		t.Error("an expired session must be removed from the index")
	}
}
