package repositories

import (
	"context"
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