package services

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/infrastructure/auth"
	"github.com/you/authzsvc/internal/infrastructure/repositories"
	"github.com/you/authzsvc/internal/mocks"
)

// sessionHarness wires the real session repository, the real JWT service and a real (mini) Redis.
type sessionHarness struct {
	t        *testing.T
	mr       *miniredis.Miniredis
	rdb      *redis.Client
	repo     domain.SessionRepository
	tokens   domain.TokenService
	svc      domain.AuthService
	user     *domain.User
	refTTL   time.Duration
	userRepo *mocks.MockUserRepository
}

func newSessionHarness(t *testing.T, policy domain.SessionPolicy, refreshTTL time.Duration) *sessionHarness {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1, DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = rdb.Close() })

	user := createValidUser(t)
	userRepo := mocks.NewMockUserRepository()
	userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) { return user, nil }

	tokens := auth.NewJWTService("test-secret-test-secret-test-secret", "authzsvc-test", 15*time.Minute, refreshTTL)
	repo := repositories.NewSessionRepository(rdb, refreshTTL)
	svc := NewAuthService(userRepo, repo, mocks.NewMockPasswordService(), tokens, mocks.NewMockOTPService(), mocks.NewMockPolicyService(),
		rdb, mocks.NewMockRequestValidationService(), mocks.NewMockComprehensiveAuditService(), mocks.NewMockIdentifierResolutionService(),
		mocks.NewMockEmailAuthenticationStrategy(), mocks.NewMockPhoneAuthenticationStrategy(), WithSessionPolicy(policy))
	return &sessionHarness{t: t, mr: mr, rdb: rdb, repo: repo, tokens: tokens, svc: svc, user: user, refTTL: refreshTTL, userRepo: userRepo}
}

// newSession stores a session created `age` ago that expires `ttl` after its creation, like Login does.
func (h *sessionHarness) newSession(age, ttl time.Duration) (*domain.Session, string) {
	h.t.Helper()
	session := &domain.Session{
		ID:        fmt.Sprintf("sess_%d_%d", h.user.ID, time.Now().UnixNano()),
		UserID:    h.user.ID,
		CreatedAt: time.Now().Add(-age),
		ExpiresAt: time.Now().Add(-age).Add(ttl),
	}
	if err := h.repo.Create(context.Background(), session); err != nil {
		h.t.Fatalf("create session: %v", err)
	}
	token, err := h.tokens.GenerateRefreshToken(h.user.ID, h.user.Role, session.ID)
	if err != nil {
		h.t.Fatalf("refresh token: %v", err)
	}
	return session, token
}

func (h *sessionHarness) refresh(token string) (*domain.AuthResult, error) {
	return h.svc.RefreshToken(context.Background(), token)
}

func (h *sessionHarness) mustRefresh(token string) *domain.AuthResult {
	h.t.Helper()
	res, err := h.refresh(token)
	if err != nil {
		h.t.Fatalf("refresh failed: %v", err)
	}
	return res
}

func (h *sessionHarness) sessionTTL(session *domain.Session) time.Duration {
	return h.mr.TTL("session:" + session.ID)
}

func near(got, want, tolerance time.Duration) bool {
	d := got - want
	return d < tolerance && d > -tolerance
}

// --- Finding 1: session lifetime ---

func TestRefresh_DefaultKeepsTodaysTwentyFourHours(t *testing.T) {
	h := newSessionHarness(t, domain.SessionPolicy{}, 168*time.Hour)
	session, token := h.newSession(0, 7*24*time.Hour)

	h.mustRefresh(token)

	if got := h.sessionTTL(session); !near(got, 24*time.Hour, time.Minute) {
		t.Errorf("default: redis TTL after refresh = %v, want 24h", got)
	}
	stored, err := h.repo.FindByID(context.Background(), session.ID)
	if err != nil || !near(time.Until(stored.ExpiresAt), 24*time.Hour, time.Minute) {
		t.Errorf("default: ExpiresAt = %v (%v), want ~24h", stored, err)
	}
}

func TestRefresh_DefaultLogsOutAfterTwentyFourHours(t *testing.T) {
	h := newSessionHarness(t, domain.SessionPolicy{}, 168*time.Hour)
	_, token := h.newSession(0, 7*24*time.Hour)
	next := h.mustRefresh(token).RefreshToken

	h.mr.FastForward(25 * time.Hour) // the person opens the app 25h after the last refresh

	_, err := h.refresh(next)
	if !errors.Is(err, domain.ErrSessionNotFound) {
		t.Errorf("default behaviour is unchanged: the session is gone after 24h, got %v", err)
	}
}

func TestRefresh_ConfiguredTTLKeepsThePersonLoggedIn(t *testing.T) {
	policy := domain.SessionPolicy{TTL: 720 * time.Hour}
	h := newSessionHarness(t, policy, 720*time.Hour)
	session, token := h.newSession(0, policy.LoginTTL())
	next := h.mustRefresh(token).RefreshToken

	if got := h.sessionTTL(session); !near(got, 720*time.Hour, time.Minute) {
		t.Errorf("redis TTL after refresh = %v, want 720h", got)
	}

	h.mr.FastForward(48 * time.Hour) // 24h no longer logs out
	res, err := h.refresh(next)
	if err != nil {
		t.Fatalf("a refresh 48h later must still work with session ttl 720h: %v", err)
	}
	// sliding: the second refresh renewed the full lifetime again
	if got := h.sessionTTL(session); !near(got, 720*time.Hour, time.Minute) {
		t.Errorf("each refresh renews the lifetime, redis TTL = %v", got)
	}
	if res.RefreshToken == "" || res.AccessToken == "" {
		t.Error("a fresh pair must come back")
	}
}

func TestRefresh_RefreshTokenNeverExpiresBeforeItsSession(t *testing.T) {
	policy := domain.SessionPolicy{TTL: 720 * time.Hour}
	// config.effectiveRefreshTTL raises refresh_ttl (168h) to the session ttl; the JWT service gets that value
	h := newSessionHarness(t, policy, 720*time.Hour)
	session, token := h.newSession(0, policy.LoginTTL())

	res := h.mustRefresh(token)

	claims, err := h.tokens.ValidateRefreshToken(res.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := h.repo.FindByID(context.Background(), session.ID)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ExpiresAt < stored.ExpiresAt.Unix() {
		t.Errorf("refresh JWT expires at %d, before its session at %d", claims.ExpiresAt, stored.ExpiresAt.Unix())
	}
}

func TestRefresh_MaxAgeCapsTheSlidingSession(t *testing.T) {
	policy := domain.SessionPolicy{TTL: 720 * time.Hour, MaxAge: 100 * time.Hour}
	h := newSessionHarness(t, policy, 720*time.Hour)

	session, token := h.newSession(90*time.Hour, 100*time.Hour)
	h.mustRefresh(token)
	if got := h.sessionTTL(session); !near(got, 10*time.Hour, time.Minute) {
		t.Errorf("a refresh near the cap only extends to the cap, TTL = %v, want ~10h", got)
	}

	// past the cap: refused as an expired session even though the sliding window is still open
	old, oldToken := h.newSession(101*time.Hour, 720*time.Hour)
	_, err := h.refresh(oldToken)
	if !errors.Is(err, domain.ErrSessionExpired) {
		t.Errorf("past SESSION_MAX_AGE the refresh is refused (401 'Session expired'), got %v", err)
	}
	_ = old
}

// --- Finding 2: grace window ---

func TestRefresh_StrictByDefaultRotatedTokenIsRefused(t *testing.T) {
	h := newSessionHarness(t, domain.SessionPolicy{}, 168*time.Hour)
	_, token := h.newSession(0, 24*time.Hour)
	h.mustRefresh(token)

	_, err := h.refresh(token)

	if !errors.Is(err, domain.ErrTokenInvalid) {
		t.Errorf("grace 0 = strict one-time use, got %v", err)
	}
}

func TestRefresh_GraceAcceptsTheRotatedTokenOnceInsideTheWindow(t *testing.T) {
	h := newSessionHarness(t, domain.SessionPolicy{RefreshGrace: 30 * time.Second}, 168*time.Hour)
	session, token := h.newSession(0, 24*time.Hour)
	lost := h.mustRefresh(token) // the answer never reached the app

	again, err := h.refresh(token) // the app retries with the token it still has
	if err != nil {
		t.Fatalf("inside the grace window the just-rotated token must be accepted: %v", err)
	}
	if again.SessionID != session.ID || again.AccessToken == "" || again.RefreshToken == "" {
		t.Fatalf("a fresh valid pair for the same session is expected: %+v", again)
	}
	if _, err := h.tokens.ValidateRefreshToken(again.RefreshToken); err != nil {
		t.Errorf("the new refresh token must be valid: %v", err)
	}
	if again.RefreshToken == lost.RefreshToken {
		t.Error("the retry must get its own new pair")
	}
	// the new pair works
	h.mustRefresh(again.RefreshToken)

	// but the grace is spent: a third presentation of the old token is refused
	if _, err := h.refresh(token); !errors.Is(err, domain.ErrTokenInvalid) {
		t.Errorf("the grace works once, got %v", err)
	}
}

func TestRefresh_GraceRefusedOutsideTheWindow(t *testing.T) {
	h := newSessionHarness(t, domain.SessionPolicy{RefreshGrace: 30 * time.Second}, 168*time.Hour)
	_, token := h.newSession(0, 24*time.Hour)
	h.mustRefresh(token)

	h.mr.FastForward(31 * time.Second)

	if _, err := h.refresh(token); !errors.Is(err, domain.ErrTokenInvalid) {
		t.Errorf("a token older than the window stays refused, got %v", err)
	}
}

func TestRefresh_GraceRefusedAfterLogout(t *testing.T) {
	h := newSessionHarness(t, domain.SessionPolicy{RefreshGrace: 30 * time.Second}, 168*time.Hour)
	session, token := h.newSession(0, 24*time.Hour)
	h.mustRefresh(token)

	if err := h.svc.Logout(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := h.refresh(token); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Errorf("logout kills everything, including the grace: %v", err)
	}
}

func TestRefresh_GraceRefusedWhenTheSessionWasDeletedForTheUser(t *testing.T) {
	h := newSessionHarness(t, domain.SessionPolicy{RefreshGrace: 30 * time.Second}, 168*time.Hour)
	_, token := h.newSession(0, 24*time.Hour)
	h.mustRefresh(token)

	if err := h.repo.DeleteAllForUser(context.Background(), h.user.ID); err != nil {
		t.Fatal(err)
	}

	if _, err := h.refresh(token); !errors.Is(err, domain.ErrSessionNotFound) {
		t.Errorf("a deleted session stays refused, got %v", err)
	}
}

func TestRefresh_GraceIsBoundToTheSessionThatRotatedTheToken(t *testing.T) {
	h := newSessionHarness(t, domain.SessionPolicy{RefreshGrace: 30 * time.Second}, 168*time.Hour)
	_, token := h.newSession(0, 24*time.Hour)
	h.mustRefresh(token)
	// the grace record claims another session: the token must be refused
	key := fmt.Sprintf("refresh_grace:%x", sha256.Sum256([]byte(token)))
	if err := h.rdb.Set(context.Background(), key, "sess_other", 30*time.Second).Err(); err != nil {
		t.Fatal(err)
	}

	if _, err := h.refresh(token); !errors.Is(err, domain.ErrTokenInvalid) {
		t.Errorf("grace of another session must not apply, got %v", err)
	}
}

func TestRefresh_GraceDoesNotWidenAnythingElse(t *testing.T) {
	h := newSessionHarness(t, domain.SessionPolicy{RefreshGrace: 30 * time.Second}, 168*time.Hour)
	_, token := h.newSession(0, 24*time.Hour)
	h.mustRefresh(token)

	// inactive user
	h.user.IsActive = false
	if _, err := h.refresh(token); !errors.Is(err, domain.ErrUserInactive) {
		t.Errorf("an inactive user is refused even inside the window, got %v", err)
	}
	h.user.IsActive = true

	// a token that was never rotated has no grace
	if _, err := h.refresh("not-a-token"); !errors.Is(err, domain.ErrTokenInvalid) {
		t.Errorf("garbage stays refused, got %v", err)
	}
}

// --- retryable conditions ---

func TestRefresh_ConcurrentRefreshIsRetryableAndDoesNotBurnTheToken(t *testing.T) {
	h := newSessionHarness(t, domain.SessionPolicy{}, 168*time.Hour)
	session, token := h.newSession(0, 24*time.Hour)
	// another refresh of the same session holds the lock
	if err := h.rdb.Set(context.Background(), "refresh_lock:"+session.ID, "locked", 30*time.Second).Err(); err != nil {
		t.Fatal(err)
	}

	_, err := h.refresh(token)
	if !errors.Is(err, domain.ErrConcurrentRefresh) {
		t.Fatalf("lock held must be ErrConcurrentRefresh (HTTP 409), got %v", err)
	}
	if errors.Is(err, domain.ErrTokenInvalid) {
		t.Error("a concurrent refresh must not look like an invalid token")
	}

	// the lock goes away; the same token is still good
	h.mr.Del("refresh_lock:" + session.ID)
	h.mustRefresh(token)
}

func TestRefresh_GraceNotBurnedByAConcurrentAttempt(t *testing.T) {
	h := newSessionHarness(t, domain.SessionPolicy{RefreshGrace: 30 * time.Second}, 168*time.Hour)
	session, token := h.newSession(0, 24*time.Hour)
	h.mustRefresh(token)
	h.mr.Set("refresh_lock:"+session.ID, "locked")

	if _, err := h.refresh(token); !errors.Is(err, domain.ErrConcurrentRefresh) {
		t.Fatalf("got %v", err)
	}
	h.mr.Del("refresh_lock:" + session.ID)

	if _, err := h.refresh(token); err != nil {
		t.Errorf("the retry after the 409 must still get the grace: %v", err)
	}
}

func TestRefresh_RedisDownIsRetryableNotUnauthorized(t *testing.T) {
	h := newSessionHarness(t, domain.SessionPolicy{}, 168*time.Hour)
	_, token := h.newSession(0, 24*time.Hour)
	h.mr.Close()

	_, err := h.refresh(token)

	if !errors.Is(err, domain.ErrTemporarilyUnavailable) {
		t.Fatalf("a Redis failure must be retryable (HTTP 503), got %v", err)
	}
	if errors.Is(err, domain.ErrTokenInvalid) || errors.Is(err, domain.ErrSessionNotFound) {
		t.Errorf("a Redis failure must never look like a logout: %v", err)
	}
}

func TestRefresh_SessionLookupFailureIsRetryableButMissingSessionIsFinal(t *testing.T) {
	for name, tc := range map[string]struct {
		repoErr   error
		retryable bool
	}{
		"redis error":     {errors.New("connection reset"), true},
		"session missing": {domain.ErrSessionNotFound, false},
		"session expired": {domain.ErrSessionExpired, false},
	} {
		t.Run(name, func(t *testing.T) {
			h := newSessionHarness(t, domain.SessionPolicy{}, 168*time.Hour)
			_, token := h.newSession(0, 24*time.Hour)
			failing := mocks.NewMockSessionRepository()
			failing.FindByIDFunc = func(ctx context.Context, id string) (*domain.Session, error) { return nil, tc.repoErr }
			svc := NewAuthService(h.userRepo, failing, mocks.NewMockPasswordService(), h.tokens, mocks.NewMockOTPService(), mocks.NewMockPolicyService(),
				h.rdb, mocks.NewMockRequestValidationService(), mocks.NewMockComprehensiveAuditService(), mocks.NewMockIdentifierResolutionService(),
				mocks.NewMockEmailAuthenticationStrategy(), mocks.NewMockPhoneAuthenticationStrategy())

			_, err := svc.RefreshToken(context.Background(), token)

			if got := errors.Is(err, domain.ErrTemporarilyUnavailable); got != tc.retryable {
				t.Errorf("retryable = %v, want %v (%v)", got, tc.retryable, err)
			}
			if !tc.retryable && !errors.Is(err, domain.ErrSessionNotFound) {
				t.Errorf("a missing or expired session stays a 401 class error: %v", err)
			}
		})
	}
}

func TestRefresh_ExtendTTLFailureIsRetryable(t *testing.T) {
	h := newSessionHarness(t, domain.SessionPolicy{}, 168*time.Hour)
	session, token := h.newSession(0, 24*time.Hour)
	failing := mocks.NewMockSessionRepository()
	failing.FindByIDFunc = func(ctx context.Context, id string) (*domain.Session, error) { return h.repo.FindByID(ctx, id) }
	failing.ExtendTTLFunc = func(ctx context.Context, id string, ttl time.Duration) error { return errors.New("redis timeout") }
	svc := NewAuthService(h.userRepo, failing, mocks.NewMockPasswordService(), h.tokens, mocks.NewMockOTPService(), mocks.NewMockPolicyService(),
		h.rdb, mocks.NewMockRequestValidationService(), mocks.NewMockComprehensiveAuditService(), mocks.NewMockIdentifierResolutionService(),
		mocks.NewMockEmailAuthenticationStrategy(), mocks.NewMockPhoneAuthenticationStrategy())

	_, err := svc.RefreshToken(context.Background(), token)

	if !errors.Is(err, domain.ErrTemporarilyUnavailable) {
		t.Errorf("got %v", err)
	}
	// the token was not burned by the failed attempt
	if exists, _ := h.rdb.Exists(context.Background(), fmt.Sprintf("blacklist:refresh:%x", sha256.Sum256([]byte(token)))).Result(); exists != 0 {
		t.Error("a failed refresh must leave the token usable")
	}
	_ = session
}
