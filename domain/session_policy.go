package domain

import (
	"errors"
	"time"
)

// Session lifetimes used when nothing is configured (today's behaviour): a session created at login
// lasts 7 days; every refresh sets it to 24 hours from now.
const (
	DefaultLoginSessionTTL   = 7 * 24 * time.Hour
	DefaultRefreshSessionTTL = 24 * time.Hour
)

// ErrTemporarilyUnavailable marks a failure that retrying may fix (Redis or another dependency
// failed). The HTTP layer answers it with a retryable status, never 401.
var ErrTemporarilyUnavailable = errors.New("temporarily unavailable")

// SessionPolicy is the session lifetime configuration. The zero value is today's behaviour.
type SessionPolicy struct {
	// TTL, when > 0, is the sliding session lifetime: a new session and every successful refresh
	// set the expiry to now+TTL. 0 keeps the legacy values (7 days at login, 24 hours per refresh).
	TTL time.Duration
	// MaxAge, when > 0, is an absolute cap on the session age since login: no refresh can extend a
	// session past CreatedAt+MaxAge and a refresh after it is refused. 0 = no cap.
	MaxAge time.Duration
	// RefreshGrace, when > 0, lets the refresh token that was just rotated be presented once more
	// within this window (a lost response must not log the person out). 0 = strict one-time use.
	RefreshGrace time.Duration
	// RefreshUntilSuccessor, when true, keeps the rotated refresh token usable once more (same session)
	// until its successor is first used, bounded by the refresh lifetime, instead of the RefreshGrace
	// window: an app frozen right after a refresh (new token never stored) must not log the person out.
	RefreshUntilSuccessor bool
}

// GraceTTL is how long a just-rotated refresh token may still be presented once; 0 = strict one-time use
func (p SessionPolicy) GraceTTL() time.Duration {
	if p.RefreshUntilSuccessor {
		return p.RefreshTTL()
	}
	return p.RefreshGrace
}

// LoginTTL is the lifetime of a session created at login
func (p SessionPolicy) LoginTTL() time.Duration {
	if p.TTL > 0 {
		return p.TTL
	}
	return DefaultLoginSessionTTL
}

// RefreshTTL is the lifetime a refresh gives the session, before the MaxAge cap
func (p SessionPolicy) RefreshTTL() time.Duration {
	if p.TTL > 0 {
		return p.TTL
	}
	return DefaultRefreshSessionTTL
}

// Expired reports whether a session created at createdAt is past the absolute cap
func (p SessionPolicy) Expired(createdAt, now time.Time) bool {
	return p.MaxAge > 0 && !now.Before(createdAt.Add(p.MaxAge))
}

// CappedTTL limits ttl so the session never outlives createdAt+MaxAge
func (p SessionPolicy) CappedTTL(createdAt, now time.Time, ttl time.Duration) time.Duration {
	if p.MaxAge <= 0 {
		return ttl
	}
	if left := createdAt.Add(p.MaxAge).Sub(now); left < ttl {
		return left
	}
	return ttl
}
