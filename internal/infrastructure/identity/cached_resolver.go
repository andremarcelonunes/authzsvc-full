package identity

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
)

const (
	// KeyPrefix prefixes every cache key: authz:backend_id:<authz user id>.
	KeyPrefix = "authz:backend_id:"
	// PositiveTTL is how long a found mapping is cached.
	PositiveTTL = 5 * time.Minute
	// NegativeTTL is how long a "not found" answer is cached. Kept very short: an account
	// has no backend profile only for the moment between sign-up and profile creation, and
	// the first call after that (which creates the profile) is exactly the one that caches
	// "not found". A long TTL left a brand-new account without x-backend-user-id for half a
	// minute, so services that depend on that header refused it right after sign-up.
	NegativeTTL = 2 * time.Second

	foundPrefix   = "1:"
	notFoundValue = "0"
)

// CachedResolver wraps a resolver with a Redis cache. Errors from the wrapped
// resolver are never cached; Redis failures never fail the lookup.
type CachedResolver struct {
	next  domain.BackendIdentityResolver
	redis redis.Cmdable
}

// NewCachedResolver wraps next with a Redis cache.
func NewCachedResolver(next domain.BackendIdentityResolver, rdb redis.Cmdable) *CachedResolver {
	return &CachedResolver{next: next, redis: rdb}
}

func (c *CachedResolver) ResolveBackendUserID(ctx context.Context, authzUserID uint) (string, bool, error) {
	key := fmt.Sprintf("%s%d", KeyPrefix, authzUserID)

	cached, err := c.redis.Get(ctx, key).Result()
	switch {
	case err == nil:
		if cached == notFoundValue {
			return "", false, nil
		}
		if id, ok := strings.CutPrefix(cached, foundPrefix); ok && id != "" {
			return id, true, nil
		}
		// unrecognised value: ignore and refresh from the source
	case err != redis.Nil:
		log.Printf("identity: cache read failed (falling through to backend): %v", err)
	}

	id, found, err := c.next.ResolveBackendUserID(ctx, authzUserID)
	if err != nil {
		return "", false, err
	}

	value, ttl := notFoundValue, NegativeTTL
	if found {
		value, ttl = foundPrefix+id, PositiveTTL
	}
	if setErr := c.redis.Set(ctx, key, value, ttl).Err(); setErr != nil {
		log.Printf("identity: cache write failed: %v", setErr)
	}
	return id, found, nil
}
