package identity

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
)

// AccountInvalidator implements domain.AccountStateInvalidator on Redis. It deletes, by exact key
// and without scanning the keyspace:
//   - the identity cache entry authz:backend_id:<user id> (KeyPrefix);
//   - the user's pending OTP keys: otp:<phone>:<id>, otp:att:<phone>:<id> and the resend
//     throttle otp:res:<phone>. These formats are the ones services.OTPServiceImpl writes; a test
//     in the services package pins them together.
//
// Password reset by phone uses the same OTP keys (and its reset requests live in PostgreSQL),
// so there are no other Redis keys per user to remove.
type AccountInvalidator struct {
	redis redis.Cmdable
}

// NewAccountInvalidator builds an AccountInvalidator over rdb.
func NewAccountInvalidator(rdb redis.Cmdable) *AccountInvalidator {
	return &AccountInvalidator{redis: rdb}
}

// InvalidateAccount deletes the keys listed on the type. phone may be empty, in which case
// only the identity cache entry is removed.
func (a *AccountInvalidator) InvalidateAccount(ctx context.Context, userID uint, phone string) error {
	keys := []string{fmt.Sprintf("%s%d", KeyPrefix, userID)}
	if phone != "" {
		keys = append(keys,
			fmt.Sprintf("otp:%s:%d", phone, userID),
			fmt.Sprintf("otp:att:%s:%d", phone, userID),
			fmt.Sprintf("otp:res:%s", phone),
		)
	}
	if err := a.redis.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("failed to invalidate cached state of user %d: %w", userID, err)
	}
	return nil
}

var _ domain.AccountStateInvalidator = (*AccountInvalidator)(nil)
