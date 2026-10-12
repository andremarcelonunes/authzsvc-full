package services

import "github.com/you/authzsvc/domain"

// AuthStrategyOption customises an authentication strategy at construction.
type AuthStrategyOption func(policy *domain.PhoneVerificationPolicy)

// WithStrategyPhoneVerificationPolicy sets the phone verification policy of a strategy
// (REQUIRE_PHONE_VERIFICATION). The default is domain.StrictPhoneVerification().
func WithStrategyPhoneVerificationPolicy(policy domain.PhoneVerificationPolicy) AuthStrategyOption {
	return func(target *domain.PhoneVerificationPolicy) {
		if policy != nil {
			*target = policy
		}
	}
}
