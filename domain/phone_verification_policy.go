package domain

// PhoneVerificationRule implements PhoneVerificationPolicy from the single configuration switch
// REQUIRE_PHONE_VERIFICATION. The zero value does NOT require verification; use
// StrictPhoneVerification (the default of the service) to keep today's behaviour.
type PhoneVerificationRule struct {
	Required bool
}

// StrictPhoneVerification is the default: unverified users cannot log in and registration sends an OTP.
func StrictPhoneVerification() PhoneVerificationRule { return PhoneVerificationRule{Required: true} }

// RequiresPhoneVerification reports whether the phone must be verified before login.
func (r PhoneVerificationRule) RequiresPhoneVerification() bool { return r.Required }

// AllowUnverifiedLogin reports whether a user with an unverified phone may log in.
func (r PhoneVerificationRule) AllowUnverifiedLogin() bool { return !r.Required }

// ShouldEnforceVerification reports whether login must be refused for this user.
func (r PhoneVerificationRule) ShouldEnforceVerification(user *User) bool {
	return r.Required && user != nil && !user.PhoneVerified
}

var _ PhoneVerificationPolicy = PhoneVerificationRule{}
