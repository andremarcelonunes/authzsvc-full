package domain

import "testing"

func TestPhoneVerificationRule(t *testing.T) {
	unverified := &User{PhoneVerified: false}
	verified := &User{PhoneVerified: true}

	strict := StrictPhoneVerification()
	if !strict.RequiresPhoneVerification() || strict.AllowUnverifiedLogin() {
		t.Error("strict rule must require verification")
	}
	if !strict.ShouldEnforceVerification(unverified) || strict.ShouldEnforceVerification(verified) || strict.ShouldEnforceVerification(nil) {
		t.Error("strict rule must refuse only unverified users")
	}

	relaxed := PhoneVerificationRule{Required: false}
	if relaxed.RequiresPhoneVerification() || !relaxed.AllowUnverifiedLogin() {
		t.Error("relaxed rule must allow unverified login")
	}
	if relaxed.ShouldEnforceVerification(unverified) || relaxed.ShouldEnforceVerification(verified) {
		t.Error("relaxed rule must never enforce")
	}
}
