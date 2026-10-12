package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"
)

// otpDigestPrefix marks a stored value as a digest. A value without it is a code stored in clear by a
// release before digests existed: it is still accepted (compared in constant time) so codes issued just
// before the deploy keep working until they expire.
const otpDigestPrefix = "hmac1:"

// otpDigestContext derives the digest key from the server secret, so no new setting is needed.
const otpDigestContext = "authzsvc/otp-at-rest/v1"

// OTPDigester turns a one-time code into HMAC-SHA256(key, scope || 0x00 || code). The scope binds a
// digest to what it was issued for (phone and user, or a reset request id), so a digest copied from one
// place cannot be replayed for another.
type OTPDigester struct {
	key []byte
}

// NewOTPDigester derives the key from secret (the JWT secret in production). An empty secret gets a
// random per-process key: digests then do not survive a restart or span instances, but a code is still
// never stored in clear.
func NewOTPDigester(secret string) *OTPDigester {
	if secret == "" {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			panic(err)
		}
		return &OTPDigester{key: key}
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(otpDigestContext))
	return &OTPDigester{key: mac.Sum(nil)}
}

// Digest returns the storable form of code for scope.
func (d *OTPDigester) Digest(scope, code string) string {
	mac := hmac.New(sha256.New, d.key)
	mac.Write([]byte(scope))
	mac.Write([]byte{0})
	mac.Write([]byte(code))
	return otpDigestPrefix + hex.EncodeToString(mac.Sum(nil))
}

// otpMatches compares a stored value with a code the user typed, in constant time. d may be nil
// (then only legacy clear values can match).
func otpMatches(d *OTPDigester, stored, scope, provided string) bool {
	if strings.HasPrefix(stored, otpDigestPrefix) {
		return d != nil && hmac.Equal([]byte(stored), []byte(d.Digest(scope, provided)))
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(provided)) == 1
}
