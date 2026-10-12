package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSecret = "unit-test-secret"

func TestJWT_PhoneVerifiedClaimRoundTrip(t *testing.T) {
	svc := NewJWTService(testSecret, "iss", time.Minute, time.Hour).(*JWTServiceImpl)
	for _, verified := range []bool{true, false} {
		tok, err := svc.GenerateUserAccessToken(5, "client", "s1", "+5511988887777", verified)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := svc.ValidateAccessToken(tok)
		if err != nil || claims.PhoneVerified != verified || claims.UserID != 5 || claims.Role != "client" {
			t.Errorf("verified=%v: %+v err=%v", verified, claims, err)
		}
	}
	// the legacy generator keeps working and says "not verified"
	tok, _ := svc.GenerateAccessToken(5, "client", "s1")
	if claims, err := svc.ValidateAccessToken(tok); err != nil || claims.PhoneVerified {
		t.Errorf("legacy token: %+v err=%v", claims, err)
	}
}

// Tokens issued before the claim existed must be accepted and count as not verified.
func TestJWT_TokenWithoutPhoneVerifiedClaimIsNotVerified(t *testing.T) {
	svc := NewJWTService(testSecret, "iss", time.Minute, time.Hour)
	now := time.Now()
	for name, extra := range map[string]interface{}{
		"absent":         nil,
		"wrong type":     "true",
		"explicit false": false,
	} {
		claims := jwt.MapClaims{"user_id": 5, "role": "user", "session_id": "s", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
		if extra != nil {
			claims["phone_verified"] = extra
		}
		raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(testSecret))
		if err != nil {
			t.Fatal(err)
		}
		got, err := svc.ValidateAccessToken(raw)
		if err != nil {
			t.Errorf("%s: must not be an error: %v", name, err)
			continue
		}
		if got.PhoneVerified {
			t.Errorf("%s: must count as not verified", name)
		}
	}
}

// The phone claim round-trips; a token issued without it decodes with an empty phone.
func TestJWT_PhoneClaimRoundTrip(t *testing.T) {
	svc := NewJWTService("test-secret-key-0123456789abcdef", "authzsvc", time.Minute, time.Hour)

	tok, err := svc.GenerateUserAccessToken(5, "client", "s1", "+5511988887777", false)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	claims, err := svc.ValidateAccessToken(tok)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Phone != "+5511988887777" {
		t.Errorf("expected phone claim, got %q", claims.Phone)
	}

	old, err := svc.GenerateAccessToken(5, "client", "s1")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	claims, err = svc.ValidateAccessToken(old)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if claims.Phone != "" {
		t.Errorf("expected empty phone, got %q", claims.Phone)
	}
}
