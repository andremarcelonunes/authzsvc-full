package handlers

import (
	"testing"

	"github.com/you/authzsvc/domain"
)

// token.phone_verified reaches the rule engine as the string "true" / "false", so a gateway rule
// can compare a request value against it (e.g. header.x-phone-verified==token.phone_verified).
func TestCheck_PhoneVerifiedClaimReachesRules(t *testing.T) {
	cases := []struct {
		name     string
		verified bool
		sent     string
		want     int
	}{
		{"verified token, request says true", true, "true", 200},
		{"verified token, request says false", true, "false", 403},
		{"unverified token, request says false", false, "false", 200},
		{"unverified token, request says true", false, "true", 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCheckFixture(t)
			f.enforcer.AddPolicy("role_user", "/gate/*", "GET", "header.x-phone-verified==token.phone_verified")
			f.tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
				return &domain.TokenClaims{UserID: 123, Role: "user", SessionID: "session_123", PhoneVerified: tc.verified}, nil
			}
			headers := map[string]string{"Authorization": "Bearer valid_token", "X-Phone-Verified": tc.sent}
			if w := f.do("GET", "/external/authz/check/gate/x", headers, ""); w.Code != tc.want {
				t.Errorf("got %d, want %d (%s)", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

// A token issued before the claim existed decodes as phone_verified=false: the rule sees "false", not an error.
func TestCheck_TokenWithoutPhoneVerifiedClaimCountsAsNotVerified(t *testing.T) {
	f := newCheckFixture(t) // default claims: PhoneVerified zero value, like a decoded old token
	f.enforcer.AddPolicy("role_user", "/gate/*", "GET", "query.verified==token.phone_verified")
	if w := f.do("GET", "/external/authz/check/gate/x?verified=false", bearer, ""); w.Code != 200 {
		t.Errorf("old token must be treated as not verified: %d %s", w.Code, w.Body.String())
	}
	if w := f.do("GET", "/external/authz/check/gate/x?verified=true", bearer, ""); w.Code != 403 {
		t.Errorf("old token must not match verified=true: %d", w.Code)
	}
}

// The dual role inherits the policies of both profiles.
func TestCheck_ClientContactInheritsClientAndContactPolicies(t *testing.T) {
	f := newCheckFixture(t)
	f.useRBAC(t)
	for _, g := range [][2]string{{"role_client_contact", "role_client"}, {"role_client_contact", "role_contact"}} {
		if _, err := f.enforcer.AddGroupingPolicy(g[0], g[1]); err != nil {
			t.Fatal(err)
		}
	}
	f.enforcer.AddPolicy("role_client", "/only/client", "GET", "*")
	f.enforcer.AddPolicy("role_contact", "/only/contact", "GET", "*")

	check := func(role, path string) int {
		f.asUser(123, role)
		return f.do("GET", "/external/authz/check"+path, bearer, "").Code
	}
	if got := check("client_contact", "/only/client"); got != 200 {
		t.Errorf("client_contact on client policy: %d", got)
	}
	if got := check("client_contact", "/only/contact"); got != 200 {
		t.Errorf("client_contact on contact policy: %d", got)
	}
	if got := check("client", "/only/contact"); got != 403 {
		t.Errorf("client on contact policy: %d", got)
	}
	if got := check("contact", "/only/client"); got != 403 {
		t.Errorf("contact on client policy: %d", got)
	}
}
