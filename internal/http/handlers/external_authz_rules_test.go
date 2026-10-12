package handlers

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
)

// ---- helpers ----------------------------------------------------------------

// fakeResolver is a domain.BackendIdentityResolver backed by a map.
type fakeResolver struct {
	mu    sync.Mutex
	ids   map[uint]string
	err   error
	calls int
}

func (r *fakeResolver) ResolveBackendUserID(_ context.Context, id uint) (string, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.err != nil {
		return "", false, r.err
	}
	v, ok := r.ids[id]
	return v, ok, nil
}

// newRBACEnforcer returns an enforcer whose model has a role definition and the
// standard groupings of internal/app/policies.go.
func newRBACEnforcer(t *testing.T) *casbin.Enforcer {
	t.Helper()
	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, rule

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch2(r.obj, p.obj) && regexMatch(r.act, p.act)
`)
	if err != nil {
		t.Fatal(err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range [][2]string{
		{"role_admin", "role_user"},
		{"role_root", "role_admin"},
		{"role_client", "role_user"},
		{"role_contact", "role_user"},
		{"role_attendant", "role_user"},
	} {
		if _, err := e.AddGroupingPolicy(g[0], g[1]); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

// useRBAC swaps the fixture's enforcer for one with role inheritance.
func (f *checkFixture) useRBAC(t *testing.T) {
	t.Helper()
	f.enforcer = newRBACEnforcer(t)
	f.h.enforcer = f.enforcer
}

// asUser makes the "valid_token" belong to the given user id and role.
func (f *checkFixture) asUser(id uint, role string) {
	f.tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
		if token != "valid_token" {
			return nil, domain.ErrTokenInvalid
		}
		return &domain.TokenClaims{UserID: id, Role: role, SessionID: "s"}, nil
	}
	f.sessions.FindByIDFunc = func(_ context.Context, sid string) (*domain.Session, error) {
		return &domain.Session{ID: sid, UserID: id}, nil
	}
}

func (f *checkFixture) setResolver(r domain.BackendIdentityResolver) { f.h.backendIdentity = r }

// backendHeader returns the x-backend-user-id response header and whether it is present at all.
func backendHeader(w *httptest.ResponseRecorder) (string, bool) {
	v, ok := w.Header()["X-Backend-User-Id"]
	if !ok || len(v) != 1 {
		return "", false
	}
	return v[0], true
}

const clientContactsPolicy = "/api/v1/users/client/:client_id/contacts"

// ---- gap 1: named path parameters ------------------------------------------

func TestPathParamsFromPattern(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          map[string]string
	}{
		{"/a/:x/b", "/a/5/b", map[string]string{"x": "5"}},
		{"/a/:x", "/a/5", map[string]string{"x": "5"}},
		{"/c/:u/d/:t", "/c/1/d/2", map[string]string{"u": "1", "t": "2"}},
		{"/x/:o/", "/x/9/", map[string]string{"o": "9"}},
		{"/files/:id/*", "/files/3/a/b/c", map[string]string{"id": "3"}},
		{"/plain", "/plain", map[string]string{}},
		{"/users/*", "/users/7", map[string]string{}},
	}
	for _, tc := range cases {
		got := pathParamsFromPattern(tc.pattern, tc.path)
		if fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("%s vs %s: got %v want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestCheck_NamedPathParams(t *testing.T) {
	cases := []struct {
		name, pattern, rule, ok, other string
	}{
		{"parameter in the middle", clientContactsPolicy, "path.client_id==token.user_id",
			"/api/v1/users/client/123/contacts", "/api/v1/users/client/124/contacts"},
		{"parameter at the end", "/api/v1/things/:thing_id", "path.thing_id==token.user_id",
			"/api/v1/things/123", "/api/v1/things/124"},
		{"two parameters", "/consent/status/user/:user_id/consultant/:team_id", "path.user_id==token.user_id&&path.team_id==token.user_id",
			"/consent/status/user/123/consultant/123", "/consent/status/user/123/consultant/124"},
		{"trailing slash pattern", "/x/:owner/", "path.owner==token.user_id",
			"/x/123/", "/x/124/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCheckFixture(t)
			f.enforcer.AddPolicy("role_user", tc.pattern, "GET", tc.rule)
			if w := f.do("GET", "/external/authz/check"+tc.ok, bearer, ""); w.Code != 200 {
				t.Errorf("owner: %d %s", w.Code, w.Body.String())
			}
			if w := f.do("GET", "/external/authz/check"+tc.other, bearer, ""); w.Code != 403 {
				t.Errorf("other: %d", w.Code)
			}
		})
	}
}

func TestCheck_LegacyPathIDStillWorks(t *testing.T) {
	f := newCheckFixture(t)
	f.enforcer.AddPolicy("role_user", "/users/*", "GET", "path.id==token.user_id")
	f.enforcer.AddPolicy("role_user", "/profile/:user_id", "GET", "path.user_id==token.user_id")
	if w := f.do("GET", "/external/authz/check/users/123", bearer, ""); w.Code != 200 {
		t.Errorf("owner: %d", w.Code)
	}
	if w := f.do("GET", "/external/authz/check/users/5", bearer, ""); w.Code != 403 {
		t.Errorf("other: %d", w.Code)
	}
}

// ---- gap 2: backend user id -------------------------------------------------

// gatewayFixture: user 4774 (role client) is backend user 58; user 4775 is 77.
func gatewayFixture(t *testing.T) (*checkFixture, *fakeResolver) {
	t.Helper()
	f := newCheckFixture(t)
	f.useRBAC(t)
	loadGatewayPolicies(t, f.enforcer)
	f.asUser(4774, "client")
	r := &fakeResolver{ids: map[uint]string{4774: "58", 4775: "77"}}
	f.setResolver(r)
	return f, r
}

func TestCheck_BackendID_PathQueryBody(t *testing.T) {
	f, _ := gatewayFixture(t)
	cases := []struct {
		name, method, target, body string
		want                       int
	}{
		{"path owner", "GET", "/api/v1/users/client/58/contacts", "", 200},
		{"path other id", "GET", "/api/v1/users/client/59/contacts", "", 403},
		{"query owner", "DELETE", "/api/v1/users/contact/association/?client_id=58", "", 200},
		{"query other id", "DELETE", "/api/v1/users/contact/association/?client_id=59", "", 403},
		{"query missing", "DELETE", "/api/v1/users/contact/association/", "", 403},
		{"body owner (number)", "POST", "/api/v1/users/associate/contact/", `{"client_id":58}`, 200},
		{"body owner (string)", "POST", "/api/v1/users/associate/contact/", `{"client_id":"58"}`, 200},
		{"body other id", "POST", "/api/v1/users/associate/contact/", `{"client_id":59}`, 403},
		{"body missing", "POST", "/api/v1/users/associate/contact/", "", 403},
		{"body not JSON", "POST", "/api/v1/users/associate/contact/", "nope", 403},
		{"body unknown field", "POST", "/api/v1/users/associate/contact/", `{"other":58}`, 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := f.do(tc.method, "/external/authz/check"+tc.target, bearer, tc.body)
			if w.Code != tc.want {
				t.Fatalf("status %d want %d body %s", w.Code, tc.want, w.Body.String())
			}
			if tc.want == 200 {
				if v, ok := backendHeader(w); !ok || v != "58" {
					t.Errorf("x-backend-user-id = %q present=%v", v, ok)
				}
			}
		})
	}
}

func TestCheck_BackendID_NotMapped_403(t *testing.T) {
	f, _ := gatewayFixture(t)
	f.asUser(9999, "client") // not in the resolver
	w := f.do("GET", "/external/authz/check/api/v1/users/client/58/contacts", bearer, "")
	if w.Code != 403 {
		t.Fatalf("status %d", w.Code)
	}
}

func TestCheck_BackendID_ResolverError_500(t *testing.T) {
	f, r := gatewayFixture(t)
	r.err = errors.New("backend down")
	w := f.do("GET", "/external/authz/check/api/v1/users/client/58/contacts", bearer, "")
	if w.Code != 500 {
		t.Fatalf("status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "backend down") {
		t.Errorf("500 leaks the error: %s", w.Body.String())
	}
}

func TestCheck_BackendID_ResolverNil(t *testing.T) {
	f, _ := gatewayFixture(t)
	f.setResolver(nil)
	// rule needs it -> 500
	if w := f.do("GET", "/external/authz/check/api/v1/users/client/58/contacts", bearer, ""); w.Code != 500 {
		t.Errorf("needed: %d", w.Code)
	}
	// rule "*" does not -> allowed, header present and empty
	w := f.do("POST", "/external/authz/check/api/v1/users/register/contact/", bearer, "{}")
	if w.Code != 200 {
		t.Fatalf("not needed: %d", w.Code)
	}
	if v, ok := backendHeader(w); !ok || v != "" {
		t.Errorf("header = %q present=%v", v, ok)
	}
}

func TestCheck_BackendHeader_AlwaysPresent_NeverEchoed(t *testing.T) {
	f, r := gatewayFixture(t)
	spoof := map[string]string{"Authorization": "Bearer valid_token", "x-backend-user-id": "999"}

	// mapped, rule does not reference it ("*"): resolved anyway
	w := f.do("POST", "/external/authz/check/api/v1/users/register/contact/", spoof, "{}")
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if v, ok := backendHeader(w); !ok || v != "58" {
		t.Errorf("mapped: %q %v", v, ok)
	}

	// unmapped
	f.asUser(9999, "client")
	w = f.do("POST", "/external/authz/check/api/v1/users/register/contact/", spoof, "{}")
	if v, ok := backendHeader(w); w.Code != 200 || !ok || v != "" {
		t.Errorf("unmapped: status %d %q %v", w.Code, v, ok)
	}

	// resolver failing on a request whose rule did not need it: allowed, empty
	f.asUser(4774, "client")
	r.err = errors.New("boom")
	w = f.do("POST", "/external/authz/check/api/v1/users/register/contact/", spoof, "{}")
	if v, ok := backendHeader(w); w.Code != 200 || !ok || v != "" {
		t.Errorf("unresolvable: status %d %q %v", w.Code, v, ok)
	}
}

func TestCheck_BackendResolvedAtMostOncePerRequest(t *testing.T) {
	f, r := gatewayFixture(t)
	f.enforcer.AddPolicy("role_client", "/multi/:a", "POST", "path.a==token.backend_user_id&&body.b==token.backend_user_id")
	f.enforcer.AddPolicy("role_client", "/multi/:a", "POST", "body.c==token.backend_user_id")
	w := f.do("POST", "/external/authz/check/multi/58", bearer, `{"b":58}`)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if r.calls != 1 {
		t.Errorf("resolver called %d times", r.calls)
	}
	// also when the rule fails
	r.calls = 0
	if w := f.do("POST", "/external/authz/check/multi/59", bearer, `{"b":58,"c":58}`); w.Code != 200 {
		t.Fatalf("second policy: %d", w.Code)
	}
	if r.calls != 1 {
		t.Errorf("resolver called %d times (second request)", r.calls)
	}
}

func TestAuthorize_JSONEndpointBackendHeader(t *testing.T) {
	f, _ := gatewayFixture(t)
	r := gin.New()
	r.POST("/external/authz", f.h.Authorize)
	post := func(payload string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/external/authz", strings.NewReader(payload))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	w := post(`{"attributes":{"request":{"http":{"method":"GET","path":"/api/v1/users/client/58/contacts","headers":{"authorization":"Bearer valid_token"}}}}}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"x-backend-user-id":"58"`) {
		t.Errorf("status %d body %s", w.Code, w.Body.String())
	}
	f.setResolver(&fakeResolver{err: errors.New("down")})
	w = post(`{"attributes":{"request":{"http":{"method":"GET","path":"/api/v1/users/client/58/contacts","headers":{"authorization":"Bearer valid_token"}}}}}`)
	if w.Code != 500 {
		t.Errorf("resolver error: status %d body %s", w.Code, w.Body.String())
	}
}

// ---- gap 3: role inheritance ------------------------------------------------

func TestCheck_RoleInheritance(t *testing.T) {
	f := newCheckFixture(t)
	f.useRBAC(t)
	f.enforcer.AddPolicy("role_admin", "/admin/x", "GET", "*")
	f.enforcer.AddPolicy("role_user", "/auth/me", "GET", "*")

	f.asUser(1, "root")
	if w := f.do("GET", "/external/authz/check/admin/x", bearer, ""); w.Code != 200 {
		t.Errorf("root via role_admin: %d", w.Code)
	}
	if w := f.do("GET", "/external/authz/check/auth/me", bearer, ""); w.Code != 200 {
		t.Errorf("root via role_user (transitive): %d", w.Code)
	}
	f.asUser(2, "client")
	if w := f.do("GET", "/external/authz/check/auth/me", bearer, ""); w.Code != 200 {
		t.Errorf("client via role_user: %d", w.Code)
	}
	if w := f.do("GET", "/external/authz/check/admin/x", bearer, ""); w.Code != 403 {
		t.Errorf("client must not inherit role_admin: %d", w.Code)
	}
}

func TestMatchingPolicies_OwnBeforeInherited(t *testing.T) {
	f := newCheckFixture(t)
	f.useRBAC(t)
	f.enforcer.AddPolicy("role_user", "/o/:id", "GET", "inherited")
	f.enforcer.AddPolicy("role_client", "/o/:id", "GET", "own")
	got, err := f.h.matchingPolicies("role_client", "/o/1", "GET")
	if err != nil || len(got) != 2 || got[0].rule != "own" || got[1].rule != "inherited" {
		t.Errorf("got %+v err %v", got, err)
	}
}

// ---- gap 4: every matching policy -------------------------------------------

func TestCheck_AnyMatchingPolicyAllows(t *testing.T) {
	f := newCheckFixture(t)
	f.enforcer.AddPolicy("role_user", "/m/:id", "GET", "path.id==999")
	f.enforcer.AddPolicy("role_user", "/m/:id", "GET", "path.id==token.user_id")
	if w := f.do("GET", "/external/authz/check/m/123", bearer, ""); w.Code != 200 {
		t.Errorf("second policy passes: %d", w.Code)
	}
	if w := f.do("GET", "/external/authz/check/m/5", bearer, ""); w.Code != 403 {
		t.Errorf("all fail: %d", w.Code)
	}
}

func TestCheck_OwnFailsInheritedAllows(t *testing.T) {
	f := newCheckFixture(t)
	f.useRBAC(t)
	f.asUser(123, "client")
	f.enforcer.AddPolicy("role_client", "/m/:id", "GET", "path.id==999")
	f.enforcer.AddPolicy("role_user", "/m/:id", "GET", "path.id==token.user_id")
	if w := f.do("GET", "/external/authz/check/m/123", bearer, ""); w.Code != 200 {
		t.Errorf("inherited policy allows: %d", w.Code)
	}
}

func TestCheck_UnevaluableAndMalformedRulesAreNotSatisfied(t *testing.T) {
	f := newCheckFixture(t)
	f.enforcer.AddPolicy("role_user", "/b", "POST", "body.author_id==token.user_id")
	if w := f.do("POST", "/external/authz/check/b", bearer, ""); w.Code != 403 {
		t.Errorf("missing body: %d", w.Code)
	}

	f.enforcer.AddPolicy("role_user", "/mal", "GET", "path.id>token.user_id")
	if w := f.do("GET", "/external/authz/check/mal", bearer, ""); w.Code != 403 {
		t.Errorf("malformed rule: %d", w.Code)
	}

	// neither blocks a later policy that is satisfied
	f.enforcer.AddPolicy("role_user", "/c", "POST", "body.author_id==token.user_id")
	f.enforcer.AddPolicy("role_user", "/c", "POST", "garbage")
	f.enforcer.AddPolicy("role_user", "/c", "POST", "*")
	if w := f.do("POST", "/external/authz/check/c", bearer, ""); w.Code != 200 {
		t.Errorf("later '*' policy: %d", w.Code)
	}
}

func TestCheck_ResolverErrorDoesNotBlockOtherAllowingPolicy(t *testing.T) {
	f := newCheckFixture(t)
	f.setResolver(&fakeResolver{err: errors.New("down")})
	f.enforcer.AddPolicy("role_user", "/r/:id", "GET", "path.id==token.backend_user_id")
	if w := f.do("GET", "/external/authz/check/r/1", bearer, ""); w.Code != 500 {
		t.Fatalf("only the resolver rule: %d", w.Code)
	}
	f.enforcer.AddPolicy("role_user", "/r/:id", "GET", "*")
	if w := f.do("GET", "/external/authz/check/r/1", bearer, ""); w.Code != 200 {
		t.Errorf("with an allowing policy: %d", w.Code)
	}
}

// ---- the drafted gateway policy file ---------------------------------------

type csvPolicy struct{ role, pattern, method, rule string }

func readGatewayPolicies(t *testing.T) []csvPolicy {
	t.Helper()
	fh, err := os.Open("testdata/gateway_policies.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	var out []csvPolicy
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) != 4 {
			t.Fatalf("bad policy line %q", line)
		}
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		out = append(out, csvPolicy{parts[0], parts[1], parts[2], parts[3]})
	}
	if len(out) < 50 {
		t.Fatalf("only %d policies read", len(out))
	}
	return out
}

func loadGatewayPolicies(t *testing.T, e *casbin.Enforcer) {
	t.Helper()
	for _, p := range readGatewayPolicies(t) {
		if _, err := e.AddPolicy(p.role, p.pattern, p.method, p.rule); err != nil {
			t.Fatal(err)
		}
	}
}

var conditionRe = regexp.MustCompile(`^(path|query|body)\.([A-Za-z_][A-Za-z0-9_]*)==token\.backend_user_id$`)

func TestGatewayPolicies_EveryRuleParsesAndEnforces(t *testing.T) {
	policies := readGatewayPolicies(t)
	const owner, ownerBackend = uint(4774), "58"
	const stranger, strangerBackend = uint(4775), "77"

	for _, p := range policies {
		p := p
		t.Run(p.role+" "+p.method+" "+p.pattern, func(t *testing.T) {
			f := newCheckFixture(t)
			f.useRBAC(t)
			loadGatewayPolicies(t, f.enforcer)
			f.setResolver(&fakeResolver{ids: map[uint]string{owner: ownerBackend, stranger: strangerBackend}})

			// 1. the rule parses
			pathParams := map[string]bool{}
			for _, seg := range strings.Split(p.pattern, "/") {
				if strings.HasPrefix(seg, ":") {
					pathParams[seg[1:]] = true
				}
			}
			var queryName, bodyField string
			pathOwnerParam := ""
			if p.rule != "*" {
				for _, cond := range strings.Split(p.rule, "&&") {
					m := conditionRe.FindStringSubmatch(strings.TrimSpace(cond))
					if m == nil {
						t.Fatalf("rule %q does not parse", p.rule)
					}
					switch m[1] {
					case "path":
						if !pathParams[m[2]] {
							t.Fatalf("path.%s is not a parameter of %s", m[2], p.pattern)
						}
						pathOwnerParam = m[2]
					case "query":
						queryName = m[2]
					case "body":
						bodyField = m[2]
					}
				}
			}

			// 2. a representative request
			target := ""
			for _, seg := range strings.Split(p.pattern, "/") {
				switch {
				case seg == "":
				case seg == "*":
					target += "/x"
				case strings.HasPrefix(seg, ":"):
					if seg[1:] == pathOwnerParam {
						target += "/" + ownerBackend
					} else {
						target += "/9"
					}
				default:
					target += "/" + seg
				}
			}
			if strings.HasSuffix(p.pattern, "/") {
				target += "/"
			}
			if queryName != "" {
				target += "?" + queryName + "=" + ownerBackend
			}
			body := ""
			if bodyField != "" {
				body = fmt.Sprintf(`{%q:%s}`, bodyField, ownerBackend)
			}
			method := strings.Split(strings.Trim(p.method, "()"), "|")[0]
			callerRole := strings.TrimPrefix(p.role, "role_")

			f.asUser(owner, callerRole)
			if w := f.do(method, "/external/authz/check"+target, bearer, body); w.Code != 200 {
				t.Fatalf("right caller: status %d (%s %s) body %s", w.Code, method, target, w.Body.String())
			}

			// 3. a different caller is denied
			if p.rule == "*" {
				f.asUser(owner, "nobody")
			} else {
				f.asUser(stranger, callerRole)
			}
			if w := f.do(method, "/external/authz/check"+target, bearer, body); w.Code != 403 {
				t.Fatalf("different caller: status %d (%s %s)", w.Code, method, target)
			}
		})
	}
}

// A mistyped right-hand side must never be compared as plain text: otherwise the
// caller could satisfy the rule by sending that same text.
func TestExtractTokenValue_RejectsAnythingButTokenClaims(t *testing.T) {
	h := &ExternalAuthzHandlers{}
	claims := map[string]interface{}{"user_id": "7"}

	for _, source := range []string{"tokn.user_id", "token_user_id", "admin", "token.", "path.id"} {
		value, ok, err := h.extractTokenValue(context.Background(), source, claims, &backendLookup{})
		if err != nil || ok || value != "" {
			t.Errorf("source %q: expected not satisfied, got value=%q ok=%v err=%v", source, value, ok, err)
		}
	}

	value, ok, err := h.extractTokenValue(context.Background(), "token.user_id", claims, &backendLookup{})
	if err != nil || !ok || value != "7" {
		t.Errorf("token.user_id: expected 7, got value=%q ok=%v err=%v", value, ok, err)
	}
}

// A query parameter sent twice must not satisfy a rule: the upstream may read the
// other occurrence (FastAPI keeps the last one).
func TestExtractRequestValue_RepeatedQueryParameterNeverMatches(t *testing.T) {
	h := &ExternalAuthzHandlers{}
	request := func(query string) EnvoyRequest {
		var r EnvoyRequest
		r.Attributes.Request.HTTP.Path = "/x"
		r.Attributes.Request.HTTP.Query = query
		return r
	}

	for _, query := range []string{"client_id=15&client_id=26", "client_id=26&client_id=15", "client_id=15&client_id=15", "client_id="} {
		if value, found, err := h.extractRequestValue(request(query), "/x", "query.client_id"); err != nil || found {
			t.Errorf("query %q: expected not found, got value=%q found=%v err=%v", query, value, found, err)
		}
	}

	value, found, err := h.extractRequestValue(request("client_id=15&contact_id=17"), "/x", "query.client_id")
	if err != nil || !found || value != "15" {
		t.Errorf("single occurrence: expected 15, got value=%q found=%v err=%v", value, found, err)
	}
}

// x-user-phone comes from the token only: present with the account's phone, present and
// empty for a token without the claim, and a client-supplied value is never echoed.
func TestCheck_PhoneHeader_FromTokenOnly(t *testing.T) {
	f, _ := gatewayFixture(t)
	spoof := map[string]string{"Authorization": "Bearer valid_token", "x-user-phone": "+15550000000"}
	phoneHeader := func(w *httptest.ResponseRecorder) (string, bool) {
		v, ok := w.Header()["X-User-Phone"]
		if !ok || len(v) != 1 {
			return "", false
		}
		return v[0], true
	}

	f.tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
		return &domain.TokenClaims{UserID: 4774, Role: "client", SessionID: "s", Phone: "+5511988887777"}, nil
	}
	w := f.do("POST", "/external/authz/check/api/v1/users/register/contact/", spoof, "{}")
	if v, ok := phoneHeader(w); w.Code != 200 || !ok || v != "+5511988887777" {
		t.Errorf("with claim: status %d %q %v", w.Code, v, ok)
	}

	f.asUser(4774, "client") // token without the phone claim
	w = f.do("POST", "/external/authz/check/api/v1/users/register/contact/", spoof, "{}")
	if v, ok := phoneHeader(w); w.Code != 200 || !ok || v != "" {
		t.Errorf("without claim: status %d %q %v", w.Code, v, ok)
	}
}
