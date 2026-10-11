package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

type checkFixture struct {
	h        *ExternalAuthzHandlers
	tokenSvc *mocks.MockTokenService
	sessions *mocks.MockSessionRepository
	enforcer *casbin.Enforcer
	router   *gin.Engine
	// seen records the last (path, method) authorized via a policy lookup is not
	// needed: behaviour is observed through policies.
}

// newCheckFixture wires the Check handler on the same route pattern as the
// real router, with a valid user (id 123, role user, session_123) by default.
func newCheckFixture(t *testing.T) *checkFixture {
	t.Helper()
	gin.SetMode(gin.TestMode)
	f := &checkFixture{
		tokenSvc: mocks.NewMockTokenService(),
		sessions: mocks.NewMockSessionRepository(),
		enforcer: createTestEnforcer(t),
	}
	f.tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
		if token != "valid_token" {
			return nil, domain.ErrTokenInvalid
		}
		return &domain.TokenClaims{UserID: 123, Role: "user", SessionID: "session_123"}, nil
	}
	f.sessions.FindByIDFunc = func(ctx context.Context, id string) (*domain.Session, error) {
		return &domain.Session{ID: id, UserID: 123}, nil
	}
	f.h = NewExternalAuthzHandlers(f.tokenSvc, f.sessions, f.enforcer, nil)
	f.router = gin.New()
	f.router.Any("/external/authz/check/*path", f.h.Check)
	return f
}

func (f *checkFixture) do(method, target string, headers map[string]string, body string) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, target, rd)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

var bearer = map[string]string{"Authorization": "Bearer valid_token"}

func errorBody(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var b map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("body is not JSON: %q", w.Body.String())
	}
	return b["error"]
}

func TestCheck_Allowed(t *testing.T) {
	f := newCheckFixture(t)
	f.enforcer.AddPolicy("role_user", "/api/v1/users/user/:id", "GET", "*")

	w := f.do("GET", "/external/authz/check/api/v1/users/user/9", bearer, "")
	if w.Code != 200 {
		t.Fatalf("status %d body %s", w.Code, w.Body.String())
	}
	if w.Body.Len() != 0 {
		t.Errorf("body must be empty, got %q", w.Body.String())
	}
	if got := w.Header().Get("x-user-id"); got != "123" {
		t.Errorf("x-user-id = %q", got)
	}
	if got := w.Header().Get("x-user-role"); got != "user" {
		t.Errorf("x-user-role = %q", got)
	}
}

func TestCheck_SpoofedIdentityHeadersIgnored(t *testing.T) {
	f := newCheckFixture(t)
	f.enforcer.AddPolicy("role_user", "/auth/me", "GET", "*")

	w := f.do("GET", "/external/authz/check/auth/me", map[string]string{
		"Authorization": "Bearer valid_token",
		"x-user-id":     "999",
		"x-user-role":   "admin",
	}, "")
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	if got := w.Header().Values("x-user-id"); len(got) != 1 || got[0] != "123" {
		t.Errorf("x-user-id = %v", got)
	}
	if got := w.Header().Values("x-user-role"); len(got) != 1 || got[0] != "user" {
		t.Errorf("x-user-role = %v", got)
	}
}

func TestCheck_Unauthorized(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		setup   func(*checkFixture)
		message string
	}{
		{"no authorization header", nil, nil, "Authorization header required"},
		{"wrong scheme", map[string]string{"Authorization": "Basic valid_token"}, nil, "Invalid authorization header format"},
		{"invalid token", map[string]string{"Authorization": "Bearer nope"}, nil, "Invalid token"},
		{"expired token", bearer, func(f *checkFixture) {
			f.tokenSvc.ValidateAccessTokenFunc = func(string) (*domain.TokenClaims, error) { return nil, domain.ErrTokenExpired }
		}, "Token expired"},
		{"other token error", bearer, func(f *checkFixture) {
			f.tokenSvc.ValidateAccessTokenFunc = func(string) (*domain.TokenClaims, error) { return nil, errors.New("boom") }
		}, "Token validation failed"},
		{"session missing", bearer, func(f *checkFixture) {
			f.sessions.FindByIDFunc = func(context.Context, string) (*domain.Session, error) { return nil, nil }
		}, "Session invalid or expired"},
		{"session lookup error", bearer, func(f *checkFixture) {
			f.sessions.FindByIDFunc = func(context.Context, string) (*domain.Session, error) { return nil, errors.New("redis down") }
		}, "Session invalid or expired"},
		{"session of another user", bearer, func(f *checkFixture) {
			f.sessions.FindByIDFunc = func(_ context.Context, id string) (*domain.Session, error) {
				return &domain.Session{ID: id, UserID: 456}, nil
			}
		}, "Session user mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCheckFixture(t)
			f.enforcer.AddPolicy("role_user", "/auth/me", "GET", "*")
			if tc.setup != nil {
				tc.setup(f)
			}
			w := f.do("GET", "/external/authz/check/auth/me", tc.headers, "")
			if w.Code != 401 {
				t.Fatalf("status %d body %s", w.Code, w.Body.String())
			}
			if got := errorBody(t, w); got != tc.message {
				t.Errorf("error = %q want %q", got, tc.message)
			}
			if w.Header().Get("x-user-id") != "" || w.Header().Get("x-user-role") != "" {
				t.Error("identity headers must not be set on denial")
			}
		})
	}
}

func TestCheck_NoMatchingPolicy_403(t *testing.T) {
	f := newCheckFixture(t)
	f.enforcer.AddPolicy("role_user", "/auth/me", "GET", "*")
	w := f.do("GET", "/external/authz/check/admin/policies", bearer, "")
	if w.Code != 403 {
		t.Fatalf("status %d", w.Code)
	}
	if errorBody(t, w) != "Access denied" {
		t.Errorf("body %s", w.Body.String())
	}
	if w.Header().Get("x-user-id") != "" {
		t.Error("identity headers must not be set on denial")
	}
}

func TestCheck_FieldRule(t *testing.T) {
	f := newCheckFixture(t)
	f.enforcer.AddPolicy("role_user", "/users/:id", "GET", "path.id==token.user_id")

	if w := f.do("GET", "/external/authz/check/users/123", bearer, ""); w.Code != 200 {
		t.Errorf("owner: status %d body %s", w.Code, w.Body.String())
	}
	w := f.do("GET", "/external/authz/check/users/124", bearer, "")
	if w.Code != 403 {
		t.Fatalf("other id: status %d", w.Code)
	}
	if !strings.Contains(errorBody(t, w), "Field validation failed") {
		t.Errorf("body %s", w.Body.String())
	}
}

func TestCheck_FieldRuleUsesQueryHeaderAndBody(t *testing.T) {
	f := newCheckFixture(t)
	f.enforcer.AddPolicy("role_user", "/api/data", "GET", "query.user_id==token.user_id")
	f.enforcer.AddPolicy("role_user", "/api/posts", "POST", "body.author_id==token.user_id")

	if w := f.do("GET", "/external/authz/check/api/data?user_id=123", bearer, ""); w.Code != 200 {
		t.Errorf("query owner: %d", w.Code)
	}
	if w := f.do("GET", "/external/authz/check/api/data?user_id=1", bearer, ""); w.Code != 403 {
		t.Errorf("query other: %d", w.Code)
	}
	if w := f.do("POST", "/external/authz/check/api/posts", bearer, `{"author_id":123}`); w.Code != 200 {
		t.Errorf("body owner: %d", w.Code)
	}
	if w := f.do("POST", "/external/authz/check/api/posts", bearer, `{"author_id":5}`); w.Code != 403 {
		t.Errorf("body other: %d", w.Code)
	}
	// Missing body: the condition cannot be evaluated => policy not satisfied => 403 (was 500).
	w := f.do("POST", "/external/authz/check/api/posts", bearer, "")
	if w.Code != 403 {
		t.Fatalf("no body: %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "not found") || strings.Contains(w.Body.String(), "details") {
		t.Errorf("403 body leaks internals: %s", w.Body.String())
	}
	if !strings.Contains(errorBody(t, w), "Field validation failed") {
		t.Errorf("body %s", w.Body.String())
	}
}

func TestCheck_MethodComesFromHTTPMethod(t *testing.T) {
	f := newCheckFixture(t)
	f.enforcer.AddPolicy("role_user", "/things/:id", "GET", "*")

	if w := f.do("GET", "/external/authz/check/things/1", bearer, ""); w.Code != 200 {
		t.Errorf("GET: %d", w.Code)
	}
	if w := f.do("DELETE", "/external/authz/check/things/1", bearer, ""); w.Code != 403 {
		t.Errorf("DELETE: %d", w.Code)
	}
}

func TestCheck_HeadAndOptionsAreNotBypassed(t *testing.T) {
	f := newCheckFixture(t)
	f.enforcer.AddPolicy("role_user", "/things", "GET", "*")

	for _, m := range []string{"HEAD", "OPTIONS"} {
		// no token -> 401, not a free pass
		if w := f.do(m, "/external/authz/check/things", nil, ""); w.Code != 401 {
			t.Errorf("%s without token: %d", m, w.Code)
		}
		// with token but only GET allowed -> 403
		if w := f.do(m, "/external/authz/check/things", bearer, ""); w.Code != 403 {
			t.Errorf("%s with GET-only policy: %d", m, w.Code)
		}
	}
	f.enforcer.AddPolicy("role_user", "/things", "HEAD", "*")
	if w := f.do("HEAD", "/external/authz/check/things", bearer, ""); w.Code != 200 {
		t.Errorf("HEAD with HEAD policy: %d", w.Code)
	}
}

func TestCheck_PathRemainder(t *testing.T) {
	f := newCheckFixture(t)
	f.enforcer.AddPolicy("role_user", "/", "GET", "*")
	f.enforcer.AddPolicy("role_user", "/trail/", "GET", "*")
	f.enforcer.AddPolicy("role_user", "/files/a b", "GET", "*")

	// remainder "/" authorizes path "/"
	if w := f.do("GET", "/external/authz/check/", bearer, ""); w.Code != 200 {
		t.Errorf("root: %d %s", w.Code, w.Body.String())
	}
	// trailing slash is passed through as received
	if w := f.do("GET", "/external/authz/check/trail/", bearer, ""); w.Code != 200 {
		t.Errorf("trailing slash: %d", w.Code)
	}
	if w := f.do("GET", "/external/authz/check/trail", bearer, ""); w.Code != 403 {
		t.Errorf("no trailing slash must not match /trail/: %d", w.Code)
	}
	// encoded characters: c.Param("path") is the decoded path (%20 -> space)
	if w := f.do("GET", "/external/authz/check/files/a%20b", bearer, ""); w.Code != 200 {
		t.Errorf("encoded: %d", w.Code)
	}
	// query string is not part of the authorized path
	if w := f.do("GET", "/external/authz/check/?x=1", bearer, ""); w.Code != 200 {
		t.Errorf("root with query: %d", w.Code)
	}
}

func TestCheck_BuildsEnvoyRequestFromHTTPRequest(t *testing.T) {
	f := newCheckFixture(t)
	// A header rule proves header names are lower-cased and values passed.
	f.enforcer.AddPolicy("role_user", "/h", "POST", "header.x-tenant==token.role")
	w := f.do("POST", "/external/authz/check/h", map[string]string{
		"Authorization": "Bearer valid_token",
		"X-Tenant":      "user",
	}, "{}")
	if w.Code != 200 {
		t.Fatalf("status %d %s", w.Code, w.Body.String())
	}
	// (Body base64 encoding is proven by TestCheck_FieldRuleUsesQueryHeaderAndBody.)
}

func TestCheck_InternalFailure_500_NoDetails(t *testing.T) {
	f := newCheckFixture(t)
	// An internal failure: the rule needs the backend id but no resolver is configured.
	f.enforcer.AddPolicy("role_user", "/bad/:id", "GET", "path.id==token.backend_user_id")
	w := f.do("GET", "/external/authz/check/bad/5", bearer, "")
	if w.Code != 500 {
		t.Fatalf("status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "unsupported") || strings.Contains(w.Body.String(), "details") {
		t.Errorf("leaks internals: %s", w.Body.String())
	}
	if errorBody(t, w) != "Field validation failed" {
		t.Errorf("body %s", w.Body.String())
	}
}

func TestCheck_JSONEndpointStillReportsDetailsOn500(t *testing.T) {
	// The JSON endpoint keeps its historical response (including details).
	f := newCheckFixture(t)
	f.enforcer.AddPolicy("role_user", "/bad/:id", "GET", "path.id==token.backend_user_id")
	r := gin.New()
	r.POST("/external/authz", f.h.Authorize)
	payload := `{"attributes":{"request":{"http":{"method":"GET","path":"/bad/5","headers":{"authorization":"Bearer valid_token"}}}}}`
	req := httptest.NewRequest("POST", "/external/authz", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), `"details"`) {
		t.Errorf("status %d body %s", w.Code, w.Body.String())
	}
}
