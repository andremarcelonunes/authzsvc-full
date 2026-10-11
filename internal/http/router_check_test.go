package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/http/handlers"
	"github.com/you/authzsvc/internal/http/middleware"
	"github.com/you/authzsvc/internal/mocks"
)

func TestBuildRouter_ExternalAuthzRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)

	m, err := model.NewModelFromString(`
[request_definition]
r = sub, obj, act, field

[policy_definition]
p = sub, obj, act, field

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && r.obj == p.obj && r.act == p.act
`)
	if err != nil {
		t.Fatal(err)
	}
	enforcer, err := casbin.NewEnforcer(m)
	if err != nil {
		t.Fatal(err)
	}
	enforcer.AddPolicy("role_user", "/some/path", "GET", "*")

	tokenSvc := mocks.NewMockTokenService()
	tokenSvc.ValidateAccessTokenFunc = func(string) (*domain.TokenClaims, error) {
		return &domain.TokenClaims{UserID: 7, Role: "user", SessionID: "s"}, nil
	}
	sessions := mocks.NewMockSessionRepository()
	sessions.FindByIDFunc = func(_ context.Context, id string) (*domain.Session, error) {
		return &domain.Session{ID: id, UserID: 7}, nil
	}
	eh := handlers.NewExternalAuthzHandlers(tokenSvc, sessions, enforcer, nil)

	var r *gin.Engine
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("router registration panicked: %v", rec)
			}
		}()
		r = BuildRouter(nil, nil, eh, handlers.NewSwaggerDocsHandler(), nil,
			middleware.NewAuthMW(tokenSvc, sessions), middleware.NewSimpleCasbinMW(enforcer))
	}()

	routes := map[string]bool{}
	for _, ri := range r.Routes() {
		routes[ri.Method+" "+ri.Path] = true
	}
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"} {
		if !routes[method+" /external/authz/check/*path"] {
			t.Errorf("%s /external/authz/check/*path not registered", method)
		}
	}
	if !routes["POST /external/authz"] {
		t.Error("POST /external/authz not registered")
	}

	// New route: Envoy-style, decision by status, identity by response headers.
	req := httptest.NewRequest("GET", "/external/authz/check/some/path", nil)
	req.Header.Set("Authorization", "Bearer x")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get("x-user-id") != "7" || w.Body.Len() != 0 {
		t.Errorf("check route: status %d headers %v body %q", w.Code, w.Header(), w.Body.String())
	}

	// Old route: JSON in, JSON out, untouched.
	payload := `{"attributes":{"request":{"http":{"method":"GET","path":"/some/path","headers":{"authorization":"Bearer x"}}}}}`
	req = httptest.NewRequest("POST", "/external/authz", stringsReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Header().Get("x-user-id") != "" ||
		!contains(w.Body.String(), `"x-user-id":"7"`) {
		t.Errorf("json route: status %d headers %v body %q", w.Code, w.Header(), w.Body.String())
	}
}

func stringsReader(s string) *strings.Reader { return strings.NewReader(s) }
func contains(s, sub string) bool            { return strings.Contains(s, sub) }
