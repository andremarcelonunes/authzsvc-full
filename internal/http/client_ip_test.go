package httpx

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/http/handlers"
	"github.com/you/authzsvc/internal/http/middleware"
	"github.com/you/authzsvc/internal/mocks"
)

type allowAll struct{}

func (allowAll) Enforce() gin.HandlerFunc { return func(c *gin.Context) { c.Next() } }

// seenAddress builds the real router, posts to /auth/register (which hands c.ClientIP() to the service
// through the context, the address the SMS budget and the audit see) and returns that address.
func seenAddress(t *testing.T, configure func(*gin.Engine), headers map[string]string) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	var seen string
	authSvc := mocks.NewMockAuthService()
	authSvc.RegisterFunc = func(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
		seen = domain.ClientIPFrom(ctx)
		return &domain.User{ID: 1}, nil
	}
	ah := handlers.NewAuthHandlers(authSvc, mocks.NewMockOTPService(), mocks.NewMockUserRepository(), mocks.NewMockTokenService(), mocks.NewMockSessionRepository(),
		handlers.WithRequireRegistrationEmail(false))
	r := BuildRouter(ah, nil, nil, handlers.NewSwaggerDocsHandler(), nil,
		middleware.NewAuthMW(mocks.NewMockTokenService(), mocks.NewMockSessionRepository()), allowAll{})
	if configure != nil {
		configure(r)
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBufferString(`{"phone":"+5511999990000","password":"Secret123!"}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.7:4242"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("register answered %d: %s", w.Code, w.Body.String())
	}
	return seen
}

// A client-written X-Forwarded-For must not change the address the service sees.
func TestClientIP_ForgedForwardedForIsIgnoredByDefault(t *testing.T) {
	got := seenAddress(t, nil, map[string]string{"X-Forwarded-For": "6.6.6.6, 7.7.7.7", "X-Real-IP": "8.8.8.8"})
	if got != "198.51.100.7" {
		t.Errorf("the address must be the TCP peer 198.51.100.7, a forged header changed it to %q", got)
	}
}

func TestClientIP_NoHeaderConfiguredUsesThePeerWhateverTheClientSends(t *testing.T) {
	got := seenAddress(t, func(r *gin.Engine) { ApplyClientIPPolicy(r, "") },
		map[string]string{"X-Forwarded-For": "6.6.6.6", "X-Envoy-External-Address": "9.9.9.9"})
	if got != "198.51.100.7" {
		t.Errorf("with CLIENT_IP_HEADER empty the address is the TCP peer, got %q", got)
	}
}

func TestClientIP_ConfiguredHeaderIsUsedAndForwardedForStillIgnored(t *testing.T) {
	configure := func(r *gin.Engine) { ApplyClientIPPolicy(r, "X-Envoy-External-Address") }
	got := seenAddress(t, configure, map[string]string{"X-Envoy-External-Address": "203.0.113.20", "X-Forwarded-For": "6.6.6.6", "X-Real-IP": "8.8.8.8"})
	if got != "203.0.113.20" {
		t.Errorf("the configured gateway header must win, got %q", got)
	}
	// Header absent (a request that did not come through the gateway): the TCP peer, never X-Forwarded-For.
	got = seenAddress(t, configure, map[string]string{"X-Forwarded-For": "6.6.6.6"})
	if got != "198.51.100.7" {
		t.Errorf("without the gateway header the TCP peer applies, got %q", got)
	}
}

func TestClientIP_EnhancedRouterIsStrictToo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := BuildEnhancedRouter(nil, nil, handlers.NewExternalAuthzHandlers(mocks.NewMockTokenService(), mocks.NewMockSessionRepository(), nil, nil),
		middleware.NewAuthMW(mocks.NewMockTokenService(), mocks.NewMockSessionRepository()), allowAll{}, MiddlewareConfig{}, MiddlewareDependencies{})
	r.GET("/ip", func(c *gin.Context) { c.String(200, c.ClientIP()) })
	req := httptest.NewRequest(http.MethodGet, "/ip", nil)
	req.RemoteAddr = "198.51.100.7:1"
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Body.String() != "198.51.100.7" {
		t.Errorf("the enhanced router must not trust X-Forwarded-For, got %q", w.Body.String())
	}
}
