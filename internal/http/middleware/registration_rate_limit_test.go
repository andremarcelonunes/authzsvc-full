package middleware

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
	"github.com/you/authzsvc/internal/services"
)

// registrationsAccepted sends attempts POST /auth/register requests from one IP through the HTTP
// validation middleware (real per-IP rate limiter on miniredis) and counts those that reach the handler.
func registrationsAccepted(t *testing.T, perMinute, attempts int) int {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(mr.Close)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })

	mw := NewValidationMiddleware(
		mocks.NewMockRequestValidationService(), mocks.NewMockSecurityValidationService(), mocks.NewMockBusinessValidationService(),
		services.NewRateLimitValidationService(rdb, services.RateLimitConfig{}),
		nil, nil, ValidationConfig{EnableRateLimiting: true, ValidationTimeout: 5 * time.Second, MaxRequestSize: 1 << 20, RegistrationRequestsPerMinute: perMinute})

	reached := 0
	r := gin.New()
	r.Use(mw.ValidateRequest())
	r.POST("/auth/register", func(c *gin.Context) { reached++; c.Status(http.StatusCreated) })

	for i := 0; i < attempts; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBufferString(`{"phone":"+14155550100","password":"abcdef"}`))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "203.0.113.5:1234"
		r.ServeHTTP(httptest.NewRecorder(), req)
	}
	return reached
}

func TestRegisterRateLimit_HTTPLayerDefaultIsFourPerMinute(t *testing.T) {
	if got := registrationsAccepted(t, 0, 10); got != 4 {
		t.Errorf("default must stay 4 per minute, got %d", got)
	}
}

func TestRegisterRateLimit_HTTPLayerLowSetting(t *testing.T) {
	if got := registrationsAccepted(t, 1, 5); got != 1 {
		t.Errorf("a budget of 1 must accept exactly 1, got %d", got)
	}
}

func TestRegisterRateLimit_HTTPLayerHighSetting(t *testing.T) {
	if got := registrationsAccepted(t, 120, 130); got != 120 {
		t.Errorf("a budget of 120 must accept exactly 120, got %d", got)
	}
}

func TestRegistrationRequestsPerMinute_FollowsLimitAndWindow(t *testing.T) {
	cases := []struct {
		limit  int
		window string
		want   int
	}{
		{0, "0s", 4}, // unset = today's defaults (2 per 30s)
		{2, "30s", 4},
		{1, "60s", 1},
		{100, "60s", 100},
		{50, "30s", 100},
		{1, "1h", 1}, // never below 1
	}
	for _, tc := range cases {
		d := durationOf(t, tc.window)
		if got := domain.RegistrationRequestsPerMinute(tc.limit, d); got != tc.want {
			t.Errorf("RegistrationRequestsPerMinute(%d, %s) = %d, want %d", tc.limit, tc.window, got, tc.want)
		}
	}
}

func durationOf(t *testing.T, s string) (d time.Duration) {
	t.Helper()
	d, err := time.ParseDuration(s)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// The middleware validates the registration body but must not count it against the per-IP
// registration limit: the auth service counts it once when it creates the account.
func TestRegister_MiddlewareDoesNotConsumeTheRegistrationLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	validator := mocks.NewMockRequestValidationService()
	var skipped []bool
	validator.ValidateRegistrationRequestFunc = func(ctx context.Context, email, phone, password, role string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
		skipped = append(skipped, validationCtx.SkipRegistrationRateLimit)
		return &domain.ValidationResult{IsValid: true, Passed: true}, nil
	}
	mw := NewValidationMiddleware(
		validator, mocks.NewMockSecurityValidationService(), mocks.NewMockBusinessValidationService(),
		mocks.NewMockRateLimitValidationService(),
		nil, nil, ValidationConfig{ValidationTimeout: 5 * time.Second, MaxRequestSize: 1 << 20})

	r := gin.New()
	r.Use(mw.ValidateRequest())
	r.POST("/auth/register", func(c *gin.Context) { c.Status(http.StatusCreated) })
	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBufferString(`{"phone":"+14155550100","password":"abcdef"}`))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(httptest.NewRecorder(), req)

	if len(skipped) != 1 || !skipped[0] {
		t.Fatalf("expected one validation call that skips the registration limit, got %v", skipped)
	}
}
