package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
	"github.com/you/authzsvc/internal/services"
)

func postRaw(t *testing.T, r *gin.Engine, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func decode(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON: %q", w.Body.String())
	}
	return out
}

func wantSMSLimit(t *testing.T, w *httptest.ResponseRecorder, retry string) {
	t.Helper()
	out := decode(t, w)
	if w.Code != http.StatusTooManyRequests || out["error"] != "sms_limit" ||
		out["message"] != "Limite de envio de códigos atingido. Tente novamente mais tarde." ||
		out["retry_after_seconds"] != float64(90) || len(out) != 3 {
		t.Errorf("unexpected 429 answer: %d %v", w.Code, out)
	}
	if w.Header().Get("Retry-After") != retry {
		t.Errorf("Retry-After = %q, want %q", w.Header().Get("Retry-After"), retry)
	}
}

func wantSMSUnavailable(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	out := decode(t, w)
	if w.Code != http.StatusServiceUnavailable || out["error"] != "sms_unavailable" || out["message"] == nil || len(out) != 2 {
		t.Errorf("unexpected 503 answer: %d %v", w.Code, out)
	}
}

func limit90() error {
	return &domain.SMSLimitError{Kind: domain.SMSLimitPhoneInterval, RetryAfter: 90 * time.Second}
}

func TestSendOTP_SMSLimitAnswers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for name, tc := range map[string]struct {
		err  error
		want func(*testing.T, *httptest.ResponseRecorder)
	}{
		"per-phone limit":    {limit90(), func(t *testing.T, w *httptest.ResponseRecorder) { wantSMSLimit(t, w, "90") }},
		"installation cap":   {fmt.Errorf("failed to send OTP SMS: %w", domain.ErrSMSUnavailable), wantSMSUnavailable},
		"wrapped phone limit": {fmt.Errorf("failed to send OTP SMS: %w", limit90()), func(t *testing.T, w *httptest.ResponseRecorder) { wantSMSLimit(t, w, "90") }},
	} {
		t.Run(name, func(t *testing.T) {
			userRepo := mocks.NewMockUserRepository()
			userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
				return &domain.User{ID: 7, Phone: "+5511999990000", IsActive: true}, nil
			}
			otp := mocks.NewMockOTPService()
			otp.GenerateFunc = func(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) { return nil, tc.err }
			h := NewAuthHandlers(mocks.NewMockAuthService(), otp, userRepo, mocks.NewMockTokenService(), mocks.NewMockSessionRepository())
			r := gin.New()
			r.POST("/auth/otp/send", h.SendOTP)
			tc.want(t, postRaw(t, r, "/auth/otp/send", `{"phone":"+5511999990000","user_id":7}`))
		})
	}
}

func TestSendOTP_VerifiedPhoneAnswers409AndPassesTheCallerAddress(t *testing.T) {
	gin.SetMode(gin.TestMode)
	user := &domain.User{ID: 7, Phone: "+5511999990000", IsActive: true, PhoneVerified: true}
	userRepo := mocks.NewMockUserRepository()
	userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) { return user, nil }
	var seenIP string
	otp := mocks.NewMockOTPService()
	otp.GenerateFunc = func(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) {
		seenIP = domain.ClientIPFrom(ctx)
		return &domain.OTPRequest{}, nil
	}
	h := NewAuthHandlers(mocks.NewMockAuthService(), otp, userRepo, mocks.NewMockTokenService(), mocks.NewMockSessionRepository())
	r := gin.New()
	r.POST("/auth/otp/send", h.SendOTP)

	w := postRaw(t, r, "/auth/otp/send", `{"phone":"+5511999990000","user_id":7}`)
	if out := decode(t, w); w.Code != http.StatusConflict || out["error"] != "phone_already_verified" {
		t.Errorf("a verified phone: %d %v", w.Code, out)
	}
	user.PhoneVerified = false
	req := httptest.NewRequest(http.MethodPost, "/auth/otp/send", bytes.NewBufferString(`{"phone":"+5511999990000","user_id":7}`))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.7:1234"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || seenIP != "198.51.100.7" {
		t.Errorf("an unverified phone gets its code, with the caller address: %d ip=%q", rec.Code, seenIP)
	}
}

func TestRegister_SMSLimitAnswers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for name, tc := range map[string]struct {
		err  error
		want func(*testing.T, *httptest.ResponseRecorder)
	}{
		"limit":       {fmt.Errorf("failed to send OTP: %w", limit90()), func(t *testing.T, w *httptest.ResponseRecorder) { wantSMSLimit(t, w, "90") }},
		"unavailable": {fmt.Errorf("failed to send OTP: %w", domain.ErrSMSUnavailable), wantSMSUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			authSvc := mocks.NewMockAuthService()
			authSvc.RegisterFunc = func(ctx context.Context, email, phone, password, role string) (*domain.User, error) { return nil, tc.err }
			h := NewAuthHandlers(authSvc, mocks.NewMockOTPService(), mocks.NewMockUserRepository(), mocks.NewMockTokenService(), mocks.NewMockSessionRepository(), WithRequireRegistrationEmail(false))
			r := gin.New()
			r.POST("/auth/register", h.Register)
			tc.want(t, postRaw(t, r, "/auth/register", `{"phone":"+5511999990000","password":"Secret123!"}`))
		})
	}
}

func TestPasswordChange_SMSLimitAnswers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for name, tc := range map[string]struct {
		err  error
		want func(*testing.T, *httptest.ResponseRecorder)
	}{
		"limit":       {limit90(), func(t *testing.T, w *httptest.ResponseRecorder) { wantSMSLimit(t, w, "90") }},
		"unavailable": {domain.ErrSMSUnavailable, wantSMSUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			userRepo := mocks.NewMockUserRepository()
			userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
				return &domain.User{ID: 7, Phone: "+5511999990000", PasswordHash: "hashed_oldpass", IsActive: true}, nil
			}
			otp := mocks.NewMockOTPService()
			otp.GenerateFunc = func(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) { return nil, tc.err }
			svc := services.NewPasswordChangeService(mocks.NewMockPasswordChangeRepository(), mocks.NewMockPasswordHistoryRepository(),
				mocks.NewMockForgotPasswordRepository(), userRepo, mocks.NewMockPasswordService(), otp, mocks.NewMockSessionRepository(), nil,
				services.DefaultPasswordChangeConfig(), services.WithPasswordChangePolicy(domain.NewPasswordPolicy(6, false)))
			h := NewPasswordChangeHandlers(svc)
			r := gin.New()
			r.Use(func(c *gin.Context) { c.Set("user_id", uint(7)) })
			r.POST("/password/change", h.InitiatePasswordChange)
			tc.want(t, postRaw(t, r, "/password/change", `{"current_password":"oldpass","new_password":"newpass1","confirm_password":"newpass1"}`))
		})
	}
}

func TestSMSUsageHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	budget := &usageBudget{usage: domain.SMSUsage{Today: 3, Month: 41, DailyCap: 100, MonthlyCap: 1000}}
	r := gin.New()
	r.GET("/admin/sms/usage", NewSMSUsageHandler(budget).Usage)

	req := httptest.NewRequest(http.MethodGet, "/admin/sms/usage", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	out := decode(t, w)
	data, _ := out["data"].(map[string]interface{})
	if w.Code != http.StatusOK || data["today"] != float64(3) || data["month"] != float64(41) || data["daily_cap"] != float64(100) || data["monthly_cap"] != float64(1000) || len(data) != 4 {
		t.Errorf("unexpected usage answer: %d %v", w.Code, out)
	}
	if strings.Contains(w.Body.String(), "+55") {
		t.Error("the usage answer must carry no phone numbers")
	}

	budget.err = errors.New("redis down")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/sms/usage", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("a store failure is a 503, got %d", w.Code)
	}
}

type usageBudget struct {
	usage domain.SMSUsage
	err   error
}

func (b *usageBudget) Reserve(ctx context.Context, t domain.SMSTarget) error { return nil }
func (b *usageBudget) Release(ctx context.Context, t domain.SMSTarget) error { return nil }
func (b *usageBudget) RecordSent(ctx context.Context) error                  { return nil }
func (b *usageBudget) Usage(ctx context.Context) (domain.SMSUsage, error)    { return b.usage, b.err }
