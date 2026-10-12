package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// A person whose phone is not verified (correct password) must be able to learn the user_id and phone
// the verification calls need; otherwise a lost registration answer leaves them with no way forward.
func TestLogin_UnverifiedPhoneAnswerCarriesWhatTheVerificationCallsNeed(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := mocks.NewMockAuthService()
	authSvc.AuthenticateUserFunc = func(ctx context.Context, r *domain.AuthRequest) (*domain.AuthResult, error) {
		return nil, &domain.AuthFailureError{UserID: 7, Err: domain.ErrPhoneNotVerified}
	}
	h := NewAuthHandlers(authSvc, mocks.NewMockOTPService(), mocks.NewMockUserRepository(), mocks.NewMockTokenService(), mocks.NewMockSessionRepository())
	r := gin.New()
	r.POST("/auth/login", h.Login)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString(`{"identifier":"+5511999990000","password":"Secret123!"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	out := decode(t, w)
	if w.Code != http.StatusForbidden || out["code"] != "phone_not_verified" || out["user_id"] != float64(7) {
		t.Errorf("expected 403 with code phone_not_verified and user_id 7, got %d %v", w.Code, out)
	}
	if out["error"] == nil {
		t.Error("the legacy error text must stay")
	}
}
