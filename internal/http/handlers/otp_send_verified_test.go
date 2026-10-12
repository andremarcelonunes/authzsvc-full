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

// A phone that is already verified must never be sent another verification code.
func TestSendOTP_AlreadyVerifiedPhoneIsNotTexted(t *testing.T) {
	gin.SetMode(gin.TestMode)
	userRepo := mocks.NewMockUserRepository()
	userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
		return &domain.User{ID: 7, Phone: "+5511999990000", PhoneVerified: true, IsActive: true}, nil
	}
	generated := 0
	otp := mocks.NewMockOTPService()
	otp.GenerateFunc = func(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) {
		generated++
		return &domain.OTPRequest{Phone: phone, UserID: userID}, nil
	}
	h := NewAuthHandlers(mocks.NewMockAuthService(), otp, userRepo, mocks.NewMockTokenService(), mocks.NewMockSessionRepository())
	r := gin.New()
	r.POST("/auth/otp/send", h.SendOTP)

	req := httptest.NewRequest(http.MethodPost, "/auth/otp/send", bytes.NewBufferString(`{"phone":"+5511999990000","user_id":7}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if generated != 0 {
		t.Errorf("an SMS was generated for an already verified phone (status %d)", w.Code)
	}
}
