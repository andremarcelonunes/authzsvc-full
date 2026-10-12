package httpx

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/http/handlers"
	"github.com/you/authzsvc/internal/http/middleware"
	"github.com/you/authzsvc/internal/mocks"
	"github.com/you/authzsvc/internal/services"
)

const dbError = `failed to check password history: ERROR: relation "auth.password_history" does not exist (SQLSTATE 42P01)`

// phoneResetRouter builds the real router with the phone-only password reset, whose history lookup
// fails the way a database without the table does.
func phoneResetRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	user := &domain.User{ID: 7, Phone: "+5511999990000", PasswordHash: "hashed_old", IsActive: true, Role: "user"}
	userRepo := mocks.NewMockUserRepository()
	userRepo.FindByPhoneFunc = func(ctx context.Context, p string) (*domain.User, error) { return user, nil }
	history := mocks.NewMockPasswordHistoryRepository()
	history.GetRecentPasswordsFunc = func(ctx context.Context, id uint, n int) ([]string, error) { return nil, errors.New(dbError[len("failed to check password history: "):]) }
	otp := mocks.NewMockOTPService()
	otp.VerifyFunc = func(ctx context.Context, phone, code string, userID uint) (bool, error) { return true, nil }
	svc := services.NewPasswordChangeService(mocks.NewMockPasswordChangeRepository(), history, mocks.NewMockForgotPasswordRepository(),
		userRepo, mocks.NewMockPasswordService(), otp, mocks.NewMockSessionRepository(), nil, services.DefaultPasswordChangeConfig(),
		services.WithPasswordChangePolicy(domain.NewPasswordPolicy(6, false)), services.WithPasswordResetRequireEmail(false))
	return BuildRouter(nil, nil, nil, handlers.NewSwaggerDocsHandler(), handlers.NewPasswordChangeHandlers(svc),
		middleware.NewAuthMW(mocks.NewMockTokenService(), mocks.NewMockSessionRepository()), allowAll{})
}

func post(r *gin.Engine, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// A 5xx must not carry the text of the internal error.
func TestInternalErrorTextNeverReachesTheClient(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	w := post(phoneResetRouter(t), "/password/reset/confirm", `{"phone":"+5511999990000","otp_code":"123456","new_password":"newpass1"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected the dependency failure to be a 500, got %d: %s", w.Code, w.Body.String())
	}
	for _, leak := range []string{"password_history", "SQLSTATE", "relation", "auth."} {
		if strings.Contains(w.Body.String(), leak) {
			t.Errorf("the 500 body leaks %q: %s", leak, w.Body.String())
		}
	}
}

// Deliberate client errors keep their exact bodies: the app matches on them.
func TestDeliberateClientErrorBodiesAreUnchanged(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := mocks.NewMockAuthService()
	authSvc.AuthenticateUserFunc = func(ctx context.Context, r *domain.AuthRequest) (*domain.AuthResult, error) {
		return nil, domain.ErrInvalidCredentials
	}
	authSvc.RegisterFunc = func(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
		return nil, domain.ErrUserAlreadyExists
	}
	userRepo := mocks.NewMockUserRepository()
	userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
		return &domain.User{ID: 7, Phone: "+5511999990000", PhoneVerified: true}, nil
	}
	otp := mocks.NewMockOTPService()
	otp.VerifyFunc = func(ctx context.Context, phone, code string, userID uint) (bool, error) { return false, domain.ErrOTPInvalid }
	ah := handlers.NewAuthHandlers(authSvc, otp, userRepo, mocks.NewMockTokenService(), mocks.NewMockSessionRepository(), handlers.WithRequireRegistrationEmail(false))
	r := BuildRouter(ah, nil, nil, handlers.NewSwaggerDocsHandler(), nil,
		middleware.NewAuthMW(mocks.NewMockTokenService(), mocks.NewMockSessionRepository()), allowAll{})

	for _, tc := range []struct {
		path, body, want string
		status           int
	}{
		{"/auth/login", `{"identifier":"+5511999990000","password":"Secret123!"}`, `{"error":"Invalid credentials"}`, 401},
		{"/auth/register", `{"phone":"+5511999990000","password":"Secret123!"}`, `{"error":"User already exists"}`, 409},
		{"/auth/otp/verify", `{"phone":"+5511999990000","code":"000000","user_id":7}`, `{"error":"Invalid OTP code"}`, 400},
		{"/auth/otp/send", `{"phone":"+5511999990000","user_id":7}`, `{"error":"phone_already_verified","message":"Phone number already verified"}`, 409},
	} {
		w := post(r, tc.path, tc.body)
		if w.Code != tc.status || strings.TrimSpace(w.Body.String()) != tc.want {
			t.Errorf("%s: got %d %s, want %d %s", tc.path, w.Code, strings.TrimSpace(w.Body.String()), tc.status, tc.want)
		}
	}
}
