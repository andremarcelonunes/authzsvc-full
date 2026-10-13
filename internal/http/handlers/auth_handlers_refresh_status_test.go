package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// The status table the app relies on: 401 = must log in; 409/503 = retry the same token.
func TestAuthHandlers_Refresh_StatusTable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name       string
		err        error
		status     int
		retryAfter string
		message    string
	}{
		{"blacklisted (used) token", fmt.Errorf("refresh token already used: %w", domain.ErrTokenInvalid), http.StatusUnauthorized, "", "Invalid or expired refresh token"},
		{"malformed or expired token", domain.ErrTokenExpired, http.StatusUnauthorized, "", "Invalid or expired refresh token"},
		{"session not found", fmt.Errorf("lookup: %w", domain.ErrSessionNotFound), http.StatusUnauthorized, "", "Session expired"},
		{"session expired", fmt.Errorf("x: %w", domain.ErrSessionExpired), http.StatusUnauthorized, "", "Session expired"},
		{"inactive user", domain.ErrUserInactive, http.StatusUnauthorized, "", "User account is inactive"},
		{"concurrent refresh", fmt.Errorf("session s: %w", domain.ErrConcurrentRefresh), http.StatusConflict, "1", "Refresh already in progress, retry shortly"},
		{"redis error", fmt.Errorf("%w: %w", domain.ErrTemporarilyUnavailable, errors.New("dial tcp: refused")), http.StatusServiceUnavailable, "2", "Token refresh temporarily unavailable, retry shortly"},
		{"anything else", errors.New("boom"), http.StatusInternalServerError, "", "Token refresh failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			authSvc := mocks.NewMockAuthService()
			authSvc.RefreshTokenFunc = func(ctx context.Context, refreshToken string) (*domain.AuthResult, error) { return nil, tc.err }
			handler := NewAuthHandlers(authSvc, mocks.NewMockOTPService(), mocks.NewMockUserRepository(), mocks.NewMockTokenService(), mocks.NewMockSessionRepository())
			body, _ := json.Marshal(RefreshRequest{RefreshToken: "tok"})
			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			handler.Refresh(c)

			if w.Code != tc.status {
				t.Fatalf("status = %d, want %d", w.Code, tc.status)
			}
			var parsed map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil || parsed["error"] != tc.message {
				t.Errorf("body = %s, want error %q", w.Body.String(), tc.message)
			}
			if got := w.Header().Get("Retry-After"); got != tc.retryAfter {
				t.Errorf("Retry-After = %q, want %q", got, tc.retryAfter)
			}
		})
	}
}
