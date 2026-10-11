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

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

func newRolesTestHandler(authSvc *mocks.MockAuthService) *AuthHandlers {
	return NewAuthHandlers(authSvc, mocks.NewMockOTPService(), mocks.NewMockUserRepository(), mocks.NewMockTokenService(), mocks.NewMockSessionRepository())
}

func TestAuthHandlers_Register_PrivilegedRoleForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := mocks.NewMockAuthService()
	authSvc.RegisterFunc = func(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
		return nil, domain.ErrRoleNotAllowedForRegistration
	}
	h := newRolesTestHandler(authSvc)

	body, _ := json.Marshal(map[string]string{"email": "a@example.com", "phone": "+5511999990000", "password": "Passw0rd!", "role": "admin"})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")
	h.Register(c)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if msg, _ := resp["error"].(string); msg == "" {
		t.Errorf("expected error message, got %v", resp)
	}
}

func TestAuthHandlers_Register_DefaultsRoleToUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var gotRole string
	authSvc := mocks.NewMockAuthService()
	authSvc.RegisterFunc = func(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
		gotRole = role
		return &domain.User{ID: 3, Role: role}, nil
	}
	h := newRolesTestHandler(authSvc)
	body, _ := json.Marshal(map[string]string{"email": "a@example.com", "phone": "+5511999990000", "password": "Passw0rd!"})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")
	h.Register(c)
	if w.Code != http.StatusCreated || gotRole != domain.RoleUser {
		t.Fatalf("expected 201 with role user, got %d role %q", w.Code, gotRole)
	}
}

func doAdminCreate(t *testing.T, h *AuthHandlers, ctxVals map[string]interface{}, body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/admin/users", bytes.NewBuffer(raw))
	c.Request.Header.Set("Content-Type", "application/json")
	for k, v := range ctxVals {
		c.Set(k, v)
	}
	h.AdminCreateUser(c)
	return w
}

func TestAuthHandlers_AdminCreateUser(t *testing.T) {
	gin.SetMode(gin.TestMode)
	valid := map[string]string{"email": "n@example.com", "phone": "+5511988887777", "password": "Passw0rd!", "role": "attendant"}
	adminCtx := map[string]interface{}{"user_id": "5", "user_role": "admin"}

	tests := []struct {
		name    string
		ctxVals map[string]interface{}
		body    map[string]string
		svcErr  error
		status  int
	}{
		{"created", adminCtx, valid, nil, http.StatusCreated},
		{"role not allowed", adminCtx, valid, domain.ErrRoleCreationNotAllowed, http.StatusForbidden},
		{"duplicate", adminCtx, valid, domain.ErrUserAlreadyExists, http.StatusConflict},
		{"otp throttled", adminCtx, valid, fmt.Errorf("x: %w", domain.ErrOTPResendThrottled), http.StatusTooManyRequests},
		{"internal error", adminCtx, valid, errors.New("boom"), http.StatusInternalServerError},
		{"missing role", adminCtx, map[string]string{"email": "n@example.com", "phone": "+5511988887777", "password": "Passw0rd!"}, nil, http.StatusBadRequest},
		{"missing email", adminCtx, map[string]string{"phone": "+5511988887777", "password": "Passw0rd!", "role": "user"}, nil, http.StatusBadRequest},
		{"missing phone", adminCtx, map[string]string{"email": "n@example.com", "password": "Passw0rd!", "role": "user"}, nil, http.StatusBadRequest},
		{"missing password", adminCtx, map[string]string{"email": "n@example.com", "phone": "+5511988887777", "role": "user"}, nil, http.StatusBadRequest},
		{"bad email", adminCtx, map[string]string{"email": "nope", "phone": "+5511988887777", "password": "Passw0rd!", "role": "user"}, nil, http.StatusBadRequest},
		{"no auth context", nil, valid, nil, http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			authSvc := mocks.NewMockAuthService()
			var gotCreator *domain.User
			var gotRole string
			authSvc.CreateUserByAdminFunc = func(ctx context.Context, creator *domain.User, email, phone, password, role string) (*domain.User, error) {
				gotCreator, gotRole = creator, role
				if tc.svcErr != nil {
					return nil, tc.svcErr
				}
				return &domain.User{ID: 99, Role: role}, nil
			}
			w := doAdminCreate(t, newRolesTestHandler(authSvc), tc.ctxVals, tc.body)
			if w.Code != tc.status {
				t.Fatalf("expected %d, got %d (%s)", tc.status, w.Code, w.Body.String())
			}
			var resp map[string]interface{}
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if tc.status == http.StatusCreated {
				data, _ := resp["data"].(map[string]interface{})
				if data["user_id"] != float64(99) || data["role"] != "attendant" || data["message"] == "" {
					t.Errorf("unexpected body %v", resp)
				}
				if gotCreator == nil || gotCreator.ID != 5 || gotCreator.Role != "admin" || gotRole != "attendant" {
					t.Errorf("creator must come from the JWT context, got %+v role %q", gotCreator, gotRole)
				}
			} else if _, ok := resp["error"].(string); !ok {
				t.Errorf("expected {\"error\": ...}, got %v", resp)
			}
		})
	}
}

func TestAuthHandlers_Register_RateLimited429(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authSvc := mocks.NewMockAuthService()
	authSvc.RegisterFunc = func(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
		return nil, fmt.Errorf("wrapped: %w", domain.ErrRegistrationRateLimited)
	}
	h := newRolesTestHandler(authSvc)
	body, _ := json.Marshal(map[string]string{"email": "a@example.com", "phone": "+5511999990000", "password": "Passw0rd!", "role": "client"})
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBuffer(body))
	c.Request.Header.Set("Content-Type", "application/json")
	h.Register(c)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", w.Code)
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if msg, _ := resp["error"].(string); msg == "" {
		t.Errorf("expected error body, got %v", resp)
	}
}

func TestAuthHandlers_RegistrationValidationErrors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	valid := map[string]string{"email": "n@example.com", "phone": "+5511988887777", "password": "Secr3tInput!", "role": "user"}
	tests := []struct {
		name       string
		err        error
		status     int
		wantError  string
		wantCode   string
		wantField  string
		noEchoText string
	}{
		{"weak password", fmt.Errorf("wrap: %w", &domain.RegistrationValidationError{Code: "PASSWORD_TOO_SHORT", Field: "password", Message: "Password must be at least 8 characters long"}),
			http.StatusBadRequest, "Password must be at least 8 characters long", "PASSWORD_TOO_SHORT", "password", ""},
		{"no field", &domain.RegistrationValidationError{Code: "ROLE_INVALID", Message: "Invalid role specified"},
			http.StatusBadRequest, "Invalid role specified", "ROLE_INVALID", "", ""},
		{"security threat", &domain.RegistrationValidationError{Code: "SECURITY_THREAT", Field: "registration", Message: "Security threat detected: <script>Secr3tInput!"},
			http.StatusBadRequest, securityRejectedMessage, "SECURITY_THREAT", "", "Secr3tInput!"},
		{"plain error", errors.New("redis down"), http.StatusInternalServerError, "", "", "", ""},
	}
	routes := map[string]func(*AuthHandlers, *mocks.MockAuthService, error) *httptest.ResponseRecorder{
		"register": func(h *AuthHandlers, m *mocks.MockAuthService, err error) *httptest.ResponseRecorder {
			m.RegisterFunc = func(ctx context.Context, e, p, pw, r string) (*domain.User, error) { return nil, err }
			raw, _ := json.Marshal(valid)
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBuffer(raw))
			c.Request.Header.Set("Content-Type", "application/json")
			h.Register(c)
			return w
		},
		"admin": func(h *AuthHandlers, m *mocks.MockAuthService, err error) *httptest.ResponseRecorder {
			m.CreateUserByAdminFunc = func(ctx context.Context, cr *domain.User, e, p, pw, r string) (*domain.User, error) {
				return nil, err
			}
			return doAdminCreate(t, h, map[string]interface{}{"user_id": "5", "user_role": "admin"}, valid)
		},
	}
	for route, call := range routes {
		for _, tc := range tests {
			t.Run(route+"/"+tc.name, func(t *testing.T) {
				m := mocks.NewMockAuthService()
				w := call(newRolesTestHandler(m), m, tc.err)
				if w.Code != tc.status {
					t.Fatalf("expected %d, got %d (%s)", tc.status, w.Code, w.Body.String())
				}
				var resp map[string]interface{}
				_ = json.Unmarshal(w.Body.Bytes(), &resp)
				if tc.status == http.StatusInternalServerError {
					return
				}
				if resp["error"] != tc.wantError || resp["code"] != tc.wantCode {
					t.Errorf("unexpected body %v", resp)
				}
				if f, has := resp["field"]; (tc.wantField == "") == has || (has && f != tc.wantField) {
					t.Errorf("unexpected field in %v", resp)
				}
				if tc.noEchoText != "" && strings.Contains(w.Body.String(), tc.noEchoText) {
					t.Errorf("body echoes input: %s", w.Body.String())
				}
			})
		}
	}
}
