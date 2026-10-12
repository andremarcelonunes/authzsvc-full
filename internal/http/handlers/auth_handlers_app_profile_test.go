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

func postJSON(t *testing.T, call func(c *gin.Context), path string, body interface{}, ctxVals map[string]interface{}) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	raw, _ := json.Marshal(body)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, path, bytes.NewBuffer(raw))
	c.Request.Header.Set("Content-Type", "application/json")
	for k, v := range ctxVals {
		c.Set(k, v)
	}
	call(c)
	return w
}

func responseMessage(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Data struct {
			Message string `json:"message"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("not JSON: %q", w.Body.String())
	}
	return resp.Data.Message
}

// ---- REQUIRE_REGISTRATION_EMAIL ----

func TestRegister_EmailSwitch(t *testing.T) {
	phoneOnly := map[string]string{"phone": "+5511999990000", "password": "Passw0rd!"}
	emptyEmail := map[string]string{"email": "", "phone": "+5511999990000", "password": "Passw0rd!"}
	badEmail := map[string]string{"email": "not-an-email", "phone": "+5511999990000", "password": "Passw0rd!"}
	goodEmail := map[string]string{"email": "a@example.com", "phone": "+5511999990000", "password": "Passw0rd!"}

	tests := []struct {
		name         string
		requireEmail bool
		body         map[string]string
		wantStatus   int
		wantEmail    string
	}{
		{"required: missing email rejected", true, phoneOnly, http.StatusBadRequest, ""},
		{"required: empty email rejected", true, emptyEmail, http.StatusBadRequest, ""},
		{"required: email accepted", true, goodEmail, http.StatusCreated, "a@example.com"},
		{"optional: missing email accepted", false, phoneOnly, http.StatusCreated, ""},
		{"optional: empty email accepted", false, emptyEmail, http.StatusCreated, ""},
		{"optional: an email that is sent is still validated", false, badEmail, http.StatusBadRequest, ""},
		{"optional: valid email accepted", false, goodEmail, http.StatusCreated, "a@example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			authSvc := mocks.NewMockAuthService()
			called := false
			gotEmail := "unset"
			authSvc.RegisterFunc = func(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
				called, gotEmail = true, email
				return &domain.User{ID: 9, Role: role}, nil
			}
			h := NewAuthHandlers(authSvc, mocks.NewMockOTPService(), mocks.NewMockUserRepository(), mocks.NewMockTokenService(),
				mocks.NewMockSessionRepository(), WithRequireRegistrationEmail(tc.requireEmail))
			w := postJSON(t, h.Register, "/auth/register", tc.body, nil)
			if w.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d (%s)", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantStatus == http.StatusCreated && (!called || gotEmail != tc.wantEmail) {
				t.Errorf("service called=%v with email %q, want %q", called, gotEmail, tc.wantEmail)
			}
			if tc.wantStatus == http.StatusBadRequest && called {
				t.Error("service must not be called for an invalid request")
			}
		})
	}
}

func TestRegister_DefaultRequiresEmail(t *testing.T) {
	h := NewAuthHandlers(mocks.NewMockAuthService(), mocks.NewMockOTPService(), mocks.NewMockUserRepository(), mocks.NewMockTokenService(), mocks.NewMockSessionRepository())
	w := postJSON(t, h.Register, "/auth/register", map[string]string{"phone": "+5511999990000", "password": "Passw0rd!"}, nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("without options the e-mail must stay mandatory, got %d", w.Code)
	}
}

func TestRegister_ValidationErrorShapeKept(t *testing.T) {
	authSvc := mocks.NewMockAuthService()
	authSvc.RegisterFunc = func(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
		return nil, &domain.RegistrationValidationError{Code: "PHONE_FORMAT_INVALID", Field: "phone", Message: "Phone number format is invalid"}
	}
	h := NewAuthHandlers(authSvc, mocks.NewMockOTPService(), mocks.NewMockUserRepository(), mocks.NewMockTokenService(), mocks.NewMockSessionRepository(), WithRequireRegistrationEmail(false))
	w := postJSON(t, h.Register, "/auth/register", map[string]string{"phone": "12", "password": "Passw0rd!"}, nil)
	var body map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if w.Code != http.StatusBadRequest || body["code"] != "PHONE_FORMAT_INVALID" || body["field"] != "phone" || body["error"] == "" {
		t.Errorf("400 must keep error/code/field: %d %v", w.Code, body)
	}
}

func TestAdminCreateUser_EmailSwitch(t *testing.T) {
	adminCtx := map[string]interface{}{"user_id": "5", "user_role": "admin"}
	body := map[string]string{"phone": "+5511988887777", "password": "Passw0rd!", "role": "client"}

	for _, requireEmail := range []bool{true, false} {
		t.Run(fmt.Sprintf("require_email=%v", requireEmail), func(t *testing.T) {
			authSvc := mocks.NewMockAuthService()
			authSvc.CreateUserByAdminFunc = func(ctx context.Context, creator *domain.User, email, phone, password, role string) (*domain.User, error) {
				return &domain.User{ID: 11, Role: role}, nil
			}
			h := NewAuthHandlers(authSvc, mocks.NewMockOTPService(), mocks.NewMockUserRepository(), mocks.NewMockTokenService(),
				mocks.NewMockSessionRepository(), WithRequireRegistrationEmail(requireEmail))
			w := postJSON(t, h.AdminCreateUser, "/admin/users", body, adminCtx)
			want := http.StatusBadRequest
			if !requireEmail {
				want = http.StatusCreated
			}
			if w.Code != want {
				t.Errorf("status %d, want %d (%s)", w.Code, want, w.Body.String())
			}
			// an e-mail that is sent is still validated
			bad := map[string]string{"email": "nope", "phone": "+5511988887777", "password": "Passw0rd!", "role": "client"}
			if w := postJSON(t, h.AdminCreateUser, "/admin/users", bad, adminCtx); w.Code != http.StatusBadRequest {
				t.Errorf("invalid e-mail must be rejected, got %d", w.Code)
			}
		})
	}
}

// ---- REQUIRE_PHONE_VERIFICATION: the registration message ----

func TestRegister_MessageFollowsPhoneVerificationSwitch(t *testing.T) {
	body := map[string]string{"email": "a@example.com", "phone": "+5511999990000", "password": "Passw0rd!"}
	adminCtx := map[string]interface{}{"user_id": "5", "user_role": "admin"}
	adminBody := map[string]string{"email": "a@example.com", "phone": "+5511999990000", "password": "Passw0rd!", "role": "user"}

	for _, require := range []bool{true, false} {
		h := NewAuthHandlers(mocks.NewMockAuthService(), mocks.NewMockOTPService(), mocks.NewMockUserRepository(), mocks.NewMockTokenService(),
			mocks.NewMockSessionRepository(), WithRequirePhoneVerification(require))

		for name, w := range map[string]*httptest.ResponseRecorder{
			"register": postJSON(t, h.Register, "/auth/register", body, nil),
			"admin":    postJSON(t, h.AdminCreateUser, "/admin/users", adminBody, adminCtx),
		} {
			if w.Code != http.StatusCreated {
				t.Fatalf("%s: status %d", name, w.Code)
			}
			mentionsVerify := strings.Contains(strings.ToLower(responseMessage(t, w)), "verify")
			if mentionsVerify != require {
				t.Errorf("%s require=%v: message %q (mentions verify=%v)", name, require, responseMessage(t, w), mentionsVerify)
			}
		}
	}
}

// ---- POST /auth/roles ----

func TestAddRole(t *testing.T) {
	userCtx := map[string]interface{}{"user_id": "7", "user_role": "user"}
	tests := []struct {
		name       string
		ctxVals    map[string]interface{}
		body       interface{}
		svc        func(ctx context.Context, userID uint, add string) (*domain.User, error)
		wantStatus int
		wantRole   string
	}{
		{"add client", userCtx, map[string]string{"add": "client"},
			func(ctx context.Context, id uint, add string) (*domain.User, error) {
				return &domain.User{ID: id, Role: domain.RoleClient}, nil
			}, http.StatusOK, domain.RoleClient},
		{"no-op returns 200 with the unchanged role", userCtx, map[string]string{"add": "client"},
			func(ctx context.Context, id uint, add string) (*domain.User, error) {
				return &domain.User{ID: id, Role: domain.RoleClientContact}, nil
			}, http.StatusOK, domain.RoleClientContact},
		{"transition not allowed", userCtx, map[string]string{"add": "admin"},
			func(ctx context.Context, id uint, add string) (*domain.User, error) {
				return nil, fmt.Errorf("x: %w", domain.ErrRoleTransitionNotAllowed)
			}, http.StatusForbidden, ""},
		{"inactive user", userCtx, map[string]string{"add": "client"},
			func(ctx context.Context, id uint, add string) (*domain.User, error) {
				return nil, domain.ErrUserInactive
			},
			http.StatusForbidden, ""},
		{"unknown user", userCtx, map[string]string{"add": "client"},
			func(ctx context.Context, id uint, add string) (*domain.User, error) {
				return nil, domain.ErrUserNotFound
			},
			http.StatusNotFound, ""},
		{"internal error", userCtx, map[string]string{"add": "client"},
			func(ctx context.Context, id uint, add string) (*domain.User, error) { return nil, errors.New("boom") },
			http.StatusInternalServerError, ""},
		{"not authenticated", nil, map[string]string{"add": "client"}, nil, http.StatusUnauthorized, ""},
		{"bad user id in context", map[string]interface{}{"user_id": "abc"}, map[string]string{"add": "client"}, nil, http.StatusUnauthorized, ""},
		{"missing add", userCtx, map[string]string{}, nil, http.StatusBadRequest, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			authSvc := mocks.NewMockAuthService()
			var gotID uint
			var gotAdd string
			called := false
			authSvc.AddProfileFunc = func(ctx context.Context, id uint, add string) (*domain.User, error) {
				called, gotID, gotAdd = true, id, add
				return tc.svc(ctx, id, add)
			}
			h := newRolesTestHandler(authSvc)
			w := postJSON(t, h.AddRole, "/auth/roles", tc.body, tc.ctxVals)
			if w.Code != tc.wantStatus {
				t.Fatalf("status %d, want %d (%s)", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantRole != "" {
				var resp struct {
					Data struct {
						Role   string `json:"role"`
						UserID uint   `json:"user_id"`
					} `json:"data"`
				}
				_ = json.Unmarshal(w.Body.Bytes(), &resp)
				if resp.Data.Role != tc.wantRole || resp.Data.UserID != 7 || gotID != 7 || gotAdd != "client" {
					t.Errorf("response %+v, service got id=%d add=%q", resp.Data, gotID, gotAdd)
				}
			}
			if (tc.wantStatus == http.StatusUnauthorized || tc.wantStatus == http.StatusBadRequest) && called {
				t.Error("the service must not be called")
			}
		})
	}
}

// The token verification endpoint returns the phone_verified claim.
func TestVerifyToken_ReturnsPhoneVerified(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, verified := range []bool{true, false} {
		tokenSvc := mocks.NewMockTokenService()
		tokenSvc.ValidateAccessTokenFunc = func(token string) (*domain.TokenClaims, error) {
			return &domain.TokenClaims{UserID: 4, Role: "client", PhoneVerified: verified}, nil
		}
		h := NewAuthHandlers(mocks.NewMockAuthService(), mocks.NewMockOTPService(), mocks.NewMockUserRepository(), tokenSvc, mocks.NewMockSessionRepository())
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodGet, "/auth/verify", nil)
		c.Request.Header.Set("Authorization", "Bearer t")
		h.VerifyToken(c)
		var resp struct {
			User struct {
				PhoneVerified bool `json:"phone_verified"`
			} `json:"user"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != 200 || resp.User.PhoneVerified != verified {
			t.Errorf("verified=%v: %d %s", verified, w.Code, w.Body.String())
		}
	}
}
