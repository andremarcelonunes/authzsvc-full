package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// appCall performs a JSON request against the test server and returns status and decoded body.
func appCall(t *testing.T, helper *ServerTestHelper, method, path, token string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, helper.URL(path), rd)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp := helper.DoRequest(req)
	defer resp.Body.Close()
	var out map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func dataOf(t *testing.T, body map[string]interface{}) map[string]interface{} {
	t.Helper()
	data, ok := body["data"].(map[string]interface{})
	require.True(t, ok, "response must have a data object: %v", body)
	return data
}

func tokenClaims(t *testing.T, suite *TestSuite, access string) jwt.MapClaims {
	t.Helper()
	token, err := jwt.Parse(access, func(*jwt.Token) (interface{}, error) { return []byte(suite.Config.JWTSecret), nil })
	require.NoError(t, err)
	return token.Claims.(jwt.MapClaims)
}

func newAppServer(t *testing.T, opts ServerOptions) (*TestSuite, *ServerTestHelper) {
	t.Helper()
	suite := GetTestSuite()
	server := NewTestServerWithOptions(t, suite, nil, opts)
	helper := NewServerTestHelper(t, server)
	helper.MustStart()
	helper.MustWaitForReady()
	return suite, helper
}

// The mobile-app sign-up: name-less, phone + password only, no OTP, log in by phone, and the
// token says phone_verified=false. Both switches are off.
func TestAppRegistration_PhoneOnly_NoOTP_LoginByPhone(t *testing.T) {
	suite, helper := newAppServer(t, ServerOptions{RequireRegistrationEmail: false, RequirePhoneVerification: false})
	ctx := context.Background()
	const password = "ValidPassword123!"
	phone, otherPhone := generateTestPhone(), generateTestPhone()
	t.Cleanup(func() { suite.DB.Exec("DELETE FROM users WHERE phone IN (?, ?)", phone, otherPhone) })

	// register with phone and password only
	status, body := appCall(t, helper, http.MethodPost, "/auth/register", "", map[string]string{"phone": phone, "password": password})
	require.Equal(t, http.StatusCreated, status, "body: %v", body)
	data := dataOf(t, body)
	userID := int(data["user_id"].(float64))
	assert.NotContains(t, strings.ToLower(data["message"].(string)), "verify", "the message must not tell the user to verify the phone")

	// no OTP was generated
	otpKeys, err := suite.Redis.Keys(ctx, fmt.Sprintf("otp:%s:*", phone)).Result()
	require.NoError(t, err)
	assert.Empty(t, otpKeys, "no OTP may be stored when verification is not required")

	// stored without e-mail as SQL NULL, phone_verified still false
	var row struct {
		EmailIsNull   bool
		PhoneVerified bool
	}
	require.NoError(t, suite.DB.Raw("SELECT email IS NULL AS email_is_null, phone_verified FROM users WHERE id = ?", userID).Scan(&row).Error)
	assert.True(t, row.EmailIsNull, "a missing e-mail must be stored as NULL")
	assert.False(t, row.PhoneVerified, "phone_verified is stored exactly as before")

	// a second user without e-mail does not collide on the unique e-mail index
	status, body = appCall(t, helper, http.MethodPost, "/auth/register", "", map[string]string{"phone": otherPhone, "password": password, "email": ""})
	require.Equal(t, http.StatusCreated, status, "body: %v", body)

	// the same phone again: 409
	status, _ = appCall(t, helper, http.MethodPost, "/auth/register", "", map[string]string{"phone": phone, "password": password})
	assert.Equal(t, http.StatusConflict, status)

	// log in by phone while the phone is unverified
	status, body = appCall(t, helper, http.MethodPost, "/auth/login", "", map[string]string{"identifier": phone, "password": password})
	require.Equal(t, http.StatusOK, status, "body: %v", body)
	access := dataOf(t, body)["access_token"].(string)
	claims := tokenClaims(t, suite, access)
	assert.Equal(t, false, claims["phone_verified"], "token must carry phone_verified=false")
	assert.Equal(t, "user", claims["role"])

	// wrong password is still refused
	status, _ = appCall(t, helper, http.MethodPost, "/auth/login", "", map[string]string{"identifier": phone, "password": "wrong-password"})
	assert.Equal(t, http.StatusUnauthorized, status)

	// the verification endpoint reports the claim, and /auth/me works for the user without e-mail
	req, _ := http.NewRequest(http.MethodGet, helper.URL("/auth/verify"), nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp := helper.DoRequest(req)
	var verify map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&verify)
	resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, false, verify["user"].(map[string]interface{})["phone_verified"])

	status, body = appCall(t, helper, http.MethodGet, "/auth/me", access, nil)
	require.Equal(t, http.StatusOK, status, "body: %v", body)
	assert.Equal(t, "", dataOf(t, body)["email"])

	// OTP endpoints keep working: verifying the phone flips the claim at the next login
	status, body = appCall(t, helper, http.MethodPost, "/auth/otp/send", "", map[string]interface{}{"phone": phone, "user_id": userID})
	require.Equal(t, http.StatusOK, status, "body: %v", body)
	code, err := suite.Redis.Get(ctx, fmt.Sprintf("otp:%s:%d", phone, userID)).Result()
	require.NoError(t, err)
	status, body = appCall(t, helper, http.MethodPost, "/auth/otp/verify", "", map[string]interface{}{"phone": phone, "user_id": userID, "code": code})
	require.Equal(t, http.StatusOK, status, "body: %v", body)
	status, body = appCall(t, helper, http.MethodPost, "/auth/login", "", map[string]string{"identifier": phone, "password": password})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, tokenClaims(t, suite, dataOf(t, body)["access_token"].(string))["phone_verified"])
}

// With the defaults nothing changes: e-mail is mandatory, an OTP is sent and unverified users cannot log in.
func TestAppRegistration_DefaultsStayStrict(t *testing.T) {
	suite, helper := newAppServer(t, DefaultServerOptions())
	ctx := context.Background()
	const password = "ValidPassword123!"
	phone, email := generateTestPhone(), generateTestEmail()
	t.Cleanup(func() { suite.DB.Exec("DELETE FROM users WHERE phone = ?", phone) })

	status, _ := appCall(t, helper, http.MethodPost, "/auth/register", "", map[string]string{"phone": phone, "password": password})
	assert.Equal(t, http.StatusBadRequest, status, "e-mail is required by default")

	status, body := appCall(t, helper, http.MethodPost, "/auth/register", "", map[string]string{"email": email, "phone": phone, "password": password})
	require.Equal(t, http.StatusCreated, status, "body: %v", body)
	assert.Contains(t, strings.ToLower(dataOf(t, body)["message"].(string)), "verify")
	userID := int(dataOf(t, body)["user_id"].(float64))
	_, err := suite.Redis.Get(ctx, fmt.Sprintf("otp:%s:%d", phone, userID)).Result()
	assert.NoError(t, err, "an OTP must be sent by default")

	status, _ = appCall(t, helper, http.MethodPost, "/auth/login", "", map[string]string{"identifier": phone, "password": password})
	assert.Equal(t, http.StatusForbidden, status, "unverified phone cannot log in by default")
	status, _ = appCall(t, helper, http.MethodPost, "/auth/login", "", map[string]string{"email": email, "password": password})
	assert.Equal(t, http.StatusForbidden, status, "unverified phone cannot log in by e-mail by default")
}

// POST /auth/roles end to end: JWT + Casbin + service + refresh.
func TestAppProfile_AddRoleEndToEnd(t *testing.T) {
	suite, helper := newAppServer(t, ServerOptions{RequireRegistrationEmail: false, RequirePhoneVerification: false})
	const password = "ValidPassword123!"
	phone := generateTestPhone()
	t.Cleanup(func() { suite.DB.Exec("DELETE FROM users WHERE phone = ?", phone) })

	status, _ := appCall(t, helper, http.MethodPost, "/auth/register", "", map[string]string{"phone": phone, "password": password})
	require.Equal(t, http.StatusCreated, status)
	status, body := appCall(t, helper, http.MethodPost, "/auth/login", "", map[string]string{"identifier": phone, "password": password})
	require.Equal(t, http.StatusOK, status)
	access, refresh := dataOf(t, body)["access_token"].(string), dataOf(t, body)["refresh_token"].(string)

	// 401 without a token
	status, _ = appCall(t, helper, http.MethodPost, "/auth/roles", "", map[string]string{"add": "client"})
	assert.Equal(t, http.StatusUnauthorized, status)

	// 403 for targets that are not a profile
	for _, target := range []string{"admin", "root", "attendant", "client_contact", "user"} {
		status, _ = appCall(t, helper, http.MethodPost, "/auth/roles", access, map[string]string{"add": target})
		assert.Equal(t, http.StatusForbidden, status, "adding %s must be refused", target)
	}
	// 400 without a body field
	status, _ = appCall(t, helper, http.MethodPost, "/auth/roles", access, map[string]string{})
	assert.Equal(t, http.StatusBadRequest, status)

	// user -> client (200), the old token still says user
	status, body = appCall(t, helper, http.MethodPost, "/auth/roles", access, map[string]string{"add": "client"})
	require.Equal(t, http.StatusOK, status, "body: %v", body)
	assert.Equal(t, "client", dataOf(t, body)["role"])
	assert.Equal(t, "user", tokenClaims(t, suite, access)["role"])

	// the client token may call it again: adding a held profile is a 200 no-op
	status, body = appCall(t, helper, http.MethodPost, "/auth/roles", access, map[string]string{"add": "client"})
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, "client", dataOf(t, body)["role"])

	// client + contact -> client_contact; the refresh yields a token with the new role from the database
	status, body = appCall(t, helper, http.MethodPost, "/auth/roles", access, map[string]string{"add": "contact"})
	require.Equal(t, http.StatusOK, status, "body: %v", body)
	assert.Equal(t, "client_contact", dataOf(t, body)["role"])

	status, body = appCall(t, helper, http.MethodPost, "/auth/refresh", "", map[string]string{"refresh_token": refresh})
	require.Equal(t, http.StatusOK, status, "body: %v", body)
	newAccess := dataOf(t, body)["access_token"].(string)
	assert.Equal(t, "client_contact", tokenClaims(t, suite, newAccess)["role"])

	// the dual role inherits role_user: it can still use the API and keep adding (no-op)
	status, _ = appCall(t, helper, http.MethodGet, "/auth/me", newAccess, nil)
	assert.Equal(t, http.StatusOK, status)
	status, _ = appCall(t, helper, http.MethodPost, "/auth/roles", newAccess, map[string]string{"add": "contact"})
	assert.Equal(t, http.StatusOK, status)

	// an attendant is refused
	attPhone := generateTestPhone()
	opts := DefaultTestUser()
	opts.Role, opts.Phone, opts.Email = "attendant", attPhone, generateTestEmail()
	NewTestUserFactory(t, suite.DB).CreateUserT(opts)
	t.Cleanup(func() { suite.DB.Exec("DELETE FROM users WHERE phone = ?", attPhone) })
	status, body = appCall(t, helper, http.MethodPost, "/auth/login", "", map[string]string{"identifier": attPhone, "password": opts.Password})
	require.Equal(t, http.StatusOK, status, "body: %v", body)
	status, _ = appCall(t, helper, http.MethodPost, "/auth/roles", dataOf(t, body)["access_token"].(string), map[string]string{"add": "client"})
	assert.Equal(t, http.StatusForbidden, status, "an attendant must not take a client profile")
}

// Root/admin may create client_contact; the public endpoint refuses it.
func TestAppProfile_ClientContactCreation(t *testing.T) {
	suite, helper := newAppServer(t, ServerOptions{RequireRegistrationEmail: false, RequirePhoneVerification: false})
	const password = "ValidPassword123!"

	adminOpts := AdminTestUser()
	NewTestUserFactory(t, suite.DB).CreateUserT(adminOpts)
	phone := generateTestPhone()
	t.Cleanup(func() { suite.DB.Exec("DELETE FROM users WHERE phone IN (?, ?)", adminOpts.Phone, phone) })

	status, _ := appCall(t, helper, http.MethodPost, "/auth/register", "", map[string]string{"phone": generateTestPhone(), "password": password, "role": "client_contact"})
	assert.Equal(t, http.StatusForbidden, status, "client_contact is not self-registrable")

	status, body := appCall(t, helper, http.MethodPost, "/auth/login", "", map[string]string{"email": adminOpts.Email, "password": adminOpts.Password})
	require.Equal(t, http.StatusOK, status, "body: %v", body)
	adminToken := dataOf(t, body)["access_token"].(string)

	status, body = appCall(t, helper, http.MethodPost, "/admin/users", adminToken, map[string]string{"phone": phone, "password": password, "role": "client_contact"})
	require.Equal(t, http.StatusCreated, status, "body: %v", body)
	assert.Equal(t, "client_contact", dataOf(t, body)["role"])
}
