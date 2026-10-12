package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/you/authzsvc/domain"
)

// rawCall is appCall returning the raw body too.
func rawCall(t *testing.T, helper *ServerTestHelper, method, path string, body interface{}) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(method, helper.URL(path), bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp := helper.DoRequest(req)
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

var sixDigits = regexp.MustCompile(`\d{6}`)

// lastCodeSentTo reads the reset code from the mock SMS gateway (never from logs).
func lastCodeSentTo(t *testing.T, n *MockNotificationService, phone string) string {
	t.Helper()
	n.mu.RLock()
	defer n.mu.RUnlock()
	for i := len(n.SentMessages) - 1; i >= 0; i-- {
		if n.SentMessages[i].To == phone {
			return sixDigits.FindString(n.SentMessages[i].Message)
		}
	}
	t.Fatalf("no SMS was sent to %s", phone)
	return ""
}

// A phone-only account registers with a 6-character lowercase password, forgets it, resets it with
// phone + SMS code, and then the old password and the old refresh token are dead.
func TestPhoneOnlyAccount_ForgetsPassword_ResetsByPhoneAndCode(t *testing.T) {
	notifier := NewMockNotificationService()
	policy := domain.NewPasswordPolicy(6, false)
	suite, helper := newAppServer(t, ServerOptions{
		RequireRegistrationEmail: false, RequirePhoneVerification: false,
		PasswordPolicy: &policy, PasswordResetByPhone: true, Notifier: notifier,
	})
	phone, unknownPhone := generateTestPhone(), generateTestPhone()
	t.Cleanup(func() { suite.DB.Exec("DELETE FROM users WHERE phone = ?", phone) })
	const oldPassword, newPassword = "abcdef", "uvwxyz"

	// sign-up: phone + 6 lowercase characters is enough
	status, body := appCall(t, helper, http.MethodPost, "/auth/register", "", map[string]string{"phone": phone, "password": oldPassword})
	require.Equal(t, http.StatusCreated, status, "body: %v", body)
	// 5 characters is below the configured minimum: 400 with code and field
	status, body = appCall(t, helper, http.MethodPost, "/auth/register", "", map[string]string{"phone": generateTestPhone(), "password": "abcde"})
	require.Equal(t, http.StatusBadRequest, status)
	assert.Equal(t, "PASSWORD_TOO_SHORT", body["code"])
	assert.Equal(t, "password", body["field"])
	assert.NotEmpty(t, body["error"])

	status, body = appCall(t, helper, http.MethodPost, "/auth/login", "", map[string]string{"identifier": phone, "password": oldPassword})
	require.Equal(t, http.StatusOK, status, "body: %v", body)
	oldRefresh := dataOf(t, body)["refresh_token"].(string)

	// forgot: the answer for a known and an unknown phone is byte-identical
	knownStatus, knownBody := rawCall(t, helper, http.MethodPost, "/password/reset", map[string]string{"phone": phone})
	unknownStatus, unknownBody := rawCall(t, helper, http.MethodPost, "/password/reset", map[string]string{"phone": unknownPhone})
	require.Equal(t, http.StatusOK, knownStatus, string(knownBody))
	assert.Equal(t, knownStatus, unknownStatus)
	assert.Equal(t, string(knownBody), string(unknownBody), "known and unknown phone must get the same bytes")
	assert.Equal(t, 1, notifier.GetMessageCount(), "only the known phone receives an SMS")
	code := lastCodeSentTo(t, notifier, phone)
	require.Len(t, code, 6)

	// a wrong code, an unknown phone and a weak new password are all refused
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	status, _ = rawCall(t, helper, http.MethodPost, "/password/reset/confirm", map[string]string{"phone": phone, "otp_code": wrong, "new_password": newPassword})
	assert.Equal(t, http.StatusBadRequest, status)
	status, _ = rawCall(t, helper, http.MethodPost, "/password/reset/confirm", map[string]string{"phone": unknownPhone, "otp_code": code, "new_password": newPassword})
	assert.Equal(t, http.StatusBadRequest, status)
	status, _ = rawCall(t, helper, http.MethodPost, "/password/reset/confirm", map[string]string{"phone": phone, "otp_code": code, "new_password": "abcde"})
	assert.Equal(t, http.StatusBadRequest, status, "the policy applies to the new password")

	// the right code resets the password
	status, raw := rawCall(t, helper, http.MethodPost, "/password/reset/confirm", map[string]string{"phone": phone, "otp_code": code, "new_password": newPassword})
	require.Equal(t, http.StatusOK, status, string(raw))
	// the code is single-use
	status, _ = rawCall(t, helper, http.MethodPost, "/password/reset/confirm", map[string]string{"phone": phone, "otp_code": code, "new_password": "another1"})
	assert.Equal(t, http.StatusBadRequest, status)

	// old password and old refresh token no longer work; the new password logs in
	status, _ = appCall(t, helper, http.MethodPost, "/auth/login", "", map[string]string{"identifier": phone, "password": oldPassword})
	assert.Equal(t, http.StatusUnauthorized, status)
	status, _ = appCall(t, helper, http.MethodPost, "/auth/refresh", "", map[string]string{"refresh_token": oldRefresh})
	assert.Equal(t, http.StatusUnauthorized, status)
	status, body = appCall(t, helper, http.MethodPost, "/auth/login", "", map[string]string{"identifier": phone, "password": newPassword})
	assert.Equal(t, http.StatusOK, status, "body: %v", body)
}

// With the switch on (the default) the phone-only endpoint does not exist and the old contract holds.
func TestPhoneReset_StrictDefault_ConfirmIsNotFoundAndEmailIsRequired(t *testing.T) {
	_, helper := newAppServer(t, DefaultServerOptions())
	status, _ := rawCall(t, helper, http.MethodPost, "/password/reset/confirm", map[string]string{"phone": generateTestPhone(), "otp_code": "123456", "new_password": "Abcdef12"})
	assert.Equal(t, http.StatusNotFound, status)
	// the legacy request still needs the e-mail
	status, raw := rawCall(t, helper, http.MethodPost, "/password/reset", map[string]string{"phone": generateTestPhone()})
	assert.Equal(t, http.StatusBadRequest, status, string(raw))
	assert.True(t, strings.Contains(string(raw), "Email"), string(raw))
}
