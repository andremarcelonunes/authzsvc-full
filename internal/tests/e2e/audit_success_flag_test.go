package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/you/authzsvc/domain"
)

// TestAuditTrailPersistsLoginSuccessFlag goes through the real HTTP login path and the
// real PostgreSQL persistence and asserts that the stored audit events carry the
// correct success flag (failed login -> false, successful login -> true).
func TestAuditTrailPersistsLoginSuccessFlag(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)
	helper.MustStart()
	helper.MustWaitForReady()

	opts := DefaultTestUser()
	opts.PhoneVerified = true
	user := NewTestUserFactory(t, suite.DB).CreateUserT(opts)
	defer suite.DB.Delete(user)
	// Failed logins are audited with the identifier in metadata (user_id is not set), so match on it.
	defer suite.DB.Where("metadata->>'email' = ?", user.Email).Delete(&domain.ComprehensiveAuditEvent{})

	login := func(password string) int {
		body, err := json.Marshal(map[string]string{"email": user.Email, "password": password})
		require.NoError(t, err)
		req, err := http.NewRequest("POST", helper.URL("/auth/login"), bytes.NewBuffer(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		resp := helper.DoRequest(req)
		resp.Body.Close()
		return resp.StatusCode
	}

	assert.Equal(t, http.StatusUnauthorized, login("WrongPassword123!"), "wrong password must be rejected")
	assert.Equal(t, http.StatusOK, login(opts.Password), "correct password must succeed")

	var failures, successes []domain.ComprehensiveAuditEvent
	require.NoError(t, suite.DB.Where("metadata->>'email' = ? AND event_type = ?", user.Email, domain.EventTypeLoginFailure).Find(&failures).Error)
	require.NoError(t, suite.DB.Where("metadata->>'email' = ? AND event_type = ?", user.Email, domain.EventTypeLoginSuccess).Find(&successes).Error)

	require.Len(t, failures, 1, "exactly one login_failure event expected")
	require.Len(t, successes, 1, "exactly one login_success event expected")
	assert.False(t, failures[0].Success, "login_failure must be stored with success = false")
	assert.True(t, successes[0].Success, "login_success must be stored with success = true")
}
