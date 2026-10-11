package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExternalAuthzCheckE2E exercises the Envoy HTTP ext_authz compatible
// endpoint (ANY /external/authz/check/*path) against the real router, Casbin
// policies, JWT service and Redis sessions.
func TestExternalAuthzCheckE2E(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)

	helper.MustStart()
	helper.MustWaitForReady()

	userFactory := NewTestUserFactory(t, suite.DB)
	userOpts := DefaultTestUser()
	userOpts.PhoneVerified = true
	userOpts.Role = "user"
	user := userFactory.CreateUserT(userOpts)
	defer suite.DB.Delete(user)

	tokens := loginUser(t, helper, user.Email, userOpts.Password)
	token := tokens["access_token"].(string)

	check := func(method, path, authHeader string) *http.Response {
		req, err := http.NewRequest(method, helper.URL("/external/authz/check"+path), nil)
		require.NoError(t, err)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		return helper.DoRequest(req)
	}

	t.Run("allowed with token returns identity headers", func(t *testing.T) {
		resp := check("GET", "/auth/me", "Bearer "+token)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.NotEmpty(t, resp.Header.Get("x-user-id"))
		assert.Equal(t, "user", resp.Header.Get("x-user-role"))
	})

	t.Run("identity headers are not taken from the client", func(t *testing.T) {
		req, _ := http.NewRequest("GET", helper.URL("/external/authz/check/auth/me"), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("x-user-id", "999")
		req.Header.Set("x-user-role", "admin")
		resp := helper.DoRequest(req)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.NotEqual(t, "999", resp.Header.Get("x-user-id"))
		assert.Equal(t, "user", resp.Header.Get("x-user-role"))
	})

	t.Run("without token is 401", func(t *testing.T) {
		resp := check("GET", "/auth/me", "")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("x-user-id"))
	})

	t.Run("normal user on admin path is 403", func(t *testing.T) {
		resp := check("GET", "/admin/policies", "Bearer "+token)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("x-user-id"))
	})
}
