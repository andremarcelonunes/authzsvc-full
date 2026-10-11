package e2e

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/you/authzsvc/internal/infrastructure/identity"
)

// TestExternalAuthzBackendUserIDE2E drives token.backend_user_id through the real router with a
// logged-in user, real Casbin policies and a stub playing the backend's translation endpoint.
func TestExternalAuthzBackendUserIDE2E(t *testing.T) {
	suite := GetTestSuite()
	userFactory := NewTestUserFactory(t, suite.DB)

	userOpts := DefaultTestUser()
	userOpts.PhoneVerified = true
	userOpts.Role = "user"
	user := userFactory.CreateUserT(userOpts)
	adminOpts := AdminTestUser()
	adminOpts.PhoneVerified = true
	admin := userFactory.CreateUserT(adminOpts)
	defer func() {
		suite.DB.Delete(user)
		suite.DB.Delete(admin)
	}()

	// Stub backend: the test user is backend user 58.
	var gotKey string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-API-Key")
		if r.URL.Path == fmt.Sprintf("/api/v1/internal/users/authz/%d/backend", user.ID) {
			w.Write([]byte(fmt.Sprintf(`{"authz_user_id":%d,"backend_user_id":58,"latency_ms":1.2}`, user.ID)))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"detail":"No backend user found"}`))
	}))
	defer stub.Close()

	cacheKey := fmt.Sprintf("%s%d", identity.KeyPrefix, user.ID)
	suite.Redis.Del(context.Background(), cacheKey)
	defer suite.Redis.Del(context.Background(), cacheKey)
	resolver := identity.NewCachedResolver(identity.NewHTTPResolver(stub.URL, "e2e-key", 2*time.Second), suite.Redis)

	server := NewTestServerWithResolver(t, suite, resolver)
	helper := NewServerTestHelper(t, server)
	helper.MustStart()
	helper.MustWaitForReady()

	adminToken := loginUser(t, helper, admin.Email, adminOpts.Password)["access_token"].(string)
	userToken := loginUser(t, helper, user.Email, userOpts.Password)["access_token"].(string)

	addPolicyViaAPI(t, helper, adminToken, []string{"role_user", "/api/v1/users/client/:client_id/contacts", "GET", "path.client_id==token.backend_user_id"})

	check := func(path string) *http.Response {
		req, err := http.NewRequest("GET", helper.URL("/external/authz/check"+path), nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+userToken)
		req.Header.Set("x-backend-user-id", "999")
		return helper.DoRequest(req)
	}

	t.Run("owner is allowed and gets x-backend-user-id", func(t *testing.T) {
		resp := check("/api/v1/users/client/58/contacts")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, []string{"58"}, resp.Header.Values("x-backend-user-id"))
		assert.Equal(t, "e2e-key", gotKey)
	})

	t.Run("another id is denied", func(t *testing.T) {
		resp := check("/api/v1/users/client/59/contacts")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		assert.Empty(t, resp.Header.Get("x-backend-user-id"))
	})

	t.Run("allowed route not needing the backend id still carries the header", func(t *testing.T) {
		resp := check("/auth/me")
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, []string{"58"}, resp.Header.Values("x-backend-user-id"))
		assert.False(t, strings.Contains(resp.Header.Get("x-backend-user-id"), "999"))
	})
}
