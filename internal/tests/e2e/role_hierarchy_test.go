package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/infrastructure/auth"
	"github.com/you/authzsvc/internal/infrastructure/repositories"
	"github.com/you/authzsvc/internal/mocks"
	"github.com/you/authzsvc/internal/services"
)

func e2eJSON(t *testing.T, helper *ServerTestHelper, method, path, token string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(method, helper.URL(path), bytes.NewBuffer(raw))
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

func e2eVerifyOTP(t *testing.T, helper *ServerTestHelper, suite *TestSuite, userID uint, phone string) {
	t.Helper()
	code, err := suite.Redis.Get(context.Background(), fmt.Sprintf("otp:%s:%d", phone, userID)).Result()
	require.NoError(t, err, "OTP should have been generated for the created account")
	status, _ := e2eJSON(t, helper, "POST", "/auth/otp/verify", "", map[string]interface{}{"phone": phone, "code": code, "user_id": userID})
	require.Equal(t, http.StatusOK, status)
}

func e2eLogin(t *testing.T, helper *ServerTestHelper, email, password string) string {
	t.Helper()
	status, body := e2eJSON(t, helper, "POST", "/auth/login", "", map[string]string{"email": email, "password": password})
	require.Equal(t, http.StatusOK, status)
	return body["data"].(map[string]interface{})["access_token"].(string)
}

// TestRoleHierarchyFlow covers root -> admin -> attendant creation, the attendant being unable
// to create accounts, and the public registration restrictions.
func TestRoleHierarchyFlow(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)
	helper.MustStart()
	helper.MustWaitForReady()

	const password = "Sup3rSecret!Pass"
	rootAcct := services.BootstrapAccount{Email: generateTestEmail(), Phone: generateTestPhone(), Password: password}
	adminEmail, adminPhone := generateTestEmail(), generateTestPhone()
	attEmail, attPhone := generateTestEmail(), generateTestPhone()

	// The shared test database may hold a root from an aborted earlier run; the bootstrap is a no-op then.
	require.NoError(t, suite.DB.Exec("DELETE FROM users WHERE role = ?", domain.RoleRoot).Error)
	t.Cleanup(func() {
		suite.DB.Exec("DELETE FROM users WHERE email IN (?, ?, ?)", rootAcct.Email, adminEmail, attEmail)
	})

	// Root is created by the bootstrap service (installation).
	boot := services.NewBootstrapService(repositories.NewUserRepository(suite.DB), auth.NewPasswordService(), mocks.NewMockBusinessValidationService(), nil, nil)
	created, err := boot.EnsureRootAdmin(context.Background(), rootAcct)
	require.NoError(t, err)
	require.True(t, created)
	created, err = boot.EnsureRootAdmin(context.Background(), rootAcct)
	require.NoError(t, err)
	assert.False(t, created, "second bootstrap run must not create another root")

	rootToken := e2eLogin(t, helper, rootAcct.Email, password)

	// root creates an admin
	status, body := e2eJSON(t, helper, "POST", "/admin/users", rootToken, map[string]string{
		"email": adminEmail, "phone": adminPhone, "password": password, "role": domain.RoleAdmin})
	require.Equal(t, http.StatusCreated, status, "%v", body)
	data := body["data"].(map[string]interface{})
	assert.Equal(t, domain.RoleAdmin, data["role"])
	adminID := uint(data["user_id"].(float64))

	// duplicate -> 409
	status, _ = e2eJSON(t, helper, "POST", "/admin/users", rootToken, map[string]string{
		"email": adminEmail, "phone": generateTestPhone(), "password": password, "role": domain.RoleAdmin})
	assert.Equal(t, http.StatusConflict, status)

	// nobody creates root through the API
	status, _ = e2eJSON(t, helper, "POST", "/admin/users", rootToken, map[string]string{
		"email": generateTestEmail(), "phone": generateTestPhone(), "password": password, "role": domain.RoleRoot})
	assert.Equal(t, http.StatusForbidden, status)

	// the admin verifies the phone, logs in and creates an attendant
	e2eVerifyOTP(t, helper, suite, adminID, adminPhone)
	adminToken := e2eLogin(t, helper, adminEmail, password)

	status, _ = e2eJSON(t, helper, "POST", "/admin/users", adminToken, map[string]string{
		"email": generateTestEmail(), "phone": generateTestPhone(), "password": password, "role": domain.RoleAdmin})
	assert.Equal(t, http.StatusForbidden, status, "admin must not create admin")

	status, body = e2eJSON(t, helper, "POST", "/admin/users", adminToken, map[string]string{
		"email": attEmail, "phone": attPhone, "password": password, "role": domain.RoleAttendant})
	require.Equal(t, http.StatusCreated, status, "%v", body)
	attID := uint(body["data"].(map[string]interface{})["user_id"].(float64))

	// an admin creates several accounts in a row (all 201). NOTE: the E2E server uses a mock
	// validator, so the per-IP registration rate limit is NOT exercised here; that guarantee is
	// covered by TestCreateUserByAdmin_NotSubjectToPublicRegistrationRateLimit (real validator).
	var bulkEmails []interface{}
	t.Cleanup(func() {
		for _, e := range bulkEmails {
			suite.DB.Exec("DELETE FROM users WHERE email = ?", e)
		}
	})
	for i := 0; i < 4; i++ {
		email := generateTestEmail()
		bulkEmails = append(bulkEmails, email)
		status, body = e2eJSON(t, helper, "POST", "/admin/users", adminToken, map[string]string{
			"email": email, "phone": generateTestPhone(), "password": password, "role": domain.RoleAttendant})
		require.Equal(t, http.StatusCreated, status, "bulk creation %d: %v", i, body)
	}

	// the attendant verifies, logs in and cannot create accounts
	e2eVerifyOTP(t, helper, suite, attID, attPhone)
	attToken := e2eLogin(t, helper, attEmail, password)
	status, _ = e2eJSON(t, helper, "POST", "/admin/users", attToken, map[string]string{
		"email": generateTestEmail(), "phone": generateTestPhone(), "password": password, "role": domain.RoleUser})
	assert.Equal(t, http.StatusForbidden, status, "attendant must not create users")

	// no token -> 401
	status, _ = e2eJSON(t, helper, "POST", "/admin/users", "", map[string]string{
		"email": generateTestEmail(), "phone": generateTestPhone(), "password": password, "role": domain.RoleUser})
	assert.Equal(t, http.StatusUnauthorized, status)

	// public registration: privileged role rejected, client accepted
	for _, role := range []string{domain.RoleAdmin, domain.RoleRoot, domain.RoleAttendant, "moderator"} {
		email := generateTestEmail()
		status, _ = e2eJSON(t, helper, "POST", "/auth/register", "", map[string]string{
			"email": email, "phone": generateTestPhone(), "password": password, "role": role})
		assert.Equal(t, http.StatusForbidden, status, "role %s must not be self-registrable", role)
		var count int64
		suite.DB.Model(&repositories.DBUser{}).Where("email = ?", email).Count(&count)
		assert.Zero(t, count, "no user may be created for role %s", role)
	}
	clientEmail := generateTestEmail()
	t.Cleanup(func() { suite.DB.Exec("DELETE FROM users WHERE email = ?", clientEmail) })
	status, _ = e2eJSON(t, helper, "POST", "/auth/register", "", map[string]string{
		"email": clientEmail, "phone": generateTestPhone(), "password": password, "role": domain.RoleClient})
	assert.Equal(t, http.StatusCreated, status)
	var client repositories.DBUser
	require.NoError(t, suite.DB.Where("email = ?", clientEmail).First(&client).Error)
	assert.Equal(t, domain.RoleClient, client.Role)
}
