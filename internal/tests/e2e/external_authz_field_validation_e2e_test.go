package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExternalAuthzFieldValidationE2E tests comprehensive field validation scenarios
// using the real server with actual policies created via admin API
func TestExternalAuthzFieldValidationE2E(t *testing.T) {
	suite := GetTestSuite()
	server := NewTestServer(t, suite)
	helper := NewServerTestHelper(t, server)

	helper.MustStart()
	helper.MustWaitForReady()

	// Create test users
	userFactory := NewTestUserFactory(t, suite.DB)

	// Regular user (will be used in all tests)
	userOpts := DefaultTestUser()
	userOpts.PhoneVerified = true
	userOpts.Role = "user"
	regularUser := userFactory.CreateUserT(userOpts)

	// Admin user (to create policies)
	adminOpts := AdminTestUser()
	adminOpts.PhoneVerified = true
	adminUser := userFactory.CreateUserT(adminOpts)

	defer func() {
		suite.DB.Delete(regularUser)
		suite.DB.Delete(adminUser)
	}()

	// Get admin token for policy management
	adminTokens := loginUser(t, helper, adminUser.Email, adminOpts.Password)
	adminToken := adminTokens["access_token"].(string)

	// Get regular user token for testing
	userTokens := loginUser(t, helper, regularUser.Email, userOpts.Password)
	userToken := userTokens["access_token"].(string)

	// === SETUP COMPREHENSIVE POLICIES VIA ADMIN API ===
	policies := [][]string{
		// Query string validation
		{"role_user", "/api/data", "GET", "query.user_id==token.user_id"},

		// POST body validation
		{"role_user", "/api/posts", "POST", "body.author_id==token.user_id"},

		// Header validation
		{"role_user", "/api/upload", "POST", "header.x-user-id==token.user_id"},

		// Path parameter validation
		{"role_user", "/users/*", "GET", "path.user_id==token.user_id"},

		// Multi-field validation (path + query)
		{"role_user", "/api/orders/*", "GET", "path.user_id==token.user_id&&query.status==*"},

		// Multi-field validation (body + header)
		{"role_user", "/api/profile", "PUT", "body.user_id==token.user_id&&header.x-user-id==token.user_id"},

		// No validation (wildcard)
		{"role_user", "/public/*", "GET", "*"},
	}

	// Add all policies via admin API
	for _, policy := range policies {
		addPolicyViaAPI(t, helper, adminToken, policy)
	}

	// === COMPREHENSIVE FIELD VALIDATION TESTS ===
	tests := []struct {
		name            string
		envoyRequest    map[string]interface{}
		expectedStatus  int
		expectedHeaders map[string]string
		description     string
	}{
		// ===== QUERY STRING VALIDATION TESTS =====
		{
			name: "query validation success - user accesses own data",
			envoyRequest: createExternalAuthzRequest("GET", "/api/data", userToken, "", fmt.Sprintf("user_id=%d", regularUser.ID), nil),
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"x-user-id":   fmt.Sprintf("%d", regularUser.ID),
				"x-user-role": "user",
			},
			description: fmt.Sprintf("User %d should access /api/data?user_id=%d", regularUser.ID, regularUser.ID),
		},
		{
			name: "query validation failure - user tries to access other user data",
			envoyRequest: createExternalAuthzRequest("GET", "/api/data", userToken, "", "user_id=999", nil),
			expectedStatus: http.StatusForbidden,
			description: fmt.Sprintf("User %d should be denied /api/data?user_id=999", regularUser.ID),
		},

		// ===== POST BODY FIELD VALIDATION TESTS =====
		{
			name: "body validation success - user creates post with own author_id",
			envoyRequest: createExternalAuthzRequest("POST", "/api/posts", userToken, "", "", map[string]interface{}{
				"title":     "My Great Post",
				"content":   "Amazing content",
				"author_id": float64(regularUser.ID), // JSON numbers are float64
			}),
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"x-user-id":   fmt.Sprintf("%d", regularUser.ID),
				"x-user-role": "user",
			},
			description: fmt.Sprintf("User %d should create post with author_id=%d", regularUser.ID, regularUser.ID),
		},
		{
			name: "body validation failure - user tries to create post as another user",
			envoyRequest: createExternalAuthzRequest("POST", "/api/posts", userToken, "", "", map[string]interface{}{
				"title":     "Fake Post",
				"content":   "Malicious content",
				"author_id": 999,
			}),
			expectedStatus: http.StatusForbidden,
			description: fmt.Sprintf("User %d should be denied creating post with author_id=999", regularUser.ID),
		},

		// ===== HEADER VALIDATION TESTS =====
		{
			name: "header validation success - user uploads with correct x-user-id",
			envoyRequest: createExternalAuthzRequestWithHeaders("POST", "/api/upload", userToken, map[string]string{
				"x-user-id":    fmt.Sprintf("%d", regularUser.ID),
				"content-type": "multipart/form-data",
			}),
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"x-user-id":   fmt.Sprintf("%d", regularUser.ID),
				"x-user-role": "user",
			},
			description: fmt.Sprintf("User %d should upload with x-user-id=%d", regularUser.ID, regularUser.ID),
		},
		{
			name: "header validation failure - user sends wrong x-user-id",
			envoyRequest: createExternalAuthzRequestWithHeaders("POST", "/api/upload", userToken, map[string]string{
				"x-user-id":    "999",
				"content-type": "multipart/form-data",
			}),
			expectedStatus: http.StatusForbidden,
			description: fmt.Sprintf("User %d should be denied upload with x-user-id=999", regularUser.ID),
		},

		// ===== PATH PARAMETER VALIDATION TESTS =====
		{
			name: "path validation success - user accesses own profile",
			envoyRequest: createExternalAuthzRequest("GET", fmt.Sprintf("/users/%d/profile", regularUser.ID), userToken, "", "", nil),
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"x-user-id":   fmt.Sprintf("%d", regularUser.ID),
				"x-user-role": "user",
			},
			description: fmt.Sprintf("User %d should access /users/%d/profile", regularUser.ID, regularUser.ID),
		},
		{
			name: "path validation failure - user tries to access other user profile",
			envoyRequest: createExternalAuthzRequest("GET", "/users/999/profile", userToken, "", "", nil),
			expectedStatus: http.StatusForbidden,
			description: fmt.Sprintf("User %d should be denied /users/999/profile", regularUser.ID),
		},

		// ===== MULTI-FIELD VALIDATION TESTS =====
		{
			name: "multi-field validation success - path and query match",
			envoyRequest: createExternalAuthzRequest("GET", fmt.Sprintf("/api/orders/%d", regularUser.ID), userToken, "", "status=active", nil),
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"x-user-id":   fmt.Sprintf("%d", regularUser.ID),
				"x-user-role": "user",
			},
			description: fmt.Sprintf("User %d should access /api/orders/%d?status=active", regularUser.ID, regularUser.ID),
		},
		{
			name: "multi-field validation with body and header success",
			envoyRequest: createExternalAuthzRequestWithBodyAndHeaders("PUT", "/api/profile", userToken, 
				map[string]string{
					"x-user-id":    fmt.Sprintf("%d", regularUser.ID),
					"content-type": "application/json",
				},
				map[string]interface{}{
					"user_id": float64(regularUser.ID),
					"name":    "Updated Name",
					"email":   "updated@example.com",
				},
			),
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"x-user-id":   fmt.Sprintf("%d", regularUser.ID),
				"x-user-role": "user",
			},
			description: fmt.Sprintf("User %d should update profile with matching user_id in body and header", regularUser.ID),
		},

		// ===== NO VALIDATION TESTS =====
		{
			name: "no validation - public endpoint allows access",
			envoyRequest: createExternalAuthzRequest("GET", "/public/info", userToken, "", "", nil),
			expectedStatus: http.StatusOK,
			expectedHeaders: map[string]string{
				"x-user-id":   fmt.Sprintf("%d", regularUser.ID),
				"x-user-role": "user",
			},
			description: "Public endpoints should allow access without field validation",
		},
	}

	// === RUN ALL VALIDATION TESTS ===
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Call external authorization endpoint
			reqBody, _ := json.Marshal(tt.envoyRequest)
			req, _ := http.NewRequest("POST", helper.URL("/external/authz"), bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")

			resp := helper.DoRequest(req)

			// Verify response status
			assert.Equal(t, tt.expectedStatus, resp.StatusCode, 
				"Test: %s | Expected status %d, got %d", tt.description, tt.expectedStatus, resp.StatusCode)

			// Parse response
			var respBody map[string]interface{}
			json.NewDecoder(resp.Body).Decode(&respBody)
			resp.Body.Close()

			// For successful responses, verify expected headers are returned
			if tt.expectedStatus == http.StatusOK && tt.expectedHeaders != nil {
				require.Contains(t, respBody, "headers", "Successful response should contain headers")
				headers := respBody["headers"].(map[string]interface{})
				
				for expectedKey, expectedValue := range tt.expectedHeaders {
					assert.Equal(t, expectedValue, headers[expectedKey], 
						"Header %s should be %s", expectedKey, expectedValue)
				}
			}

			// For error responses, verify error structure
			if tt.expectedStatus != http.StatusOK {
				assert.Contains(t, respBody, "status", "Error response should contain status")
				status := respBody["status"].(map[string]interface{})
				assert.Equal(t, float64(tt.expectedStatus), status["code"], "Status code should match")
			}

			t.Logf("✅ %s | Status: %d | Response: %v", tt.description, resp.StatusCode, respBody)
		})
	}

	server.ValidatePerformance(t)
}

// === HELPER FUNCTIONS ===

// addPolicyViaAPI adds a Casbin policy via the admin API
func addPolicyViaAPI(t *testing.T, helper *ServerTestHelper, adminToken string, policy []string) {
	t.Helper()

	reqBody := map[string]interface{}{
		"subject": policy[0],
		"object":  policy[1],
		"action":  policy[2],
	}
	if len(policy) > 3 {
		reqBody["rule"] = policy[3]
	}

	body, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", helper.URL("/admin/policies"), bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp := helper.DoRequest(req)
	require.Equal(t, http.StatusNoContent, resp.StatusCode, 
		"Failed to add policy: %v", policy)
	resp.Body.Close()

	t.Logf("✅ Added policy: %v", policy)
}

// createExternalAuthzRequest creates an Envoy-style external authorization request
func createExternalAuthzRequest(method, path, token, body, query string, bodyData map[string]interface{}) map[string]interface{} {
	headers := map[string]string{
		"authorization": "Bearer " + token,
	}
	
	if bodyData != nil {
		headers["content-type"] = "application/json"
		bodyJSON, _ := json.Marshal(bodyData)
		body = base64.StdEncoding.EncodeToString(bodyJSON)
	}

	return map[string]interface{}{
		"attributes": map[string]interface{}{
			"request": map[string]interface{}{
				"http": map[string]interface{}{
					"method":  method,
					"path":    path,
					"headers": headers,
					"body":    body,
					"query":   query,
				},
			},
		},
	}
}

// createExternalAuthzRequestWithHeaders creates request with custom headers
func createExternalAuthzRequestWithHeaders(method, path, token string, customHeaders map[string]string) map[string]interface{} {
	headers := map[string]string{
		"authorization": "Bearer " + token,
	}
	
	// Add custom headers
	for k, v := range customHeaders {
		headers[k] = v
	}

	return map[string]interface{}{
		"attributes": map[string]interface{}{
			"request": map[string]interface{}{
				"http": map[string]interface{}{
					"method":  method,
					"path":    path,
					"headers": headers,
				},
			},
		},
	}
}

// createExternalAuthzRequestWithBodyAndHeaders creates request with both body and headers
func createExternalAuthzRequestWithBodyAndHeaders(method, path, token string, customHeaders map[string]string, bodyData map[string]interface{}) map[string]interface{} {
	headers := map[string]string{
		"authorization": "Bearer " + token,
	}
	
	// Add custom headers
	for k, v := range customHeaders {
		headers[k] = v
	}

	bodyJSON, _ := json.Marshal(bodyData)
	body := base64.StdEncoding.EncodeToString(bodyJSON)

	return map[string]interface{}{
		"attributes": map[string]interface{}{
			"request": map[string]interface{}{
				"http": map[string]interface{}{
					"method":  method,
					"path":    path,
					"headers": headers,
					"body":    body,
				},
			},
		},
	}
}