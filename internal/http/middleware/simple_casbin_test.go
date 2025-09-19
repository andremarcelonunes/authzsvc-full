package middleware

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestEnforcer creates a Casbin enforcer with proper model for testing
func createTestEnforcer() *casbin.Enforcer {
	modelText := `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act, v3

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = r.sub == p.sub && keyMatch2(r.obj, p.obj) && regexMatch(r.act, p.act)
`
	m, _ := model.NewModelFromString(modelText)
	e, _ := casbin.NewEnforcer(m)
	return e
}

func TestSimpleCasbinMW_Enforce(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		setupEnforcer  func() *casbin.Enforcer
		setupContext   func(*gin.Context)
		request        *http.Request
		expectedStatus int
		expectedError  string
	}{
		{
			name: "missing user credentials",
			setupEnforcer: func() *casbin.Enforcer {
				return createTestEnforcer()
			},
			setupContext: func(c *gin.Context) {
				// No user credentials set
			},
			request:        httptest.NewRequest("GET", "/users/123", nil),
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "User ID or role not found in token",
		},
		{
			name: "access denied - no policy",
			setupEnforcer: func() *casbin.Enforcer {
				return createTestEnforcer()
			},
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "123")
				c.Set("user_role", "user")
			},
			request:        httptest.NewRequest("GET", "/users/123", nil),
			expectedStatus: http.StatusForbidden,
			expectedError:  "Access denied",
		},
		{
			name: "access granted - no validation rule",
			setupEnforcer: func() *casbin.Enforcer {
				e := createTestEnforcer()
				e.AddPolicy("role_user", "/users/:id", "GET")
				return e
			},
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "123")
				c.Set("user_role", "user")
			},
			request:        httptest.NewRequest("GET", "/users/123", nil),
			expectedStatus: http.StatusOK,
		},
		{
			name: "field validation success - path parameter",
			setupEnforcer: func() *casbin.Enforcer {
				e := createTestEnforcer()
				e.AddPolicy("role_user", "/users/:id", "GET", "path.id==token.user_id")
				return e
			},
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "123")
				c.Set("user_role", "user")
			},
			request:        httptest.NewRequest("GET", "/users/123", nil),
			expectedStatus: http.StatusOK,
		},
		{
			name: "field validation failure - path parameter mismatch",
			setupEnforcer: func() *casbin.Enforcer {
				e := createTestEnforcer()
				e.AddPolicy("role_user", "/users/:id", "GET", "path.id==token.user_id")
				return e
			},
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "456")
				c.Set("user_role", "user")
			},
			request:        httptest.NewRequest("GET", "/users/123", nil),
			expectedStatus: http.StatusForbidden,
			expectedError:  "Field validation failed",
		},
		{
			name: "field validation success - query parameter",
			setupEnforcer: func() *casbin.Enforcer {
				e := createTestEnforcer()
				e.AddPolicy("role_user", "/data", "GET", "query.user_id==token.user_id")
				return e
			},
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "123")
				c.Set("user_role", "user")
			},
			request:        httptest.NewRequest("GET", "/data?user_id=123", nil),
			expectedStatus: http.StatusOK,
		},
		{
			name: "field validation success - header",
			setupEnforcer: func() *casbin.Enforcer {
				e := createTestEnforcer()
				e.AddPolicy("role_user", "/api/data", "GET", "header.x-user-id==token.user_id")
				return e
			},
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "123")
				c.Set("user_role", "user")
			},
			request: func() *http.Request {
				req := httptest.NewRequest("GET", "/api/data", nil)
				req.Header.Set("x-user-id", "123")
				return req
			}(),
			expectedStatus: http.StatusOK,
		},
		{
			name: "field validation success - multiple conditions",
			setupEnforcer: func() *casbin.Enforcer {
				e := createTestEnforcer()
				e.AddPolicy("role_user", "/users/:id", "GET", "path.id==token.user_id&&query.active==token.role")
				return e
			},
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "123")
				c.Set("user_role", "user")
			},
			request: httptest.NewRequest("GET", "/users/123?active=user", nil),
			expectedStatus: http.StatusOK,
		},
		{
			name: "admin access - no validation rule",
			setupEnforcer: func() *casbin.Enforcer {
				e := createTestEnforcer()
				e.AddPolicy("role_admin", "/users/:id", "GET")
				return e
			},
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "999")
				c.Set("user_role", "admin")
			},
			request:        httptest.NewRequest("GET", "/users/123", nil),
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup
			enforcer := tt.setupEnforcer()
			middleware := NewSimpleCasbinMW(enforcer)

			// Create test router
			router := gin.New()
			router.Use(func(c *gin.Context) {
				tt.setupContext(c)
				c.Next()
			})
			router.Use(middleware.Enforce())
			router.GET("/users/:id", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "success"})
			})
			router.GET("/data", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "success"})
			})
			router.GET("/api/data", func(c *gin.Context) {
				c.JSON(http.StatusOK, gin.H{"status": "success"})
			})

			// Execute request
			w := httptest.NewRecorder()
			router.ServeHTTP(w, tt.request)

			// Assertions
			assert.Equal(t, tt.expectedStatus, w.Code)
			
			if tt.expectedError != "" {
				var response map[string]interface{}
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
				assert.Contains(t, response["error"], tt.expectedError)
			}
		})
	}
}

func TestSimpleCasbinMW_checkPermission(t *testing.T) {
	tests := []struct {
		name               string
		setupEnforcer     func() *casbin.Enforcer
		role              string
		path              string
		method            string
		expectedAllowed   bool
		expectedRule      string
		expectedError     bool
	}{
		{
			name: "policy not found",
			setupEnforcer: func() *casbin.Enforcer {
				e := createTestEnforcer()
				return e
			},
			role:            "role_user",
			path:            "/users/123",
			method:          "GET",
			expectedAllowed: false,
			expectedRule:    "",
			expectedError:   false,
		},
		{
			name: "policy found without validation rule",
			setupEnforcer: func() *casbin.Enforcer {
				e := createTestEnforcer()
				e.AddPolicy("role_user", "/users/123", "GET")
				return e
			},
			role:            "role_user",
			path:            "/users/123",
			method:          "GET",
			expectedAllowed: true,
			expectedRule:    "",
			expectedError:   false,
		},
		{
			name: "policy found with validation rule",
			setupEnforcer: func() *casbin.Enforcer {
				e := createTestEnforcer()
				e.AddPolicy("role_user", "/users/:id", "GET", "path.id==token.user_id")
				return e
			},
			role:            "role_user",
			path:            "/users/:id",
			method:          "GET",
			expectedAllowed: true,
			expectedRule:    "path.id==token.user_id",
			expectedError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enforcer := tt.setupEnforcer()
			mw := NewSimpleCasbinMW(enforcer)

			allowed, rule, err := mw.checkPermission(tt.role, tt.path, tt.method)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedAllowed, allowed)
				assert.Equal(t, tt.expectedRule, rule)
			}
		})
	}
}

func TestSimpleCasbinMW_validateFields(t *testing.T) {
	tests := []struct {
		name           string
		validationRule string
		setupContext   func(*gin.Context)
		tokenClaims    map[string]interface{}
		expectedValid  bool
		expectedError  bool
	}{
		{
			name:           "empty validation rule",
			validationRule: "",
			setupContext:   func(c *gin.Context) {},
			tokenClaims:    map[string]interface{}{},
			expectedValid:  true,
			expectedError:  false,
		},
		{
			name:           "single condition success",
			validationRule: "path.id==token.user_id",
			setupContext: func(c *gin.Context) {
				c.Params = []gin.Param{{Key: "id", Value: "123"}}
			},
			tokenClaims:   map[string]interface{}{"user_id": "123"},
			expectedValid: true,
			expectedError: false,
		},
		{
			name:           "single condition failure",
			validationRule: "path.id==token.user_id",
			setupContext: func(c *gin.Context) {
				c.Params = []gin.Param{{Key: "id", Value: "123"}}
			},
			tokenClaims:   map[string]interface{}{"user_id": "456"},
			expectedValid: false,
			expectedError: false,
		},
		{
			name:           "multiple conditions success",
			validationRule: "path.id==token.user_id&&query.type==token.role",
			setupContext: func(c *gin.Context) {
				c.Params = []gin.Param{{Key: "id", Value: "123"}}
				c.Request = httptest.NewRequest("GET", "/test?type=admin", nil)
			},
			tokenClaims: map[string]interface{}{
				"user_id": "123",
				"role":    "admin",
			},
			expectedValid: true,
			expectedError: false,
		},
		{
			name:           "multiple conditions partial failure",
			validationRule: "path.id==token.user_id&&query.type==token.role",
			setupContext: func(c *gin.Context) {
				c.Params = []gin.Param{{Key: "id", Value: "123"}}
				c.Request = httptest.NewRequest("GET", "/test?type=user", nil)
			},
			tokenClaims: map[string]interface{}{
				"user_id": "123",
				"role":    "admin",
			},
			expectedValid: false,
			expectedError: false,
		},
		{
			name:           "invalid condition format",
			validationRule: "path.id!=token.user_id",
			setupContext:   func(c *gin.Context) {},
			tokenClaims:    map[string]interface{}{},
			expectedValid:  false,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := NewSimpleCasbinMW(nil)
			
			// Setup context
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			tt.setupContext(c)

			valid, err := mw.validateFields(c, tt.validationRule, tt.tokenClaims)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedValid, valid)
			}
		})
	}
}

func TestSimpleCasbinMW_extractRequestValue(t *testing.T) {
	tests := []struct {
		name          string
		source        string
		setupContext  func(*gin.Context)
		expectedValue interface{}
		expectedError bool
	}{
		{
			name:   "extract path parameter",
			source: "path.id",
			setupContext: func(c *gin.Context) {
				c.Params = []gin.Param{{Key: "id", Value: "123"}}
			},
			expectedValue: "123",
			expectedError: false,
		},
		{
			name:   "extract query parameter",
			source: "query.user_id",
			setupContext: func(c *gin.Context) {
				c.Request = httptest.NewRequest("GET", "/test?user_id=456", nil)
			},
			expectedValue: "456",
			expectedError: false,
		},
		{
			name:   "extract header",
			source: "header.x-user-id",
			setupContext: func(c *gin.Context) {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("x-user-id", "789")
				c.Request = req
			},
			expectedValue: "789",
			expectedError: false,
		},
		{
			name:   "extract body field",
			source: "body.user_id",
			setupContext: func(c *gin.Context) {
				body := map[string]interface{}{"user_id": "999"}
				bodyBytes, _ := json.Marshal(body)
				req := httptest.NewRequest("POST", "/test", bytes.NewReader(bodyBytes))
				req.Header.Set("Content-Type", "application/json")
				c.Request = req
			},
			expectedValue: "999",
			expectedError: false,
		},
		{
			name:          "invalid source format",
			source:        "invalid",
			setupContext:  func(c *gin.Context) {},
			expectedValue: nil,
			expectedError: true,
		},
		{
			name:   "missing path parameter",
			source: "path.missing",
			setupContext: func(c *gin.Context) {
				c.Params = []gin.Param{}
			},
			expectedValue: nil,
			expectedError: true,
		},
		{
			name:   "unsupported source type",
			source: "cookie.session",
			setupContext: func(c *gin.Context) {},
			expectedValue: nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := NewSimpleCasbinMW(nil)
			
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			tt.setupContext(c)

			value, err := mw.extractRequestValue(c, tt.source)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedValue, value)
			}
		})
	}
}

func TestSimpleCasbinMW_extractTokenValue(t *testing.T) {
	tests := []struct {
		name          string
		source        string
		tokenClaims   map[string]interface{}
		expectedValue interface{}
		expectedError bool
	}{
		{
			name:          "extract user_id claim",
			source:        "token.user_id",
			tokenClaims:   map[string]interface{}{"user_id": "123"},
			expectedValue: "123",
			expectedError: false,
		},
		{
			name:          "extract role claim",
			source:        "token.role",
			tokenClaims:   map[string]interface{}{"role": "admin"},
			expectedValue: "admin",
			expectedError: false,
		},
		{
			name:          "invalid source format",
			source:        "invalid",
			tokenClaims:   map[string]interface{}{},
			expectedValue: nil,
			expectedError: true,
		},
		{
			name:          "non-token source",
			source:        "path.user_id",
			tokenClaims:   map[string]interface{}{},
			expectedValue: nil,
			expectedError: true,
		},
		{
			name:          "missing claim",
			source:        "token.missing",
			tokenClaims:   map[string]interface{}{"user_id": "123"},
			expectedValue: nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mw := NewSimpleCasbinMW(nil)

			value, err := mw.extractTokenValue(tt.source, tt.tokenClaims)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedValue, value)
			}
		})
	}
}

func TestExtractTokenClaims(t *testing.T) {
	tests := []struct {
		name            string
		setupContext    func(*gin.Context)
		expectedClaims  map[string]interface{}
	}{
		{
			name: "extract standard claims",
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "123")
				c.Set("user_role", "admin")
				c.Set("email", "test@example.com")
				c.Set("phone", "+1234567890")
			},
			expectedClaims: map[string]interface{}{
				"user_id": "123",
				"role":    "admin",
				"email":   "test@example.com",
				"phone":   "+1234567890",
			},
		},
		{
			name: "extract with raw JWT claims",
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "123")
				c.Set("user_role", "user")
				c.Set("jwt_claims", map[string]interface{}{
					"sub":        "user123",
					"custom_field": "value",
				})
			},
			expectedClaims: map[string]interface{}{
				"user_id":      "123",
				"role":         "user",
				"sub":          "user123",
				"custom_field": "value",
			},
		},
		{
			name: "no claims set",
			setupContext: func(c *gin.Context) {},
			expectedClaims: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			tt.setupContext(c)

			claims := extractTokenClaims(c)

			assert.Equal(t, tt.expectedClaims, claims)
		})
	}
}

func TestFieldExtractor(t *testing.T) {
	t.Run("field extractor functionality", func(t *testing.T) {
		mw := NewSimpleCasbinMW(nil)
		extractor := NewFieldExtractor(mw)

		// Test request value extraction
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Params = []gin.Param{{Key: "id", Value: "123"}}

		value, err := extractor.ExtractRequestValue(c, "path.id")
		assert.NoError(t, err)
		assert.Equal(t, "123", value)

		// Test token value extraction
		tokenClaims := map[string]interface{}{"user_id": "456"}
		tokenValue, err := extractor.ExtractTokenValue("token.user_id", tokenClaims)
		assert.NoError(t, err)
		assert.Equal(t, "456", tokenValue)

		// Test condition validation
		c.Params = []gin.Param{{Key: "id", Value: "456"}}
		valid, err := extractor.ValidateCondition(c, "path.id==token.user_id", tokenClaims)
		assert.NoError(t, err)
		assert.True(t, valid)
	})
}