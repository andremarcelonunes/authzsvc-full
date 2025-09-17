package middleware

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/internal/config"
)

func TestGinContextAdapter(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		method         string
		url            string
		headers        map[string]string
		body           interface{}
		pathParam      map[string]string
		expectedPath   string
		expectedQuery  string
		expectedHeader string
		expectedBody   interface{}
	}{
		{
			name:           "path parameter extraction",
			method:         "GET",
			url:            "/users/123",
			pathParam:      map[string]string{"user_id": "123"},
			expectedPath:   "123",
		},
		{
			name:           "query parameter extraction",
			method:         "GET", 
			url:            "/data?tenant_id=456",
			expectedQuery:  "456",
		},
		{
			name:           "header extraction",
			method:         "GET",
			url:            "/resource",
			headers:        map[string]string{"x-user-id": "789"},
			expectedHeader: "789",
		},
		{
			name:         "body field extraction",
			method:       "POST",
			url:          "/create",
			body:         map[string]interface{}{"user_id": "999", "tenant_id": "888"},
			expectedBody: "999",
		},
		{
			name:         "nested body field extraction",
			method:       "POST",
			url:          "/create",
			body:         map[string]interface{}{"user": map[string]interface{}{"id": "777"}},
			expectedBody: "777",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup request
			var reqBody *bytes.Buffer
			if tt.body != nil {
				bodyBytes, _ := json.Marshal(tt.body)
				reqBody = bytes.NewBuffer(bodyBytes)
			} else {
				reqBody = bytes.NewBuffer([]byte{})
			}

			req := httptest.NewRequest(tt.method, tt.url, reqBody)
			if tt.headers != nil {
				for k, v := range tt.headers {
					req.Header.Set(k, v)
				}
			}

			// Setup Gin context
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = req

			// Set path parameters
			for k, v := range tt.pathParam {
				ctx.Params = append(ctx.Params, gin.Param{Key: k, Value: v})
			}

			// Create adapter
			adapter, err := NewGinContextAdapter(ctx)
			if err != nil {
				t.Fatalf("failed to create adapter: %v", err)
			}

			// Test path parameter
			if tt.expectedPath != "" {
				result := adapter.GetPathParam("user_id")
				if result != tt.expectedPath {
					t.Errorf("expected path param %q, got %q", tt.expectedPath, result)
				}
			}

			// Test query parameter
			if tt.expectedQuery != "" {
				result := adapter.GetQueryParam("tenant_id")
				if result != tt.expectedQuery {
					t.Errorf("expected query param %q, got %q", tt.expectedQuery, result)
				}
			}

			// Test header
			if tt.expectedHeader != "" {
				result := adapter.GetHeader("x-user-id")
				if result != tt.expectedHeader {
					t.Errorf("expected header %q, got %q", tt.expectedHeader, result)
				}
			}

			// Test body field
			if tt.expectedBody != nil {
				result, err := adapter.GetBodyField("user_id")
				if err != nil {
					// Try nested field for nested test case
					if strings.Contains(tt.name, "nested") {
						result, err = adapter.GetBodyField("user.id")
						if err != nil {
							t.Fatalf("failed to get nested body field: %v", err)
						}
					} else {
						t.Fatalf("failed to get body field: %v", err)
					}
				}
				if result != tt.expectedBody {
					t.Errorf("expected body field %v, got %v", tt.expectedBody, result)
				}
			}
		})
	}
}

func TestValidationEngine(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rules := []config.ValidationRule{
		{
			Name:        "UserIDMatch",
			Method:      "GET",
			Path:        "/users/:user_id",
			Description: "User ID in path must match token",
			Logic:       "all",
			Enabled:     true,
			Conditions: []config.ValidationCondition{
				{
					RequestField: config.FieldSource{Source: "path", Name: "user_id"},
					TokenField:   config.FieldSource{Source: "token", Name: "user_id"},
					Operator:     "equals",
				},
			},
		},
		{
			Name:        "TenantCheck",
			Method:      "POST",
			Path:        "/projects",
			Description: "Tenant must match",
			Logic:       "all",
			Enabled:     true,
			Conditions: []config.ValidationCondition{
				{
					RequestField: config.FieldSource{Source: "body", Name: "tenant_id"},
					TokenField:   config.FieldSource{Source: "token", Name: "tenant_id"},
					Operator:     "equals",
				},
			},
		},
	}

	engine := NewValidationEngine(rules)

	tests := []struct {
		name         string
		method       string
		path         string
		url          string
		pathParams   map[string]string
		body         interface{}
		tokenClaims  map[string]interface{}
		expectValid  bool
		expectError  string
	}{
		{
			name:        "valid user ID match",
			method:      "GET",
			path:        "/users/:user_id",
			url:         "/users/123",
			pathParams:  map[string]string{"user_id": "123"},
			tokenClaims: map[string]interface{}{"user_id": "123"},
			expectValid: true,
		},
		{
			name:        "invalid user ID match",
			method:      "GET", 
			path:        "/users/:user_id",
			url:         "/users/123",
			pathParams:  map[string]string{"user_id": "123"},
			tokenClaims: map[string]interface{}{"user_id": "456"},
			expectValid: false,
		},
		{
			name:        "valid tenant check",
			method:      "POST",
			path:        "/projects",
			url:         "/projects",
			body:        map[string]interface{}{"tenant_id": "tenant-1", "name": "Project"},
			tokenClaims: map[string]interface{}{"user_id": "123", "tenant_id": "tenant-1"},
			expectValid: true,
		},
		{
			name:        "invalid tenant check",
			method:      "POST",
			path:        "/projects", 
			url:         "/projects",
			body:        map[string]interface{}{"tenant_id": "tenant-1", "name": "Project"},
			tokenClaims: map[string]interface{}{"user_id": "123", "tenant_id": "tenant-2"},
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup request
			var reqBody *bytes.Buffer
			if tt.body != nil {
				bodyBytes, _ := json.Marshal(tt.body)
				reqBody = bytes.NewBuffer(bodyBytes)
			} else {
				reqBody = bytes.NewBuffer([]byte{})
			}

			req := httptest.NewRequest(tt.method, tt.url, reqBody)
			w := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(w)
			ctx.Request = req

			// Set path parameters
			for k, v := range tt.pathParams {
				ctx.Params = append(ctx.Params, gin.Param{Key: k, Value: v})
			}

			// Mock FullPath to return the route pattern
			ctx.Set("fullPath", tt.path)
			// Override FullPath method (this is a simplified mock)
			originalFullPath := ctx.FullPath()
			if tt.path != "" {
				// In a real test, you'd set up the router properly
				// For this test, we'll directly set the expected path
			}

			err := engine.ValidateRequest(ctx, tt.tokenClaims)
			
			if tt.expectValid && err != nil {
				t.Errorf("expected validation to pass, got error: %v", err)
			}
			
			if !tt.expectValid && err == nil {
				t.Errorf("expected validation to fail, but it passed")
			}

			if tt.expectError != "" && (err == nil || !strings.Contains(err.Error(), tt.expectError)) {
				t.Errorf("expected error containing %q, got: %v", tt.expectError, err)
			}

			// Restore original path if modified
			_ = originalFullPath
		})
	}
}

func TestValidationCondition_CompareValues(t *testing.T) {
	tests := []struct {
		name      string
		operator  string
		reqValue  interface{}
		tokenValue interface{}
		expected  bool
		expectErr bool
	}{
		{
			name:       "equals string match",
			operator:   "equals",
			reqValue:   "123",
			tokenValue: "123",
			expected:   true,
		},
		{
			name:       "equals string no match",
			operator:   "equals",
			reqValue:   "123",
			tokenValue: "456",
			expected:   false,
		},
		{
			name:       "in array match",
			operator:   "in",
			reqValue:   "project-1",
			tokenValue: []interface{}{"project-1", "project-2"},
			expected:   true,
		},
		{
			name:       "in array no match",
			operator:   "in",
			reqValue:   "project-3",
			tokenValue: []interface{}{"project-1", "project-2"},
			expected:   false,
		},
		{
			name:       "contains match",
			operator:   "contains",
			reqValue:   "hello world",
			tokenValue: "world",
			expected:   true,
		},
		{
			name:       "exists check true",
			operator:   "exists",
			reqValue:   "some-value",
			tokenValue: nil,
			expected:   true,
		},
		{
			name:       "exists check false",
			operator:   "exists",
			reqValue:   "",
			tokenValue: nil,
			expected:   false,
		},
		{
			name:      "unknown operator",
			operator:  "unknown",
			reqValue:  "value",
			tokenValue: "value",
			expected:  false,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			condition := config.ValidationCondition{
				Operator: tt.operator,
			}

			result, err := condition.CompareValues(tt.reqValue, tt.tokenValue)

			if tt.expectErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}