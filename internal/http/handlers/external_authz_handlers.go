package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/http/middleware"
)

// ExternalAuthzHandlers handles external authorization requests from Envoy
type ExternalAuthzHandlers struct {
	tokenSvc      domain.TokenService
	sessionRepo   domain.SessionRepository
	enforcer      *casbin.Enforcer
	fieldExtractor *middleware.FieldExtractor
}

// NewExternalAuthzHandlers creates new external authorization handlers
func NewExternalAuthzHandlers(
	tokenSvc domain.TokenService,
	sessionRepo domain.SessionRepository,
	enforcer *casbin.Enforcer,
) *ExternalAuthzHandlers {
	// Create a temporary SimpleCasbinMW for field extraction utilities
	tempCasbinMW := middleware.NewSimpleCasbinMW(enforcer)
	
	return &ExternalAuthzHandlers{
		tokenSvc:       tokenSvc,
		sessionRepo:    sessionRepo,
		enforcer:       enforcer,
		fieldExtractor: middleware.NewFieldExtractor(tempCasbinMW),
	}
}

// EnvoyRequest represents the request format sent by Envoy ext_authz
type EnvoyRequest struct {
	Attributes struct {
		Request struct {
			HTTP struct {
				Method  string            `json:"method"`
				Path    string            `json:"path"`
				Headers map[string]string `json:"headers"`
				Body    string            `json:"body,omitempty"`    // Base64 encoded
				Query   string            `json:"query,omitempty"`
			} `json:"http"`
		} `json:"request"`
		Source struct {
			Address struct {
				SocketAddress struct {
					Address   string `json:"address"`
					PortValue int    `json:"portValue"`
				} `json:"socketAddress"`
			} `json:"address"`
		} `json:"source"`
	} `json:"attributes"`
}

// AuthzResponse represents the response format for Envoy
type AuthzResponse struct {
	Status struct {
		Code int `json:"code"`
	} `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// Authorize handles external authorization requests from Envoy
func (h *ExternalAuthzHandlers) Authorize(c *gin.Context) {
	var envoyReq EnvoyRequest
	if err := c.ShouldBindJSON(&envoyReq); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid request format",
			"details": err.Error(),
		})
		return
	}

	// Extract JWT token from authorization header
	authHeader, exists := envoyReq.Attributes.Request.HTTP.Headers["authorization"]
	if !exists {
		// Try lowercase header name (Envoy normalizes headers)
		authHeader, exists = envoyReq.Attributes.Request.HTTP.Headers["Authorization"]
	}
	
	if !exists {
		h.respondUnauthorized(c, "Authorization header required")
		return
	}

	// Parse Bearer token
	tokenParts := strings.SplitN(authHeader, " ", 2)
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		h.respondUnauthorized(c, "Invalid authorization header format")
		return
	}

	token := tokenParts[1]

	// Validate JWT token
	claims, err := h.tokenSvc.ValidateAccessToken(token)
	if err != nil {
		switch err {
		case domain.ErrTokenExpired:
			h.respondUnauthorized(c, "Token expired")
		case domain.ErrTokenInvalid, domain.ErrTokenMalformed:
			h.respondUnauthorized(c, "Invalid token")
		default:
			h.respondUnauthorized(c, "Token validation failed")
		}
		return
	}

	// Validate session exists in Redis (critical security check)
	if claims.SessionID != "" {
		session, err := h.sessionRepo.FindByID(c.Request.Context(), claims.SessionID)
		if err != nil || session == nil {
			h.respondUnauthorized(c, "Session invalid or expired")
			return
		}
		
		// Ensure session belongs to the same user
		if session.UserID != claims.UserID {
			h.respondUnauthorized(c, "Session user mismatch")
			return
		}
	}

	// Create token claims map for field validation
	tokenClaims := map[string]interface{}{
		"user_id": fmt.Sprintf("%d", claims.UserID),
		"role":    claims.Role,
	}

	// Apply Casbin authorization logic
	path := envoyReq.Attributes.Request.HTTP.Path
	method := envoyReq.Attributes.Request.HTTP.Method
	casbinRole := "role_" + claims.Role

	// Check if this endpoint requires authorization
	allowed, validationRule, err := h.checkPermission(casbinRole, path, method)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Authorization check failed",
			"details": err.Error(),
		})
		return
	}

	if !allowed {
		h.respondForbidden(c, "Access denied")
		return
	}

	// If there's a validation rule, enforce it
	if validationRule != "" {
		valid, err := h.validateFields(c.Request.Context(), envoyReq, validationRule, tokenClaims)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Field validation failed",
				"details": err.Error(),
			})
			return
		}

		if !valid {
			h.respondForbidden(c, "Field validation failed: Request values do not match token claims")
			return
		}
	}

	// Authorization successful - return allowed response
	c.JSON(http.StatusOK, AuthzResponse{
		Status: struct {
			Code int `json:"code"`
		}{Code: http.StatusOK},
		Headers: map[string]string{
			"x-user-id":   fmt.Sprintf("%d", claims.UserID),
			"x-user-role": claims.Role,
		},
	})
}

// Health handles health check requests from Envoy
func (h *ExternalAuthzHandlers) Health(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "healthy",
		"service": "external-authz",
		"version": "1.0.0",
	})
}

// checkPermission reuses SimpleCasbinMW logic for authorization checking
func (h *ExternalAuthzHandlers) checkPermission(role, path, method string) (bool, string, error) {
	// Get all policies for this role (without path/method filtering)
	allPolicies, err := h.enforcer.GetFilteredPolicy(0, role)
	if err != nil {
		return false, "", fmt.Errorf("failed to get policies for role %s: %w", role, err)
	}
	
	if len(allPolicies) == 0 {
		return false, "", nil
	}

	// Check each policy for path and method matching
	for _, policy := range allPolicies {
		if len(policy) < 3 {
			continue // Invalid policy format
		}

		policyPath := policy[1]
		policyMethod := policy[2]
		
		// Check if path and method match
		if h.pathMatches(path, policyPath) && h.methodMatches(method, policyMethod) {
			// Extract validation rule (4th column)
			validationRule := ""
			if len(policy) > 3 {
				validationRule = policy[3]
			}
			return true, validationRule, nil
		}
	}

	return false, "", nil
}

// validateFields validates field constraints for external requests
func (h *ExternalAuthzHandlers) validateFields(ctx context.Context, envoyReq EnvoyRequest, validationRule string, tokenClaims map[string]interface{}) (bool, error) {
	if validationRule == "" || validationRule == "*" {
		return true, nil // No validation required
	}

	// Parse multiple conditions separated by &&
	conditions := strings.Split(validationRule, "&&")
	
	for _, condition := range conditions {
		condition = strings.TrimSpace(condition)
		if condition == "" {
			continue
		}

		valid, err := h.validateSingleCondition(envoyReq, condition, tokenClaims)
		if err != nil {
			return false, fmt.Errorf("validation condition '%s' failed: %w", condition, err)
		}
		
		if !valid {
			return false, nil
		}
	}

	return true, nil
}

// validateSingleCondition validates a single field condition for external requests
func (h *ExternalAuthzHandlers) validateSingleCondition(envoyReq EnvoyRequest, condition string, tokenClaims map[string]interface{}) (bool, error) {
	// Parse the condition (currently only supports == operator)
	if !strings.Contains(condition, "==") {
		return false, fmt.Errorf("unsupported condition format: %s (only == is supported)", condition)
	}

	parts := strings.Split(condition, "==")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid condition format: %s", condition)
	}

	leftSide := strings.TrimSpace(parts[0])   // e.g., "path.id"
	rightSide := strings.TrimSpace(parts[1])  // e.g., "token.user_id"

	// Extract left side value (from request)
	leftValue, err := h.extractRequestValue(envoyReq, leftSide)
	if err != nil {
		return false, fmt.Errorf("failed to extract request value '%s': %w", leftSide, err)
	}

	// Handle wildcard on right side (always matches if left side exists)
	if rightSide == "*" {
		return true, nil // Wildcard matches any value as long as left side was extracted successfully
	}

	// Extract right side value (from token)
	rightValue, err := h.extractTokenValue(rightSide, tokenClaims)
	if err != nil {
		return false, fmt.Errorf("failed to extract token value '%s': %w", rightSide, err)
	}

	// Compare values (string comparison)
	return fmt.Sprintf("%v", leftValue) == fmt.Sprintf("%v", rightValue), nil
}

// extractRequestValue extracts a value from the Envoy request
func (h *ExternalAuthzHandlers) extractRequestValue(envoyReq EnvoyRequest, source string) (interface{}, error) {
	parts := strings.SplitN(source, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid source format: %s (expected source.field)", source)
	}

	sourceType := parts[0]
	fieldName := parts[1]

	switch sourceType {
	case "path":
		// Extract path parameter (e.g., /users/:id -> /users/123)
		return h.extractPathParam(envoyReq.Attributes.Request.HTTP.Path, fieldName)

	case "query":
		// Parse query string
		if envoyReq.Attributes.Request.HTTP.Query == "" {
			return nil, fmt.Errorf("query parameter '%s' not found", fieldName)
		}
		
		values, err := url.ParseQuery(envoyReq.Attributes.Request.HTTP.Query)
		if err != nil {
			return nil, fmt.Errorf("failed to parse query string: %w", err)
		}
		
		value := values.Get(fieldName)
		if value == "" {
			return nil, fmt.Errorf("query parameter '%s' not found", fieldName)
		}
		return value, nil

	case "header":
		value, exists := envoyReq.Attributes.Request.HTTP.Headers[fieldName]
		if !exists {
			// Try lowercase version
			value, exists = envoyReq.Attributes.Request.HTTP.Headers[strings.ToLower(fieldName)]
		}
		if !exists {
			return nil, fmt.Errorf("header '%s' not found", fieldName)
		}
		return value, nil

	case "body":
		// Parse JSON body if present
		if envoyReq.Attributes.Request.HTTP.Body == "" {
			return nil, fmt.Errorf("body field '%s' not found (no body)", fieldName)
		}
		
		// Decode base64 body
		bodyBytes, err := base64.StdEncoding.DecodeString(envoyReq.Attributes.Request.HTTP.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to decode request body: %w", err)
		}
		
		var bodyData map[string]interface{}
		if err := json.Unmarshal(bodyBytes, &bodyData); err != nil {
			return nil, fmt.Errorf("failed to parse JSON body: %w", err)
		}
		
		value, exists := bodyData[fieldName]
		if !exists {
			return nil, fmt.Errorf("body field '%s' not found", fieldName)
		}
		return value, nil

	default:
		return nil, fmt.Errorf("unsupported source type: %s", sourceType)
	}
}

// extractPathParam extracts path parameters from URL path
func (h *ExternalAuthzHandlers) extractPathParam(path, paramName string) (interface{}, error) {
	// For proper path parameter extraction, we need to match against the policy patterns
	// Since we know the request was already matched by pathMatches(), we can extract from known patterns
	
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	
	// Handle common patterns based on parameter names and path structure
	switch {
	case paramName == "id":
		// Extract last segment as ID for patterns like /users/:id, /posts/:id
		if len(pathParts) >= 2 {
			return pathParts[len(pathParts)-1], nil
		}
	case paramName == "user_id":
		// For /profile/:user_id pattern, extract the second segment
		// /profile/1875 -> parts = ["profile", "1875"] -> return "1875"
		if len(pathParts) >= 2 && pathParts[0] == "profile" {
			return pathParts[1], nil
		}
		// For /users/:user_id pattern  
		if len(pathParts) >= 2 && pathParts[0] == "users" {
			return pathParts[1], nil
		}
		// For /api/orders/:user_id pattern
		// /api/orders/1875 -> parts = ["api", "orders", "1875"] -> return "1875"
		if len(pathParts) >= 3 && pathParts[0] == "api" && pathParts[1] == "orders" {
			return pathParts[2], nil
		}
	}
	
	return nil, fmt.Errorf("path parameter '%s' not found in path '%s'", paramName, path)
}

// extractTokenValue extracts a value from token claims
func (h *ExternalAuthzHandlers) extractTokenValue(source string, tokenClaims map[string]interface{}) (interface{}, error) {
	parts := strings.SplitN(source, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid token source format: %s (expected token.claim)", source)
	}

	sourceType := parts[0]
	claimName := parts[1]

	if sourceType != "token" {
		return nil, fmt.Errorf("invalid token source: %s (expected 'token')", sourceType)
	}

	value, exists := tokenClaims[claimName]
	if !exists {
		return nil, fmt.Errorf("token claim '%s' not found", claimName)
	}

	return value, nil
}

// Helper methods for path and method matching (reused from SimpleCasbinMW)
func (h *ExternalAuthzHandlers) pathMatches(requestPath, policyPath string) bool {
	// Use Casbin's keyMatch2 function to support parameterized paths
	// keyMatch2(key1, key2) - key1 is request path, key2 is policy pattern
	return util.KeyMatch2(requestPath, policyPath)
}

func (h *ExternalAuthzHandlers) methodMatches(requestMethod, policyMethod string) bool {
	// Exact match
	if requestMethod == policyMethod {
		return true
	}
	
	// Wildcard match
	if policyMethod == "*" {
		return true
	}
	
	// Regex pattern matching (simplified for this example)
	if strings.HasPrefix(policyMethod, "(") && strings.HasSuffix(policyMethod, ")") {
		pattern := strings.Trim(policyMethod, "()")
		methods := strings.Split(pattern, "|")
		for _, method := range methods {
			if requestMethod == strings.TrimSpace(method) {
				return true
			}
		}
	}
	
	return false
}


// Response helper methods
func (h *ExternalAuthzHandlers) respondUnauthorized(c *gin.Context, message string) {
	c.JSON(http.StatusUnauthorized, AuthzResponse{
		Status: struct {
			Code int `json:"code"`
		}{Code: http.StatusUnauthorized},
		Body: fmt.Sprintf(`{"error": "%s"}`, message),
	})
}

func (h *ExternalAuthzHandlers) respondForbidden(c *gin.Context, message string) {
	c.JSON(http.StatusForbidden, AuthzResponse{
		Status: struct {
			Code int `json:"code"`
		}{Code: http.StatusForbidden},
		Body: fmt.Sprintf(`{"error": "%s"}`, message),
	})
}