package middleware

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/util"
	"github.com/gin-gonic/gin"
)

// CasbinMiddleware defines the interface for Casbin authorization middleware
type CasbinMiddleware interface {
	Enforce() gin.HandlerFunc
}

// SimpleCasbinMW provides field validation using Casbin's v3 column
// Uses format: "source.field==token.claim" for validation rules
type SimpleCasbinMW struct {
	enforcer *casbin.Enforcer
}

// NewSimpleCasbinMW creates a new SimpleCasbinMW instance
func NewSimpleCasbinMW(enforcer *casbin.Enforcer) *SimpleCasbinMW {
	return &SimpleCasbinMW{
		enforcer: enforcer,
	}
}

// Enforce returns the simplified Casbin authorization middleware
func (mw *SimpleCasbinMW) Enforce() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Extract user info from token context
		_, userExists := c.Get("user_id")
		userRole, roleExists := c.Get("user_role")
		
		if !userExists || !roleExists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID or role not found in token"})
			c.Abort()
			return
		}

		// Get all user claims for field validation
		tokenClaims := extractTokenClaims(c)

		// Get request details
		path := c.FullPath() // Use parameterized path for Casbin matching
		if path == "" {
			path = c.Request.URL.Path // Fallback to actual path if no route matched
		}
		method := c.Request.Method
		casbinRole := "role_" + userRole.(string)

		// Check if this endpoint requires authorization
		allowed, validationRule, err := mw.checkPermission(casbinRole, path, method)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization check failed"})
			c.Abort()
			return
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access denied"})
			c.Abort()
			return
		}

		// If there's a validation rule, enforce it
		if validationRule != "" {
			valid, err := mw.validateFields(c, validationRule, tokenClaims)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "Field validation failed",
					"details": err.Error(),
				})
				c.Abort()
				return
			}

			if !valid {
				c.JSON(http.StatusForbidden, gin.H{
					"error": "Field validation failed",
					"details": "Request values do not match token claims",
				})
				c.Abort()
				return
			}
		}

		c.Next()
	})
}

// checkPermission checks if the role has permission and returns any validation rule
// Uses Casbin's Enforce method to leverage keyMatch2 for parameterized paths
func (mw *SimpleCasbinMW) checkPermission(role, path, method string) (bool, string, error) {
	// First, use Casbin's Enforce to check basic permission with keyMatch2 support
	allowed, err := mw.enforcer.Enforce(role, path, method)
	if err != nil {
		return false, "", fmt.Errorf("failed to enforce policy: %w", err)
	}
	
	if !allowed {
		return false, "", nil
	}
	
	// If allowed, find the matching policy to get validation rule
	// We need to manually check which policy matched since Casbin doesn't return the rule
	allPolicies, err := mw.enforcer.GetFilteredPolicy(0, role)
	if err != nil {
		return false, "", fmt.Errorf("failed to get policies for role %s: %w", role, err)
	}

	// Find the matching policy by checking if it would match the current request
	// Since we already know the request is allowed by Casbin, we need to find which specific policy matched
	for _, policy := range allPolicies {
		if len(policy) < 3 {
			continue // Invalid policy format
		}

		policyPath := policy[1]
		policyMethod := policy[2]
		
		// Check if this policy would match the current request using Casbin's keyMatch2 function
		// This is the same matching logic that Casbin uses internally
		// keyMatch2(key1, key2) - key1 is request path, key2 is policy pattern  
		pathMatches := util.KeyMatch2(path, policyPath)
		methodMatches := mw.methodMatches(method, policyMethod)
		
		if pathMatches && methodMatches {
			// This policy matches, extract validation rule (4th column)
			validationRule := ""
			if len(policy) > 3 {
				validationRule = policy[3]
			}
			return true, validationRule, nil
		}
	}

	// If we reach here, basic Casbin said allowed but we couldn't find the specific rule
	// This means it matched but has no field validation rule
	return true, "", nil
}

// validateFields validates field constraints from v3 column
// Format: "source.field==token.claim" or "source.field1==token.claim1&&source.field2==token.claim2"
func (mw *SimpleCasbinMW) validateFields(c *gin.Context, validationRule string, tokenClaims map[string]interface{}) (bool, error) {
	if validationRule == "" || validationRule == "*" {
		return true, nil // No validation required (empty or wildcard)
	}

	// Parse multiple conditions separated by &&
	conditions := strings.Split(validationRule, "&&")
	
	for _, condition := range conditions {
		condition = strings.TrimSpace(condition)
		if condition == "" {
			continue
		}

		valid, err := mw.validateSingleCondition(c, condition, tokenClaims)
		if err != nil {
			return false, fmt.Errorf("validation condition '%s' failed: %w", condition, err)
		}
		
		if !valid {
			return false, nil
		}
	}

	return true, nil
}

// pathMatches checks if the request path matches the policy path pattern
// Supports exact matches and wildcard patterns (e.g., /admin/*)
func (mw *SimpleCasbinMW) pathMatches(requestPath, policyPath string) bool {
	// Exact match
	if requestPath == policyPath {
		return true
	}
	
	// Wildcard pattern matching
	if strings.HasSuffix(policyPath, "/*") {
		prefix := strings.TrimSuffix(policyPath, "/*")
		return strings.HasPrefix(requestPath, prefix+"/")
	}
	
	// Single wildcard (just "*")
	if policyPath == "*" {
		return true
	}
	
	return false
}

// methodMatches checks if the request method matches the policy method pattern
// Supports exact matches and regex patterns (e.g., (GET|POST|PUT|DELETE))
func (mw *SimpleCasbinMW) methodMatches(requestMethod, policyMethod string) bool {
	// Exact match
	if requestMethod == policyMethod {
		return true
	}
	
	// Wildcard match
	if policyMethod == "*" {
		return true
	}
	
	// Regex pattern matching (e.g., (GET|POST|PUT|DELETE))
	if strings.HasPrefix(policyMethod, "(") && strings.HasSuffix(policyMethod, ")") {
		// Remove parentheses and compile regex
		pattern := strings.Trim(policyMethod, "()")
		regex, err := regexp.Compile("^(" + pattern + ")$")
		if err != nil {
			return false // Invalid regex, no match
		}
		return regex.MatchString(requestMethod)
	}
	
	return false
}

// validateSingleCondition validates a single field condition
// Format: "source.field==token.claim"
func (mw *SimpleCasbinMW) validateSingleCondition(c *gin.Context, condition string, tokenClaims map[string]interface{}) (bool, error) {
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
	leftValue, err := mw.extractRequestValue(c, leftSide)
	if err != nil {
		return false, fmt.Errorf("failed to extract request value '%s': %w", leftSide, err)
	}

	// Extract right side value (from token)
	rightValue, err := mw.extractTokenValue(rightSide, tokenClaims)
	if err != nil {
		return false, fmt.Errorf("failed to extract token value '%s': %w", rightSide, err)
	}

	// Compare values (string comparison)
	return fmt.Sprintf("%v", leftValue) == fmt.Sprintf("%v", rightValue), nil
}

// extractRequestValue extracts a value from the HTTP request
// Supports: path.param, query.param, header.name, body.field
func (mw *SimpleCasbinMW) extractRequestValue(c *gin.Context, source string) (interface{}, error) {
	parts := strings.SplitN(source, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid source format: %s (expected source.field)", source)
	}

	sourceType := parts[0]
	fieldName := parts[1]

	switch sourceType {
	case "path":
		value := c.Param(fieldName)
		if value == "" {
			return nil, fmt.Errorf("path parameter '%s' not found", fieldName)
		}
		return value, nil

	case "query":
		value := c.Query(fieldName)
		if value == "" {
			return nil, fmt.Errorf("query parameter '%s' not found", fieldName)
		}
		return value, nil

	case "header":
		value := c.GetHeader(fieldName)
		if value == "" {
			return nil, fmt.Errorf("header '%s' not found", fieldName)
		}
		return value, nil

	case "body":
		// Parse JSON body and extract field
		var bodyData map[string]interface{}
		if err := c.ShouldBindJSON(&bodyData); err != nil {
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

// extractTokenValue extracts a value from token claims
// Supports: token.claim_name
func (mw *SimpleCasbinMW) extractTokenValue(source string, tokenClaims map[string]interface{}) (interface{}, error) {
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

// extractTokenClaims extracts all claims from the JWT token context
func extractTokenClaims(c *gin.Context) map[string]interface{} {
	claims := make(map[string]interface{})

	// Extract standard claims that are set by auth middleware
	if userID, exists := c.Get("user_id"); exists {
		claims["user_id"] = userID
	}
	if userRole, exists := c.Get("user_role"); exists {
		claims["role"] = userRole
	}
	if email, exists := c.Get("email"); exists {
		claims["email"] = email
	}
	if phone, exists := c.Get("phone"); exists {
		claims["phone"] = phone
	}

	// Try to extract raw JWT claims if available
	if rawClaims, exists := c.Get("jwt_claims"); exists {
		if claimsMap, ok := rawClaims.(map[string]interface{}); ok {
			for k, v := range claimsMap {
				claims[k] = v
			}
		}
	}

	return claims
}

// FieldExtractor provides field extraction capabilities for testing
type FieldExtractor struct {
	mw *SimpleCasbinMW
}

// NewFieldExtractor creates a new FieldExtractor for testing
func NewFieldExtractor(mw *SimpleCasbinMW) *FieldExtractor {
	return &FieldExtractor{mw: mw}
}

// ExtractRequestValue exposes request value extraction for testing
func (fe *FieldExtractor) ExtractRequestValue(c *gin.Context, source string) (interface{}, error) {
	return fe.mw.extractRequestValue(c, source)
}

// ExtractTokenValue exposes token value extraction for testing
func (fe *FieldExtractor) ExtractTokenValue(source string, tokenClaims map[string]interface{}) (interface{}, error) {
	return fe.mw.extractTokenValue(source, tokenClaims)
}

// ValidateCondition exposes single condition validation for testing
func (fe *FieldExtractor) ValidateCondition(c *gin.Context, condition string, tokenClaims map[string]interface{}) (bool, error) {
	return fe.mw.validateSingleCondition(c, condition, tokenClaims)
}