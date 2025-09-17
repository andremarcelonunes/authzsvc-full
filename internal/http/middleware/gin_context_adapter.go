package middleware

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/internal/config"
)

// GinContextAdapter adapts Gin context to RequestContext interface
type GinContextAdapter struct {
	ctx      *gin.Context
	bodyData map[string]interface{}
}

// NewGinContextAdapter creates a new adapter for Gin context
func NewGinContextAdapter(ctx *gin.Context) (*GinContextAdapter, error) {
	adapter := &GinContextAdapter{ctx: ctx}
	
	// Pre-parse body if present
	if err := adapter.parseBody(); err != nil {
		return nil, fmt.Errorf("failed to parse request body: %w", err)
	}
	
	return adapter, nil
}

// GetPathParam retrieves a path parameter
func (g *GinContextAdapter) GetPathParam(name string) string {
	return g.ctx.Param(name)
}

// GetQueryParam retrieves a query parameter
func (g *GinContextAdapter) GetQueryParam(name string) string {
	return g.ctx.Query(name)
}

// GetHeader retrieves a header value
func (g *GinContextAdapter) GetHeader(name string) string {
	return g.ctx.GetHeader(name)
}

// GetBodyField retrieves a field from the JSON body
func (g *GinContextAdapter) GetBodyField(name string) (interface{}, error) {
	if g.bodyData == nil {
		return nil, fmt.Errorf("no body data parsed")
	}
	
	// Support nested field access with dot notation (e.g., "user.profile.id")
	result := extractNestedField(g.bodyData, name)
	if result == nil {
		return nil, fmt.Errorf("field '%s' not found", name)
	}
	return result, nil
}

// parseBody reads and parses the request body, then restores it
func (g *GinContextAdapter) parseBody() error {
	if g.ctx.Request.Body == nil {
		return nil
	}
	
	// Read the body
	bodyBytes, err := io.ReadAll(g.ctx.Request.Body)
	if err != nil {
		return fmt.Errorf("failed to read request body: %w", err)
	}
	
	// Restore the body for other handlers to read
	g.ctx.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	
	// Skip parsing if body is empty
	if len(bodyBytes) == 0 {
		return nil
	}
	
	// Try to parse as JSON
	var bodyData map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &bodyData); err != nil {
		// If JSON parsing fails, try to store as raw string
		g.bodyData = map[string]interface{}{
			"_raw": string(bodyBytes),
		}
		return nil
	}
	
	g.bodyData = bodyData
	return nil
}

// extractNestedField extracts a field using dot notation (e.g., "user.profile.id")
func extractNestedField(data map[string]interface{}, fieldPath string) interface{} {
	if data == nil {
		return nil
	}
	
	// Handle simple field access (no dots in path)
	if !strings.Contains(fieldPath, ".") {
		if field, exists := data[fieldPath]; exists {
			return field
		}
		return nil
	}
	
	// Handle nested field access with dot notation
	parts := splitFieldPath(fieldPath)
	current := data
	
	for i, part := range parts {
		if value, exists := current[part]; exists {
			if i == len(parts)-1 {
				return value // Last part, return the value
			}
			
			// Not the last part, continue traversing
			if nested, ok := value.(map[string]interface{}); ok {
				current = nested
			} else {
				return nil // Can't traverse further
			}
		} else {
			return nil // Field not found
		}
	}
	
	return nil
}

// splitFieldPath splits a field path by dots, handling escaped dots
func splitFieldPath(path string) []string {
	// For now, simple split by dot. Could be enhanced to handle escaped dots
	return strings.Split(path, ".")
}

// ValidationEngine handles validation rule execution
type ValidationEngine struct {
	rules []config.ValidationRule
}

// NewValidationEngine creates a new validation engine with rules
func NewValidationEngine(rules []config.ValidationRule) *ValidationEngine {
	return &ValidationEngine{rules: rules}
}

// ValidateRequest validates a request against all applicable rules
func (ve *ValidationEngine) ValidateRequest(ctx *gin.Context, tokenClaims map[string]interface{}) error {
	adapter, err := NewGinContextAdapter(ctx)
	if err != nil {
		return fmt.Errorf("failed to create context adapter: %w", err)
	}
	
	// Try to get path from context first (for tests), then fall back to FullPath()
	path := ctx.FullPath()
	if testPath, exists := ctx.Get("fullPath"); exists {
		if pathStr, ok := testPath.(string); ok {
			path = pathStr
		}
	}
	method := ctx.Request.Method
	
	// Find matching rules
	matchingRules := ve.findMatchingRules(method, path)
	if len(matchingRules) == 0 {
		return nil // No rules to validate
	}
	
	// Validate against each matching rule
	for _, rule := range matchingRules {
		valid, err := rule.Validate(adapter, tokenClaims)
		if err != nil {
			return fmt.Errorf("validation error for rule '%s': %w", rule.Name, err)
		}
		
		if !valid {
			return fmt.Errorf("validation failed for rule '%s': %s", rule.Name, rule.Description)
		}
	}
	
	return nil
}

// findMatchingRules finds all rules that match the given method and path
func (ve *ValidationEngine) findMatchingRules(method, path string) []config.ValidationRule {
	var matching []config.ValidationRule
	
	for _, rule := range ve.rules {
		if rule.Method == method && rule.Path == path {
			matching = append(matching, rule)
		}
	}
	
	return matching
}

// Legacy support: IsOwner checks if user owns the resource using the old ownership rules
func (ve *ValidationEngine) IsOwner(ctx *gin.Context, tokenUserID string, ownershipRules []config.OwnershipRule) bool {
	path := ctx.FullPath()
	method := ctx.Request.Method
	
	for _, rule := range ownershipRules {
		if rule.Method == method && rule.Path == path {
			requestUserID := extractUserIDFromRequest(ctx, rule.Source, rule.ParamName)
			if requestUserID != "" && requestUserID == tokenUserID {
				return true
			}
		}
	}
	
	return false
}

// extractUserIDFromRequest extracts user ID from request (renamed to avoid conflict)
func extractUserIDFromRequest(c *gin.Context, source string, paramName string) string {
	switch source {
	case "path":
		return c.Param(paramName)
	case "query":
		return c.Query(paramName)
	case "header":
		return c.GetHeader(paramName)
	case "body":
		adapter, err := NewGinContextAdapter(c)
		if err != nil {
			return ""
		}
		
		value, err := adapter.GetBodyField(paramName)
		if err != nil {
			return ""
		}
		
		if valueStr, ok := value.(string); ok {
			return valueStr
		}
		
		return fmt.Sprintf("%v", value)
	}
	return ""
}