package middleware

import (
	"net/http"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/internal/config"
)

// EnhancedCasbinMW wraps casbin enforcer with both legacy ownership rules and new validation rules
type EnhancedCasbinMW struct {
	enforcer        *casbin.Enforcer
	ownershipRules  []config.OwnershipRule
	validationEngine *ValidationEngine
}

// NewEnhancedCasbinMW creates new enhanced casbin middleware
func NewEnhancedCasbinMW(enforcer *casbin.Enforcer, ownershipRules []config.OwnershipRule, validationRules []config.ValidationRule) *EnhancedCasbinMW {
	return &EnhancedCasbinMW{
		enforcer:         enforcer,
		ownershipRules:   ownershipRules,
		validationEngine: NewValidationEngine(validationRules),
	}
}

// Enforce returns the enhanced authorization middleware
func (mw *EnhancedCasbinMW) Enforce() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// 1. Get user info from context (set by JWT middleware)
		tokenUserID, userExists := c.Get("user_id")
		primaryRole, roleExists := c.Get("user_role")
		if !userExists || !roleExists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID or role not found in token"})
			c.Abort()
			return
		}

		// 2. LEGACY: Always check for x-user-id header mismatch (backward compatibility)
		headerUserID := c.GetHeader("x-user-id")
		if headerUserID != "" && headerUserID != tokenUserID.(string) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Header x-user-id does not match token user ID"})
			c.Abort()
			return
		}

		path := c.Request.URL.Path
		method := c.Request.Method

		// 3. NEW: Enhanced field validation using the new validation engine
		// Extract token claims for validation
		tokenClaims := map[string]interface{}{
			"user_id": tokenUserID,
			"role":    primaryRole,
		}
		
		// Add any additional claims from the context
		if sessionID, exists := c.Get("session_id"); exists {
			tokenClaims["session_id"] = sessionID
		}
		
		// Add custom claims if present (you can extend this based on your JWT structure)
		if tenantID, exists := c.Get("tenant_id"); exists {
			tokenClaims["tenant_id"] = tenantID
		}
		if orgID, exists := c.Get("organization_id"); exists {
			tokenClaims["organization_id"] = orgID
		}
		if projectIDs, exists := c.Get("project_ids"); exists {
			tokenClaims["project_ids"] = projectIDs
		}

		// Run enhanced validation rules
		if err := mw.validationEngine.ValidateRequest(c, tokenClaims); err != nil {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Field validation failed",
				"details": err.Error(),
			})
			c.Abort()
			return
		}

		// 4. LEGACY: Check ownership using old rules (for backward compatibility)
		isOwner := mw.validationEngine.IsOwner(c, tokenUserID.(string), mw.ownershipRules)

		// 5. Perform Casbin authorization checks
		// First, check with the user's primary role. This lets admins bypass ownership checks.
		allowed, err := mw.enforcer.Enforce(primaryRole, path, method)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization check failed"})
			c.Abort()
			return
		}

		// If not allowed, and the user is the owner, check with the special 'role_owner'
		if !allowed && isOwner {
			allowed, err = mw.enforcer.Enforce("role_owner", path, method)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Authorization check failed for owner"})
				c.Abort()
				return
			}
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "Access Denied"})
			c.Abort()
			return
		}

		c.Next()
	})
}