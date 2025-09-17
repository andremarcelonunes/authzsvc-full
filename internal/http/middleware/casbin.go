package middleware

import (
	"net/http"

	"github.com/casbin/casbin/v2"
	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/internal/config"
)

// CasbinMW wraps the casbin enforcer and ownership rules for middleware

type CasbinMW struct {
	enforcer *casbin.Enforcer
	rules    []config.OwnershipRule
}

// NewCasbinMW creates new casbin middleware wrapper
func NewCasbinMW(enforcer *casbin.Enforcer, rules []config.OwnershipRule) *CasbinMW {
	return &CasbinMW{enforcer: enforcer, rules: rules}
}

// Enforce returns the casbin authorization middleware
func (mw *CasbinMW) Enforce() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// 1. Get user info from context
		tokenUserID, userExists := c.Get("user_id")
		primaryRole, roleExists := c.Get("user_role")
		if !userExists || !roleExists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID or role not found in token"})
			c.Abort()
			return
		}

		// 2. Always check for x-user-id header mismatch
		headerUserID := c.GetHeader("x-user-id")
		if headerUserID != "" && headerUserID != tokenUserID.(string) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Header x-user-id does not match token user ID"})
			c.Abort()
			return
		}

		path := c.Request.URL.Path
		method := c.Request.Method

		// 3. Check if the user is the owner based on the configured rules
		isOwner := false
		for _, rule := range mw.rules {
			// Use c.FullPath() to match against the route pattern (e.g., /users/:user_id)
			if rule.Path == c.FullPath() && rule.Method == method {
				requestUserID := extractUserID(c, rule.Source, rule.ParamName)
				if requestUserID != "" && requestUserID == tokenUserID.(string) {
					isOwner = true
					break
				}
			}
		}

		// 4. Perform authorization checks
		// First, check with the user's primary role. This lets admins bypass ownership checks.
		// Convert role to Casbin format (prefix with "role_")
		casbinRole := "role_" + primaryRole.(string)
		allowed, err := mw.enforcer.Enforce(casbinRole, path, method)
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
