package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
)

// AuthMiddleware creates authentication middleware
func AuthMiddleware(tokenSvc domain.TokenService, sessionRepo domain.SessionRepository) gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Get Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			c.Abort()
			return
		}

		// Check Bearer token format
		tokenParts := strings.SplitN(authHeader, " ", 2)
		if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		token := tokenParts[1]

		// Validate token
		claims, err := tokenSvc.ValidateAccessToken(token)
		if err != nil {
			switch err {
			case domain.ErrTokenExpired:
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			case domain.ErrTokenInvalid, domain.ErrTokenMalformed:
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			default:
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Token validation failed"})
			}
			c.Abort()
			return
		}

		// Validate session exists in Redis (critical security check)
		if claims.SessionID != "" {
			session, err := sessionRepo.FindByID(c.Request.Context(), claims.SessionID)
			if err != nil || session == nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Session invalid or expired"})
				c.Abort()
				return
			}
			
			// Ensure session belongs to the same user
			if session.UserID != claims.UserID {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Session user mismatch"})
				c.Abort()
				return
			}
		}

		// Set user information in context  
		c.Set("user_id", fmt.Sprintf("%d", claims.UserID)) // Convert uint to string for Casbin compatibility
		c.Set("user_role", claims.Role)
		if claims.SessionID != "" {
			c.Set("session_id", claims.SessionID)
		}

		// Continue to next handler
		c.Next()
	})
}