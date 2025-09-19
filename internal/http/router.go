package httpx

import (
	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/internal/http/handlers"
	"github.com/you/authzsvc/internal/http/middleware"
)

func BuildRouter(ah *handlers.AuthHandlers, ph *handlers.PolicyHandlers, eh *handlers.ExternalAuthzHandlers, jwtmw *middleware.AuthMW, cb middleware.CasbinMiddleware) *gin.Engine {
	r := gin.New(); r.Use(gin.Recovery())

	r.GET("/health", func(c *gin.Context){ c.JSON(200, gin.H{"ok": true}) })

	// External authorization endpoints for Envoy integration
	external := r.Group("/external")
	external.POST("/authz", eh.Authorize)
	external.GET("/health", eh.Health)

	auth := r.Group("/auth")
	auth.POST("/register", ah.Register)
	auth.POST("/login", ah.Login)
	auth.POST("/otp/send", ah.SendOTP)
	auth.POST("/otp/verify", ah.VerifyOTP)
	auth.POST("/refresh", ah.Refresh)

	v := r.Group("/").Use(jwtmw.WithJWT(), cb.Enforce())
	v.GET("/auth/me", ah.Me)
	v.POST("/auth/logout", ah.Logout)
	v.GET("/users/:id", func(c *gin.Context) {
		userID := c.Param("id")
		currentUserID, _ := c.Get("user_id")
		c.JSON(200, gin.H{
			"message": "User data access successful",
			"requested_user_id": userID,
			"current_user_id": currentUserID,
			"note": "This endpoint demonstrates SimpleCasbinMW field validation",
		})
	})

	adm := r.Group("/admin").Use(jwtmw.WithJWT(), cb.Enforce())
	adm.GET("/policies", ph.List)
	adm.POST("/policies", ph.Add)
	adm.DELETE("/policies", ph.Remove)

	return r
}
