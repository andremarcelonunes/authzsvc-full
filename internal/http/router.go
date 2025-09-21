package httpx

import (
	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/internal/http/handlers"
	"github.com/you/authzsvc/internal/http/middleware"
)

func BuildRouter(ah *handlers.AuthHandlers, ph *handlers.PolicyHandlers, eh *handlers.ExternalAuthzHandlers, dh *handlers.SwaggerDocsHandler, jwtmw *middleware.AuthMW, cb middleware.CasbinMiddleware) *gin.Engine {
	return buildRouterInternal(ah, ph, eh, dh, jwtmw, cb, nil)
}

// BuildRouterWithValidation builds router with CB-182 validation middleware
func BuildRouterWithValidation(ah *handlers.AuthHandlers, ph *handlers.PolicyHandlers, eh *handlers.ExternalAuthzHandlers, dh *handlers.SwaggerDocsHandler, jwtmw *middleware.AuthMW, cb middleware.CasbinMiddleware, validationMW *middleware.ValidationMiddleware) *gin.Engine {
	return buildRouterInternal(ah, ph, eh, dh, jwtmw, cb, validationMW)
}

func buildRouterInternal(ah *handlers.AuthHandlers, ph *handlers.PolicyHandlers, eh *handlers.ExternalAuthzHandlers, dh *handlers.SwaggerDocsHandler, jwtmw *middleware.AuthMW, cb middleware.CasbinMiddleware, validationMW *middleware.ValidationMiddleware) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/health", func(c *gin.Context){ c.JSON(200, gin.H{"ok": true}) })

	// Documentation endpoints (no validation needed)
	docs := r.Group("/docs")
	docs.GET("", dh.GetSwaggerUI)           // Swagger UI at /docs
	docs.GET("/", dh.GetSwaggerUI)          // Swagger UI at /docs/
	docs.GET("/swagger.yaml", dh.GetSwaggerYAML) // Raw YAML at /docs/swagger.yaml
	docs.GET("/api", dh.GetAPIDocs)         // API info at /docs/api

	// External authorization endpoints for Envoy integration (no validation needed)
	external := r.Group("/external")
	external.POST("/authz", eh.Authorize)
	external.GET("/health", eh.Health)

	// CB-182: Apply validation middleware to auth endpoints
	auth := r.Group("/auth")
	if validationMW != nil {
		auth.Use(validationMW.ValidateRequest())
	}
	auth.POST("/register", ah.Register)
	auth.POST("/login", ah.Login)
	auth.POST("/otp/send", ah.SendOTP)
	auth.POST("/otp/verify", ah.VerifyOTP)
	auth.POST("/refresh", ah.Refresh)

	// Protected endpoints with JWT and Casbin, optionally with validation
	v := r.Group("/")
	if validationMW != nil {
		v.Use(validationMW.ValidateRequest())
	}
	v.Use(jwtmw.WithJWT(), cb.Enforce())
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

	// Admin endpoints with JWT, Casbin, and optionally validation
	adm := r.Group("/admin")
	if validationMW != nil {
		adm.Use(validationMW.ValidateRequest())
	}
	adm.Use(jwtmw.WithJWT(), cb.Enforce())
	adm.GET("/policies", ph.List)
	adm.POST("/policies", ph.Add)
	adm.DELETE("/policies", ph.Remove)

	return r
}
