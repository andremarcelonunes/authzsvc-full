package httpx

import (
	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/internal/http/handlers"
	"github.com/you/authzsvc/internal/http/middleware"
)

func BuildRouter(ah *handlers.AuthHandlers, ph *handlers.PolicyHandlers, jwtmw *middleware.AuthMW, cb *middleware.CasbinMW) *gin.Engine {
	r := gin.New(); r.Use(gin.Recovery())

	r.GET("/health", func(c *gin.Context){ c.JSON(200, gin.H{"ok": true}) })

	auth := r.Group("/auth")
	auth.POST("/register", ah.Register)
	auth.POST("/login", ah.Login)
	auth.POST("/otp/send", ah.SendOTP)
	auth.POST("/otp/verify", ah.VerifyOTP)
	auth.POST("/refresh", ah.Refresh)

	v := r.Group("/").Use(jwtmw.WithJWT(), cb.Enforce())
	v.GET("/auth/me", ah.Me)
	v.POST("/auth/logout", ah.Logout)

	adm := r.Group("/admin").Use(jwtmw.WithJWT(), cb.Enforce())
	adm.GET("/policies", ph.List)
	adm.POST("/policies", ph.Add)
	adm.DELETE("/policies", ph.Remove)

	return r
}
