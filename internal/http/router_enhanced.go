package httpx

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/http/handlers"
	"github.com/you/authzsvc/internal/http/middleware"
)

// MiddlewareConfig holds configuration for all middleware components
type MiddlewareConfig struct {
	// Validation configuration
	ValidationConfig middleware.ValidationConfig
	
	// Security configuration
	SecurityConfig middleware.SecurityConfig
	
	// Rate limiting configuration
	RateLimitConfig middleware.RateLimitConfig
	
	// Error handling configuration
	ErrorHandlerConfig handlers.ValidationErrorConfig
	
	// Feature flags
	EnableValidationMiddleware bool
	EnableSecurityMiddleware   bool
	EnableRateLimitMiddleware  bool
	EnableEnhancedErrorHandling bool
	
	// Backward compatibility
	EnableLegacyMode bool
}

// MiddlewareDependencies holds all dependencies needed for middleware
type MiddlewareDependencies struct {
	// Validation services
	RequestValidator  domain.RequestValidationService
	SecurityValidator domain.SecurityValidationService
	BusinessValidator domain.BusinessValidationService
	RateLimitValidator domain.RateLimitValidationService
	
	// Infrastructure
	RedisClient *redis.Client
	
	// Logging and metrics
	ValidationLogger            middleware.ValidationLogger
	SecurityLogger              middleware.SecurityLogger
	RateLimitLogger             middleware.RateLimitLogger
	ValidationErrorLogger       handlers.ValidationErrorLogger
	ValidationMetricsCollector  middleware.ValidationMetricsCollector
	RateLimitMetricsCollector   middleware.RateLimitMetricsCollector
	ErrorMetricsCollector       handlers.ValidationErrorMetricsCollector
}

// BuildEnhancedRouter creates a router with comprehensive validation middleware
func BuildEnhancedRouter(
	ah *handlers.AuthHandlers,
	ph *handlers.PolicyHandlers,
	eh *handlers.ExternalAuthzHandlers,
	jwtmw *middleware.AuthMW,
	cb middleware.CasbinMiddleware,
	config MiddlewareConfig,
	deps MiddlewareDependencies,
) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	
	// Global security headers middleware (always enabled)
	if config.EnableSecurityMiddleware {
		securityMW := middleware.NewSecurityMiddleware(config.SecurityConfig, deps.SecurityLogger)
		r.Use(securityMW.AddSecurityHeaders())
	}
	
	// Health check endpoints (no validation needed)
	r.GET("/health", func(c *gin.Context) { 
		c.JSON(200, gin.H{"ok": true, "validation_enabled": config.EnableValidationMiddleware}) 
	})
	
	// Metrics endpoint (no validation needed)
	r.GET("/metrics", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Metrics endpoint"})
	})
	
	// External authorization endpoints for Envoy integration (minimal validation)
	external := r.Group("/external")
	if config.EnableSecurityMiddleware {
		securityMW := middleware.NewSecurityMiddleware(config.SecurityConfig, deps.SecurityLogger)
		external.Use(securityMW.ValidateHeaders())
		external.Use(securityMW.LimitRequestSize())
	}
	external.POST("/authz", eh.Authorize)
	external.GET("/health", eh.Health)
	
	// Public authentication endpoints with comprehensive validation
	auth := r.Group("/auth")
	
	// Configure middleware chain for auth endpoints
	if config.EnableValidationMiddleware {
		authMW := buildAuthValidationMiddleware(config, deps)
		auth.Use(authMW...)
	}
	
	// Auth routes with specific rate limits
	if config.EnableRateLimitMiddleware {
		rateLimitMW := middleware.NewRateLimitMiddleware(
			deps.RedisClient,
			deps.RateLimitValidator,
			config.RateLimitConfig,
			deps.RateLimitLogger,
			deps.RateLimitMetricsCollector,
		)
		
		// Apply endpoint-specific rate limits
		auth.POST("/register", rateLimitMW.RateLimit("/auth/register", 5, time.Minute), ah.Register)
		auth.POST("/login", rateLimitMW.RateLimitWithStrategy("/auth/login", 10, time.Minute, middleware.StrategySlidingWindow), ah.Login)
		auth.POST("/otp/send", rateLimitMW.RateLimit("/auth/otp/send", 3, time.Minute), ah.SendOTP)
		auth.POST("/otp/verify", rateLimitMW.RateLimit("/auth/otp/verify", 5, time.Minute), ah.VerifyOTP)
		auth.POST("/refresh", rateLimitMW.RateLimit("/auth/refresh", 20, time.Minute), ah.Refresh)
	} else {
		// Legacy mode - no rate limiting
		auth.POST("/register", ah.Register)
		auth.POST("/login", ah.Login)
		auth.POST("/otp/send", ah.SendOTP)
		auth.POST("/otp/verify", ah.VerifyOTP)
		auth.POST("/refresh", ah.Refresh)
	}
	
	// Authenticated endpoints with full middleware stack
	v := r.Group("/")
	
	// Configure middleware for authenticated endpoints
	middlewareChain := []gin.HandlerFunc{jwtmw.WithJWT(), cb.Enforce()}
	
	if config.EnableValidationMiddleware {
		validationMW := buildAuthenticatedValidationMiddleware(config, deps)
		middlewareChain = append(middlewareChain, validationMW...)
	}
	
	v.Use(middlewareChain...)
	v.GET("/auth/me", ah.Me)
	v.POST("/auth/logout", ah.Logout)
	
	// User management endpoints
	userRoutes := v.Group("/users")
	if config.EnableRateLimitMiddleware {
		rateLimitMW := middleware.NewRateLimitMiddleware(
			deps.RedisClient,
			deps.RateLimitValidator,
			config.RateLimitConfig,
			deps.RateLimitLogger,
			deps.RateLimitMetricsCollector,
		)
		userRoutes.Use(rateLimitMW.PerUserRateLimit(100, time.Hour)) // 100 requests per hour per user
	}
	
	userRoutes.GET("/:id", func(c *gin.Context) {
		userID := c.Param("id")
		currentUserID, _ := c.Get("user_id")
		c.JSON(200, gin.H{
			"message": "User data access successful",
			"requested_user_id": userID,
			"current_user_id": currentUserID,
			"note": "This endpoint demonstrates enhanced validation middleware",
			"validation_enabled": config.EnableValidationMiddleware,
		})
	})
	
	// Admin endpoints with strict validation and rate limiting
	adm := r.Group("/admin")
	
	// Admin middleware chain
	adminMiddleware := []gin.HandlerFunc{jwtmw.WithJWT(), cb.Enforce()}
	
	if config.EnableValidationMiddleware {
		adminValidationMW := buildAdminValidationMiddleware(config, deps)
		adminMiddleware = append(adminMiddleware, adminValidationMW...)
	}
	
	if config.EnableRateLimitMiddleware {
		rateLimitMW := middleware.NewRateLimitMiddleware(
			deps.RedisClient,
			deps.RateLimitValidator,
			config.RateLimitConfig,
			deps.RateLimitLogger,
			deps.RateLimitMetricsCollector,
		)
		adminMiddleware = append(adminMiddleware, rateLimitMW.PerUserRateLimit(50, time.Hour)) // Stricter limits for admin
	}
	
	adm.Use(adminMiddleware...)
	adm.GET("/policies", ph.List)
	adm.POST("/policies", ph.Add)
	adm.DELETE("/policies", ph.Remove)
	
	// Development/debug endpoints (only in non-production)
	if gin.Mode() != gin.ReleaseMode {
		debug := r.Group("/debug")
		debug.GET("/validation/config", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"validation_enabled": config.EnableValidationMiddleware,
				"security_enabled": config.EnableSecurityMiddleware,
				"rate_limit_enabled": config.EnableRateLimitMiddleware,
				"legacy_mode": config.EnableLegacyMode,
			})
		})
		
		debug.GET("/middleware/status", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"middleware_status": "active",
				"features": map[string]bool{
					"validation": config.EnableValidationMiddleware,
					"security": config.EnableSecurityMiddleware,
					"rate_limiting": config.EnableRateLimitMiddleware,
					"error_handling": config.EnableEnhancedErrorHandling,
				},
			})
		})
	}
	
	return r
}

// buildAuthValidationMiddleware creates middleware chain for auth endpoints
func buildAuthValidationMiddleware(config MiddlewareConfig, deps MiddlewareDependencies) []gin.HandlerFunc {
	var middlewares []gin.HandlerFunc
	
	// Security middleware
	if config.EnableSecurityMiddleware {
		securityMW := middleware.NewSecurityMiddleware(config.SecurityConfig, deps.SecurityLogger)
		middlewares = append(middlewares,
			securityMW.ValidateContentType(),
			securityMW.LimitRequestSize(),
			securityMW.ValidateCharacterEncoding(),
			securityMW.ValidateHeaders(),
			securityMW.ValidateQueryParams(),
		)
	}
	
	// Validation middleware
	if config.EnableValidationMiddleware {
		validationMW := middleware.NewValidationMiddleware(
			deps.RequestValidator,
			deps.SecurityValidator,
			deps.BusinessValidator,
			deps.RateLimitValidator,
			deps.ValidationMetricsCollector,
			deps.ValidationLogger,
			config.ValidationConfig,
		)
		middlewares = append(middlewares, validationMW.ValidateRequest())
	}
	
	return middlewares
}

// buildAuthenticatedValidationMiddleware creates middleware chain for authenticated endpoints
func buildAuthenticatedValidationMiddleware(config MiddlewareConfig, deps MiddlewareDependencies) []gin.HandlerFunc {
	var middlewares []gin.HandlerFunc
	
	// Lighter validation for authenticated endpoints
	if config.EnableSecurityMiddleware {
		securityMW := middleware.NewSecurityMiddleware(config.SecurityConfig, deps.SecurityLogger)
		middlewares = append(middlewares,
			securityMW.ValidateHeaders(),
			securityMW.ValidateQueryParams(),
		)
	}
	
	return middlewares
}

// buildAdminValidationMiddleware creates strict middleware chain for admin endpoints
func buildAdminValidationMiddleware(config MiddlewareConfig, deps MiddlewareDependencies) []gin.HandlerFunc {
	var middlewares []gin.HandlerFunc
	
	// Strict security validation for admin endpoints
	if config.EnableSecurityMiddleware {
		adminSecurityConfig := config.SecurityConfig
		adminSecurityConfig.BlockSuspiciousContent = true
		adminSecurityConfig.RequireContentType = true
		
		securityMW := middleware.NewSecurityMiddleware(adminSecurityConfig, deps.SecurityLogger)
		middlewares = append(middlewares,
			securityMW.ValidateContentType(),
			securityMW.LimitRequestSize(),
			securityMW.ValidateCharacterEncoding(),
			securityMW.ValidateHeaders(),
			securityMW.ValidateQueryParams(),
		)
	}
	
	// Enhanced validation for admin operations
	if config.EnableValidationMiddleware {
		adminValidationConfig := config.ValidationConfig
		adminValidationConfig.EnableSecurityValidation = true
		adminValidationConfig.EnableBusinessValidation = true
		adminValidationConfig.LogValidationEvents = true
		
		validationMW := middleware.NewValidationMiddleware(
			deps.RequestValidator,
			deps.SecurityValidator,
			deps.BusinessValidator,
			deps.RateLimitValidator,
			deps.ValidationMetricsCollector,
			deps.ValidationLogger,
			adminValidationConfig,
		)
		middlewares = append(middlewares, validationMW.ValidateRequest())
	}
	
	return middlewares
}

// BuildLegacyRouter creates backward-compatible router (for migration purposes)
func BuildLegacyRouter(
	ah *handlers.AuthHandlers,
	ph *handlers.PolicyHandlers,
	eh *handlers.ExternalAuthzHandlers,
	jwtmw *middleware.AuthMW,
	cb middleware.CasbinMiddleware,
) *gin.Engine {
	// Use the original router implementation for backward compatibility
	dh := handlers.NewSwaggerDocsHandler()
	// Pass nil for password change handlers in legacy mode
	return BuildRouter(ah, ph, eh, dh, nil, jwtmw, cb)
}

// DefaultMiddlewareConfig returns default configuration for all middleware
func DefaultMiddlewareConfig() MiddlewareConfig {
	return MiddlewareConfig{
		ValidationConfig:           middleware.DefaultValidationConfig(),
		SecurityConfig:             middleware.DefaultSecurityConfig(),
		RateLimitConfig:           middleware.DefaultRateLimitConfig(),
		ErrorHandlerConfig:        handlers.DefaultValidationErrorConfig(),
		EnableValidationMiddleware: true,
		EnableSecurityMiddleware:   true,
		EnableRateLimitMiddleware:  true,
		EnableEnhancedErrorHandling: true,
		EnableLegacyMode:          false,
	}
}

// DevelopmentMiddlewareConfig returns configuration suitable for development
func DevelopmentMiddlewareConfig() MiddlewareConfig {
	config := DefaultMiddlewareConfig()
	
	// Relax validation for development
	config.ValidationConfig.EnableSecurityValidation = false
	config.ValidationConfig.EnableRateLimiting = false
	config.SecurityConfig.BlockSuspiciousContent = false
	config.RateLimitConfig.EnableRateLimit = false
	config.ErrorHandlerConfig.IncludeStackTrace = true
	config.ErrorHandlerConfig.HideInternalErrors = false
	
	return config
}

// ProductionMiddlewareConfig returns configuration suitable for production
func ProductionMiddlewareConfig() MiddlewareConfig {
	config := DefaultMiddlewareConfig()
	
	// Strict validation for production
	config.ValidationConfig.EnableSecurityValidation = true
	config.ValidationConfig.EnableBusinessValidation = true
	config.ValidationConfig.EnableRateLimiting = true
	config.SecurityConfig.BlockSuspiciousContent = true
	config.SecurityConfig.RequireContentType = true
	config.RateLimitConfig.EnableRateLimit = true
	config.RateLimitConfig.EnableAutoBlock = true
	config.ErrorHandlerConfig.IncludeStackTrace = false
	config.ErrorHandlerConfig.HideInternalErrors = true
	config.ErrorHandlerConfig.SanitizeErrorMessages = true
	
	return config
}

// MigrationMiddlewareConfig returns configuration for gradual migration
func MigrationMiddlewareConfig() MiddlewareConfig {
	config := DefaultMiddlewareConfig()
	
	// Enable features gradually
	config.EnableValidationMiddleware = true
	config.EnableSecurityMiddleware = true
	config.EnableRateLimitMiddleware = false // Enable later
	config.EnableEnhancedErrorHandling = true
	
	// Relaxed validation during migration
	config.ValidationConfig.EnableSecurityValidation = false // Enable gradually
	config.ValidationConfig.EnableBusinessValidation = true
	config.SecurityConfig.BlockSuspiciousContent = false // Enable gradually
	config.RateLimitConfig.AllowOnRedisFailure = true // Graceful degradation
	
	return config
}