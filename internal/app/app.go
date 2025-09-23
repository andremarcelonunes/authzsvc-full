package app

import (
	"context"
	"log"
	"net/http"

	"github.com/you/authzsvc/internal/config"
	"github.com/you/authzsvc/internal/http/handlers"
	httpx "github.com/you/authzsvc/internal/http"
	"github.com/you/authzsvc/internal/http/middleware"
	"github.com/you/authzsvc/internal/infrastructure/database"
	"github.com/you/authzsvc/internal/infrastructure/notifications"
	"github.com/you/authzsvc/internal/infrastructure/repositories"
	"github.com/you/authzsvc/internal/infrastructure/auth"
	"github.com/you/authzsvc/internal/infrastructure/validation"
	"github.com/you/authzsvc/internal/services"

)

// Old tokenSvc removed - using clean architecture services now

func Run(cfg *config.Config) error {
	gdb, err := database.Open(cfg.DSN); if err != nil { return err }
	if err := database.AutoMigrate(gdb); err != nil { return err }
	cas, err := auth.NewCasbinService(gdb, cfg.CasbinModelPath); if err != nil { return err }
	rdb := database.NewRedis(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB).Client
	if err := rdb.Ping(context.Background()).Err(); err != nil { return err }
	// Initialize infrastructure services
	passwordSvc := auth.NewPasswordService()
	tokenSvc := auth.NewJWTService(cfg.JWTSecret, cfg.JWTIssuer, cfg.AccessTTL, cfg.RefreshTTL)
	notificationSvc := notifications.NewTwilioService(cfg.TwilioSID, cfg.TwilioToken, cfg.TwilioFrom)
	
	// Initialize repositories
	userRepo := repositories.NewUserRepository(gdb)
	sessionRepo := repositories.NewSessionRepository(rdb, cfg.RefreshTTL)
	auditRepo := repositories.NewComprehensiveAuditRepository(gdb)
	
	// Initialize password management repositories
	passwordChangeRepo := repositories.NewPasswordChangeRepository(gdb)
	passwordHistoryRepo := repositories.NewPasswordHistoryRepository(gdb)
	forgotPasswordRepo := repositories.NewForgotPasswordRepository(gdb)
	
	// Initialize audit service (CB-183)
	auditSvc := services.NewComprehensiveAuditService(auditRepo, nil, nil, nil, nil, nil, cfg, nil)
	
	// Initialize services
	otpConfig := services.OTPConfig{
		Length:       cfg.OTP_Length,
		TTL:          cfg.OTP_TTL,
		MaxAttempts:  cfg.OTP_MaxAttempts,
		ResendWindow: cfg.OTP_ResendWindow,
	}
	otpSvc := services.NewOTPService(notificationSvc, userRepo, rdb, otpConfig)
	
	// Initialize policy service
	policySvc := services.NewPolicyService(cas.E)
	
	authSvc := services.NewAuthService(userRepo, sessionRepo, passwordSvc, tokenSvc, otpSvc, policySvc, rdb, nil, auditSvc)
	
	// Initialize password change service with proper security defaults
	passwordChangeConfig := services.DefaultPasswordChangeConfig()
	// Override specific values with environment config
	passwordChangeConfig.RequestTTL = cfg.OTP_TTL
	passwordChangeConfig.RateLimitWindow = cfg.OTP_ResendWindow
	passwordChangeConfig.MaxRequestsPerWindow = 5
	passwordChangeConfig.PasswordHistoryCount = 5
	passwordChangeSvc := services.NewPasswordChangeService(
		passwordChangeRepo,
		passwordHistoryRepo,
		forgotPasswordRepo,
		userRepo,
		passwordSvc,
		otpSvc,
		sessionRepo,
		passwordChangeConfig,
	)
	
	// CB-182: Initialize validation services
	log.Println("CB-182: Initializing validation system...")
	
	// Initialize validation infrastructure
	validationLogger := validation.NewValidationLogger()
	validationMetrics := validation.NewValidationMetricsCollector()
	
	// Configure validation services
	rateLimitConfig := services.RateLimitConfig{
		DefaultWindowSize:    cfg.ValidationConfig.ValidationTimeout,
		DefaultLimit:         100, // 100 requests per window
		BruteForceThreshold:  5,   // 5 failed attempts
		BruteForceWindow:     cfg.ValidationConfig.ValidationTimeout,
		BlockDuration:        cfg.ValidationConfig.ValidationTimeout * 12, // 12x validation timeout
		EnableGracefulMode:   cfg.ValidationConfig.EnableGracefulMode,
	}
	rateLimitValidationSvc := services.NewRateLimitValidationService(rdb, rateLimitConfig)
	
	// Initialize mock repositories for CB-182 (in production, use real repositories)
	securityViolationRepo := validation.NewMockSecurityViolationRepository()
	
	// Initialize security validation service
	securityConfig := services.SecurityValidationConfig{
		EnableRealTimeScanning: true,
		MaxInputSize:          int(cfg.ValidationConfig.MaxRequestSize),
		SanitizationLevel:     "moderate",
	}
	securityValidationSvc := services.NewSecurityValidationService(securityViolationRepo, securityConfig)
	
	// Initialize business validation service
	businessConfig := services.BusinessValidationConfig{
		PasswordPolicy: services.PasswordPolicy{
			MinLength:           8,
			MaxLength:           128,
			RequireUppercase:    true,
			RequireLowercase:    true,
			RequireNumbers:      true,
			RequireSpecialChars: false,
			ForbiddenPasswords:  []string{"password", "123456", "admin"},
			MaxRepeatingChars:   3,
		},
		EmailValidation: services.EmailValidationConfig{
			AllowedDomains:      []string{},
			BlockedDomains:      []string{"tempmail.com", "10minutemail.com"},
			RequireVerification: false,
			MaxLength:          254,
		},
		PhoneValidation: services.PhoneValidationConfig{
			RequiredFormat:   "E.164",
			AllowedCountries: []string{},
			BlockedCountries: []string{},
		},
		UserLimits: services.UserLimitsConfig{
			MaxRegistrationsPerIP:   5,
			MaxRegistrationsPerDay:  10,
			MaxLoginAttemptsPerHour: 10,
			MaxOTPAttemptsPerHour:   5,
		},
	}
	businessValidationSvc := services.NewBusinessValidationService(userRepo, businessConfig)
	
	// Configure request validation service
	requestValidationConfig := services.RequestValidationConfig{
		EnableCaching:        cfg.ValidationConfig.EnableValidationCaching,
		CacheTimeout:         cfg.ValidationConfig.CacheTimeout,
		MaxValidationTime:    cfg.ValidationConfig.MaxValidationTime,
		EnableMetrics:        cfg.ValidationConfig.EnableMetrics,
	}
	requestValidationSvc := services.NewRequestValidationService(
		securityValidationSvc,
		businessValidationSvc,
		rateLimitValidationSvc,
		rdb,
		requestValidationConfig,
	)
	
	// Configure validation middleware
	validationConfig := middleware.ValidationConfig{
		EnableSecurityValidation: cfg.ValidationConfig.EnableSecurityValidation,
		EnableBusinessValidation: cfg.ValidationConfig.EnableBusinessValidation,
		EnableRateLimiting:      cfg.ValidationConfig.EnableRateLimiting,
		MaxRequestSize:          cfg.ValidationConfig.MaxRequestSize,
		ValidationTimeout:       cfg.ValidationConfig.ValidationTimeout,
		SkipValidationPaths:     cfg.ValidationConfig.SkipValidationPaths,
		LogValidationEvents:     cfg.ValidationConfig.LogValidationEvents,
		EnableMetrics:          cfg.ValidationConfig.EnableMetrics,
		ShadowMode:             cfg.ValidationConfig.ShadowMode, // CB-182: Shadow mode configuration
	}
	
	var validationMW *middleware.ValidationMiddleware
	if cfg.ValidationConfig.ShadowMode {
		log.Println("CB-182: Validation running in SHADOW MODE (logging only)")
		// In shadow mode, we'll still create the middleware but configure it to only log
		validationMW = middleware.NewValidationMiddleware(
			requestValidationSvc,
			securityValidationSvc,
			businessValidationSvc,
			rateLimitValidationSvc,
			validationMetrics,
			validationLogger,
			validationConfig,
		)
	} else {
		log.Println("CB-182: Validation running in ENFORCEMENT MODE")
		validationMW = middleware.NewValidationMiddleware(
			requestValidationSvc,
			securityValidationSvc,
			businessValidationSvc,
			rateLimitValidationSvc,
			validationMetrics,
			validationLogger,
			validationConfig,
		)
	}
	
	// Initialize handlers  
	authH := handlers.NewAuthHandlers(authSvc, otpSvc, userRepo)
	polH := &handlers.PolicyHandlers{E: cas.E}
	externalAuthzH := handlers.NewExternalAuthzHandlers(tokenSvc, sessionRepo, cas.E)
	docsH := handlers.NewSwaggerDocsHandler()
	passwordChangeH := handlers.NewPasswordChangeHandlers(passwordChangeSvc)
	
	// Initialize middleware
	jwtMW := middleware.NewAuthMW(tokenSvc, sessionRepo)
	
	// Choose Casbin middleware based on feature flag
	var casbinMW middleware.CasbinMiddleware
	if cfg.UseSimpleCasbin {
		log.Println("Using SimpleCasbinMW for authorization")
		casbinMW = middleware.NewSimpleCasbinMW(cas.E)
	} else {
		log.Println("Using legacy CasbinMW for authorization")
		casbinMW = middleware.NewCasbinMW(cas.E, cfg.OwnershipRules)
	}
	
	// Build router with CB-182 validation middleware
	r := httpx.BuildRouterWithValidation(authH, polH, externalAuthzH, docsH, passwordChangeH, jwtMW, casbinMW, validationMW)

	policies, _ := cas.E.GetPolicy()
	if len(policies) == 0 {
		// ===== ROLE INHERITANCE APPROACH =====
		// Define base user permissions ONCE
		cas.E.AddPolicy("role_user", "/auth/me", "GET", "*")
		cas.E.AddPolicy("role_user", "/auth/logout", "POST", "*")
		cas.E.AddPolicy("role_user", "/auth/otp/*", "POST", "*")
		cas.E.AddPolicy("role_user", "/users/*", "GET", "path.id==token.user_id")
		
		// Password management permissions for authenticated users
		cas.E.AddPolicy("role_user", "/api/v1/password-changes", "POST", "*")
		cas.E.AddPolicy("role_user", "/api/v1/password-changes", "GET", "*")
		cas.E.AddPolicy("role_user", "/api/v1/password-changes/*", "GET", "*")
		cas.E.AddPolicy("role_user", "/api/v1/password-changes/*/verification", "PUT", "*")
		cas.E.AddPolicy("role_user", "/api/v1/password-changes/*", "DELETE", "*")
		
		// Define admin-specific permissions
		cas.E.AddPolicy("role_admin", "/admin/*", "(GET|POST|PUT|DELETE)", "*")
		
		// Make admin inherit ALL user permissions automatically
		cas.E.AddGroupingPolicy("role_admin", "role_user")
		
		_ = cas.E.SavePolicy()
		log.Println("casbin: seeded policies with role inheritance - admin inherits from user")
	}
	addr := ":" + cfg.Port
	log.Printf("listening on %s", addr)
	return http.ListenAndServe(addr, r)
}
