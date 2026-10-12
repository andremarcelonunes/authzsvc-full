package app

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/config"
	httpx "github.com/you/authzsvc/internal/http"
	"github.com/you/authzsvc/internal/http/handlers"
	"github.com/you/authzsvc/internal/http/middleware"
	"github.com/you/authzsvc/internal/infrastructure/auth"
	"github.com/you/authzsvc/internal/infrastructure/database"
	"github.com/you/authzsvc/internal/infrastructure/identity"
	"github.com/you/authzsvc/internal/infrastructure/smsbudget"
	"github.com/you/authzsvc/internal/infrastructure/notifications"
	"github.com/you/authzsvc/internal/infrastructure/repositories"
	"github.com/you/authzsvc/internal/infrastructure/validation"
	"github.com/you/authzsvc/internal/services"
)

// Old tokenSvc removed - using clean architecture services now

func Run(cfg *config.Config) error {
	gdb, err := database.Open(cfg.DSN)
	if err != nil {
		return err
	}
	if err := database.AutoMigrate(gdb); err != nil {
		return err
	}
	
	// Seed default data retention policies for LGPD compliance
	retentionSeeder := services.NewRetentionPolicySeeder(gdb)
	if err := retentionSeeder.SeedDefaultRetentionPolicies(context.Background()); err != nil {
		log.Printf("Warning: Failed to seed retention policies: %v", err)
		// Don't fail startup for seeding issues, just log the warning
	} else {
		log.Println("LGPD: Default data retention policies initialized")
	}
	cas, err := auth.NewCasbinService(gdb, cfg.CasbinModelPath)
	if err != nil {
		return err
	}
	rdb := database.NewRedis(cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB).Client
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		return err
	}
	// Initialize infrastructure services
	passwordSvc := auth.NewPasswordService()
	tokenSvc := auth.NewJWTService(cfg.JWTSecret, cfg.JWTIssuer, cfg.AccessTTL, cfg.RefreshTTL)
	// Every SMS goes through the budget (caps per phone, per caller and for the installation; fail closed).
	smsBudget := smsbudget.NewRedisBudget(rdb, cfg.SMSBudget, cfg.JWTSecret)
	notificationSvc := notifications.NewBudgetedNotifier(
		notifications.NewTwilioService(cfg.TwilioSID, cfg.TwilioToken, cfg.TwilioFrom, notifications.WithLogMessages(cfg.OTPLogCodes)),
		smsBudget)

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
		Secret:       cfg.JWTSecret, // keys the stored digest of one-time codes
		Brand:        cfg.SMSBrand,
	}
	otpSvc := services.NewOTPService(notificationSvc, userRepo, rdb, otpConfig)

	// Initialize policy service
	policySvc := services.NewPolicyService(cas.E)

	// Initialize password change service with proper security defaults
	passwordChangeConfig := services.DefaultPasswordChangeConfig()
	// Override specific values with environment config
	passwordChangeConfig.RequestTTL = cfg.OTP_TTL
	passwordChangeConfig.RateLimitWindow = cfg.OTP_ResendWindow
	passwordChangeConfig.MaxRequestsPerWindow = 5
	passwordChangeConfig.PasswordHistoryCount = 5
	// One password policy for registration, admin creation, change and reset
	// (PASSWORD_REQUIRE_COMPLEXITY, PASSWORD_MIN_LENGTH).
	passwordPolicy := domain.NewPasswordPolicy(cfg.Password.MinLength, cfg.Password.RequireComplexity)
	passwordChangeSvc := services.NewPasswordChangeService(
		passwordChangeRepo,
		passwordHistoryRepo,
		forgotPasswordRepo,
		userRepo,
		passwordSvc,
		otpSvc,
		sessionRepo,
		auditSvc,
		passwordChangeConfig,
		services.WithPasswordChangePolicy(passwordPolicy),
		services.WithPasswordResetRequireEmail(cfg.Password.ResetRequireEmail), // PASSWORD_RESET_REQUIRE_EMAIL
		services.WithPasswordChangeOTPDigester(services.NewOTPDigester(cfg.JWTSecret)),
	)

	// LGPD User Deletion: Initialize deletion system
	log.Println("LGPD: Initializing user deletion system...")
	
	// Initialize deletion repositories
	deletionRequestRepo := repositories.NewDeletionRequestRepository(gdb)
	dataExportRepo := repositories.NewDataExportRepository(gdb)
	deletionAuditRepo := repositories.NewDeletionAuditRepository(gdb)
	extendedUserRepo := repositories.NewExtendedUserRepository(gdb)
	
	// Initialize cascade deletion service
	cascadeDeletionSvc := services.NewCascadeDeletionService(
		sessionRepo,
		auditRepo,
		passwordChangeRepo,
		passwordHistoryRepo,
		forgotPasswordRepo,
	)
	
	// Initialize LGPD compliance checker with production configuration
	lgpdConfig := &services.LGPDComplianceConfig{
		TestingMode: false, // Production mode - enforce all restrictions
		EnableLegalHoldChecks: true,
		EnableContractChecks: true,
		EnableRegulatoryChecks: true,
		MinimumAccountAge: cfg.SelfDeletion.MinAccountAge, // SELF_DELETION_MIN_ACCOUNT_AGE (default 24h, 0 = no minimum)
		CoolingOffPeriod: 24 * time.Hour,
	}
	lgpdComplianceChecker := services.NewLGPDComplianceService(userRepo, auditRepo, lgpdConfig)
	
	// Initialize user deletion service with production LGPD-compliant scheduling
	deletionConfig := services.DefaultUserDeletionConfig()
	deletionConfig.TestingMode = false // Production mode - enforce LGPD scheduling constraints
	deletionConfig.SelfDeletionImmediate = cfg.SelfDeletion.Immediate     // SELF_DELETION_IMMEDIATE (default false)
	deletionConfig.RequirePassword = cfg.SelfDeletion.RequirePassword      // SELF_DELETION_REQUIRE_PASSWORD (default false)
	log.Printf("LGPD: Production mode - %s grace period and retention policies; self-deletion immediate=%t require_password=%t min_account_age=%s",
		deletionConfig.GracePeriod, cfg.SelfDeletion.Immediate, cfg.SelfDeletion.RequirePassword, cfg.SelfDeletion.MinAccountAge)
	
	userDeletionSvc := services.NewUserDeletionService(
		extendedUserRepo,
		deletionRequestRepo,
		dataExportRepo,
		deletionAuditRepo,
		cascadeDeletionSvc,
		lgpdComplianceChecker,
		auditSvc,
		sessionRepo,
		deletionConfig,
		services.WithDeletionPasswordService(passwordSvc),
		services.WithAccountStateInvalidator(identity.NewAccountInvalidator(rdb)),
	)

	// CB-182: Initialize validation services
	log.Println("CB-182: Initializing validation system...")

	// Initialize validation infrastructure
	validationLogger := validation.NewValidationLogger()
	validationMetrics := validation.NewValidationMetricsCollector()

	// Configure validation services
	rateLimitConfig := services.RateLimitConfig{
		DefaultWindowSize:   cfg.ValidationConfig.ValidationTimeout,
		DefaultLimit:        100, // 100 requests per window
		BruteForceThreshold: 5,   // 5 failed attempts
		BruteForceWindow:    cfg.ValidationConfig.ValidationTimeout,
		BlockDuration:       cfg.ValidationConfig.ValidationTimeout * 12, // 12x validation timeout
		EnableGracefulMode:  cfg.ValidationConfig.EnableGracefulMode,
	}
	rateLimitValidationSvc := services.NewRateLimitValidationService(rdb, rateLimitConfig)

	// Initialize real security violation repository for CB-182 (replaced mock for database persistence)
	securityViolationRepo := repositories.NewSecurityViolationRepository(gdb)

	// Initialize security validation service
	securityConfig := services.SecurityValidationConfig{
		EnableRealTimeScanning: true,
		MaxInputSize:           int(cfg.ValidationConfig.MaxRequestSize),
		SanitizationLevel:      "moderate",
	}
	securityValidationSvc := services.NewSecurityValidationService(securityViolationRepo, securityConfig)

	// Initialize business validation service
	businessConfig := services.BusinessValidationConfig{
		PasswordPolicy: passwordPolicy,
		EmailValidation: services.EmailValidationConfig{
			AllowedDomains:      []string{},
			BlockedDomains:      []string{"tempmail.com", "10minutemail.com"},
			RequireVerification: false,
			MaxLength:           254,
			Optional:            !cfg.Registration.RequireEmail, // REQUIRE_REGISTRATION_EMAIL=false
		},
		PhoneValidation: services.PhoneValidationConfig{
			RequiredFormat:   "E.164",
			AllowedCountries: []string{},
			BlockedCountries: []string{},
			RequireVerification: cfg.Registration.RequirePhoneVerification, // same switch as login (REQUIRE_PHONE_VERIFICATION)
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
		EnableCaching:     cfg.ValidationConfig.EnableValidationCaching,
		CacheTimeout:      cfg.ValidationConfig.CacheTimeout,
		MaxValidationTime: cfg.ValidationConfig.MaxValidationTime,
		EnableMetrics:     cfg.ValidationConfig.EnableMetrics,
		// REGISTRATION_RATE_LIMIT_PER_IP / REGISTRATION_RATE_LIMIT_WINDOW (default 2 per 30s)
		RegistrationRateLimit:  cfg.Registration.RateLimitPerIP,
		RegistrationRateWindow: cfg.Registration.RateLimitWindow,
	}
	requestValidationSvc := services.NewRequestValidationService(
		securityValidationSvc,
		businessValidationSvc,
		rateLimitValidationSvc,
		rdb,
		requestValidationConfig,
	)

	// CB-194: Initialize identifier resolution service and authentication strategies
	log.Println("CB-194: Initializing unified authentication system...")
	identifierResolver := services.NewIdentifierResolutionService()
	// REQUIRE_PHONE_VERIFICATION: one policy shared by the strategies and the auth service
	phoneVerification := domain.PhoneVerificationRule{Required: cfg.Registration.RequirePhoneVerification}
	emailAuthStrategy := services.NewEmailAuthStrategy(userRepo, passwordSvc, identifierResolver, services.WithStrategyPhoneVerificationPolicy(phoneVerification))
	phoneAuthStrategy := services.NewPhoneAuthStrategy(userRepo, passwordSvc, identifierResolver, services.WithStrategyPhoneVerificationPolicy(phoneVerification))

	// Initialize auth service with validation support and unified authentication (CB-194)
	authSvc := services.NewAuthService(userRepo, sessionRepo, passwordSvc, tokenSvc, otpSvc, policySvc, rdb, requestValidationSvc, auditSvc, identifierResolver, emailAuthStrategy, phoneAuthStrategy, services.WithPhoneVerificationPolicy(phoneVerification), services.WithPasswordPolicy(passwordPolicy))

	// Configure validation middleware
	validationConfig := middleware.ValidationConfig{
		EnableSecurityValidation: cfg.ValidationConfig.EnableSecurityValidation,
		EnableBusinessValidation: cfg.ValidationConfig.EnableBusinessValidation,
		EnableRateLimiting:       cfg.ValidationConfig.EnableRateLimiting,
		MaxRequestSize:           cfg.ValidationConfig.MaxRequestSize,
		ValidationTimeout:        cfg.ValidationConfig.ValidationTimeout,
		SkipValidationPaths:      cfg.ValidationConfig.SkipValidationPaths,
		LogValidationEvents:      cfg.ValidationConfig.LogValidationEvents,
		EnableMetrics:            cfg.ValidationConfig.EnableMetrics,
		ShadowMode:               cfg.ValidationConfig.ShadowMode, // CB-182: Shadow mode configuration
		RegistrationRequestsPerMinute: domain.RegistrationRequestsPerMinute(cfg.Registration.RateLimitPerIP, cfg.Registration.RateLimitWindow),
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

	// Bootstrap root / service administrator (idempotent, never blocks startup)
	services.NewBootstrapService(userRepo, passwordSvc, businessValidationSvc, auditSvc, nil).Run(
		context.Background(),
		services.BootstrapAccount(cfg.Bootstrap.RootAdmin),
		services.BootstrapAccount(cfg.Bootstrap.ServiceAdmin),
	)

	// Initialize handlers
	authH := handlers.NewAuthHandlers(authSvc, otpSvc, userRepo, tokenSvc, sessionRepo,
		handlers.WithRequireRegistrationEmail(cfg.Registration.RequireEmail),
		handlers.WithRequirePhoneVerification(cfg.Registration.RequirePhoneVerification),
		handlers.WithPasswordPolicyEnforced(true),
	)
	polH := &handlers.PolicyHandlers{E: cas.E}
	// Backend id translation for token.backend_user_id; nil (untyped) when not configured.
	var backendIdentity domain.BackendIdentityResolver
	if cfg.IdentityBackend.URL != "" {
		backendIdentity = identity.NewCachedResolver(
			identity.NewHTTPResolver(cfg.IdentityBackend.URL, cfg.IdentityBackend.APIKey, cfg.IdentityBackend.Timeout),
			rdb,
		)
	} else {
		log.Println("identity backend not configured (IDENTITY_BACKEND_URL empty): rules using token.backend_user_id will fail closed")
	}
	externalAuthzH := handlers.NewExternalAuthzHandlers(tokenSvc, sessionRepo, cas.E, backendIdentity)
	docsH := handlers.NewSwaggerDocsHandler()
	passwordChangeH := handlers.NewPasswordChangeHandlers(passwordChangeSvc)
	userDeletionH := handlers.NewUserDeletionHandlers(userDeletionSvc, authSvc)

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

	// Build router with CB-182 validation middleware and LGPD deletion handlers
	r := httpx.BuildRouterWithDeletion(authH, polH, externalAuthzH, docsH, passwordChangeH, userDeletionH, jwtMW, casbinMW, validationMW)

	httpx.ApplyClientIPPolicy(r, cfg.ClientIPHeader) // CLIENT_IP_HEADER; empty = TCP peer, no proxy trusted
	log.Printf("client address: header=%q (empty = TCP peer)", cfg.ClientIPHeader)

	// Admin: SMS accepted by the provider today / this month (no phone numbers)
	r.GET("/admin/sms/usage", jwtMW.WithJWT(), casbinMW.Enforce(), handlers.NewSMSUsageHandler(smsBudget).Usage)

	if err := EnsureStandardPolicies(cas.E); err != nil {
		return err
	}

	addr := ":" + cfg.Port
	log.Printf("listening on %s", addr)
	return http.ListenAndServe(addr, r)
}
