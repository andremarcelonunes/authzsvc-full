package app

import (
	"time"

	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/config"
	"github.com/you/authzsvc/internal/infrastructure/auth"
	"github.com/you/authzsvc/internal/infrastructure/notifications"
	"github.com/you/authzsvc/internal/infrastructure/repositories"
	"github.com/you/authzsvc/internal/services"
)

// Container holds all dependencies
type Container struct {
	// Config
	Config *config.Config

	// Infrastructure
	DB          *gorm.DB
	RedisClient *redis.Client

	// Repositories
	UserRepo    domain.UserRepository
	SessionRepo domain.SessionRepository

	// Services
	PasswordSvc               domain.PasswordService
	TokenSvc                  domain.TokenService
	NotificationSvc           domain.NotificationService
	OTPSvc                    domain.OTPService
	AuthSvc                   domain.AuthService
	PolicySvc                 domain.PolicyService
	
	// Validation services
	SecurityValidationSvc     domain.SecurityValidationService
	BusinessValidationSvc     domain.BusinessValidationService
	RateLimitValidationSvc    domain.RateLimitValidationService
	RequestValidationSvc      domain.RequestValidationService
	
	// Audit services (CB-183)
	AuditRepo                 domain.ComprehensiveAuditRepository
	AuditSvc                  domain.ComprehensiveAuditService
}

// NewContainer creates and initializes all dependencies
func NewContainer(cfg *config.Config) (*Container, error) {
	container := &Container{Config: cfg}

	// Initialize infrastructure
	if err := container.initDatabase(); err != nil {
		return nil, err
	}
	if err := container.initRedis(); err != nil {
		return nil, err
	}

	// Initialize repositories
	container.initRepositories()

	// Initialize services
	if err := container.initServices(); err != nil {
		return nil, err
	}

	// Initialize validation services
	if err := container.initValidationServices(); err != nil {
		return nil, err
	}

	return container, nil
}

func (c *Container) initDatabase() error {
	db, err := gorm.Open(postgres.Open(c.Config.DSN), &gorm.Config{})
	if err != nil {
		return err
	}

	// Auto-migrate
	if err := db.AutoMigrate(&repositories.DBUser{}, &domain.ComprehensiveAuditEvent{}); err != nil {
		return err
	}

	c.DB = db
	return nil
}

func (c *Container) initRedis() error {
	c.RedisClient = redis.NewClient(&redis.Options{
		Addr:     c.Config.RedisAddr,
		Password: c.Config.RedisPassword,
		DB:       c.Config.RedisDB,
	})
	return nil
}

func (c *Container) initRepositories() {
	c.UserRepo = repositories.NewUserRepository(c.DB)
	c.SessionRepo = repositories.NewSessionRepository(c.RedisClient, c.Config.RefreshTTL)
	
	// Initialize audit repository (CB-183)
	c.AuditRepo = repositories.NewComprehensiveAuditRepository(c.DB)
}

func (c *Container) initServices() error {
	// Initialize basic services
	c.PasswordSvc = auth.NewPasswordService()
	c.TokenSvc = auth.NewJWTService(
		c.Config.JWTSecret,
		c.Config.JWTIssuer,
		c.Config.AccessTTL,
		c.Config.RefreshTTL,
	)
	c.NotificationSvc = notifications.NewTwilioService(
		c.Config.TwilioSID,
		c.Config.TwilioToken,
		c.Config.TwilioFrom,
	)

	// Initialize audit service (CB-183)
	c.AuditSvc = services.NewComprehensiveAuditService(c.AuditRepo, nil, nil, nil, nil, nil, c.Config, nil)

	// Initialize OTP service
	otpConfig := services.OTPConfig{
		Length:       c.Config.OTP_Length,
		TTL:          c.Config.OTP_TTL,
		MaxAttempts:  c.Config.OTP_MaxAttempts,
		ResendWindow: c.Config.OTP_ResendWindow,
	}
	c.OTPSvc = services.NewOTPService(c.NotificationSvc, c.UserRepo, c.RedisClient, otpConfig)

	// Initialize auth service (depends on all other services)
	// Note: RequestValidationSvc will be set after validation services are initialized
	
	// CB-194: Initialize identifier resolution and authentication strategies
	identifierResolver := services.NewIdentifierResolutionService()
	emailAuthStrategy := services.NewEmailAuthStrategy(c.UserRepo, c.PasswordSvc, identifierResolver)
	phoneAuthStrategy := services.NewPhoneAuthStrategy(c.UserRepo, c.PasswordSvc, identifierResolver)
	
	c.AuthSvc = services.NewAuthService(
		c.UserRepo,
		c.SessionRepo,
		c.PasswordSvc,
		c.TokenSvc,
		c.OTPSvc,
		c.PolicySvc, // Will be initialized separately
		c.RedisClient,
		nil,                  // RequestValidationSvc will be set in initValidationServices
		c.AuditSvc,           // CB-183: Audit service
		identifierResolver,   // CB-194: Identifier resolution service
		emailAuthStrategy,    // CB-194: Email authentication strategy
		phoneAuthStrategy,    // CB-194: Phone authentication strategy
	)

	return nil
}

func (c *Container) initValidationServices() error {
	// Initialize rate limit validation service
	rateLimitConfig := services.RateLimitConfig{
		DefaultWindowSize:   1 * time.Hour,
		DefaultLimit:        100,
		BruteForceThreshold: 5,
		BruteForceWindow:    15 * time.Minute,
		BlockDuration:       1 * time.Hour,
		EnableGracefulMode:  true, // Continue without Redis if unavailable
	}
	c.RateLimitValidationSvc = services.NewRateLimitValidationService(c.RedisClient, rateLimitConfig)

	// Initialize security validation service
	securityConfig := services.SecurityValidationConfig{
		EnableRealTimeScanning: true,
		MaxInputSize:          1024 * 1024, // 1MB
		SanitizationLevel:     "moderate",
	}
	c.SecurityValidationSvc = services.NewSecurityValidationService(nil, securityConfig) // TODO: Add violation repository

	// Initialize business validation service
	businessConfig := services.BusinessValidationConfig{
		PasswordPolicy: services.PasswordPolicy{
			MinLength:           8,
			MaxLength:           128,
			RequireUppercase:    true,
			RequireLowercase:    true,
			RequireNumbers:      true,
			RequireSpecialChars: true,
			MaxRepeatingChars:   3,
			ForbiddenPasswords: []string{
				"password", "123456", "qwerty", "admin", "user",
				"password123", "123456789", "12345678", "abc123",
			},
		},
		EmailValidation: services.EmailValidationConfig{
			AllowedDomains:      []string{}, // Empty means allow all
			BlockedDomains:      []string{"tempmail.com", "10minutemail.com", "guerrillamail.com"},
			RequireVerification: true,
			MaxLength:          254,
		},
		UserLimits: services.UserLimitsConfig{
			MaxRegistrationsPerIP:   5,
			MaxRegistrationsPerDay:  10,
			MaxLoginAttemptsPerHour: 10,
			MaxOTPAttemptsPerHour:   5,
		},
	}
	c.BusinessValidationSvc = services.NewBusinessValidationService(c.UserRepo, businessConfig)

	// Initialize request validation service (orchestrates all validation)
	requestConfig := services.RequestValidationConfig{
		EnableCaching:     true,
		CacheTimeout:      5 * time.Minute,
		MaxValidationTime: 30 * time.Second,
		EnableMetrics:     true,
	}
	c.RequestValidationSvc = services.NewRequestValidationService(
		c.SecurityValidationSvc,
		c.BusinessValidationSvc,
		c.RateLimitValidationSvc,
		c.RedisClient,
		requestConfig,
	)

	// Update AuthService with the request validator
	// CB-194: Re-initialize CB-194 services for consistency
	identifierResolver := services.NewIdentifierResolutionService()
	emailAuthStrategy := services.NewEmailAuthStrategy(c.UserRepo, c.PasswordSvc, identifierResolver)
	phoneAuthStrategy := services.NewPhoneAuthStrategy(c.UserRepo, c.PasswordSvc, identifierResolver)
	
	c.AuthSvc = services.NewAuthService(
		c.UserRepo,
		c.SessionRepo,
		c.PasswordSvc,
		c.TokenSvc,
		c.OTPSvc,
		c.PolicySvc,
		c.RedisClient,
		c.RequestValidationSvc,
		c.AuditSvc,           // CB-183: Audit service
		identifierResolver,   // CB-194: Identifier resolution service
		emailAuthStrategy,    // CB-194: Email authentication strategy
		phoneAuthStrategy,    // CB-194: Phone authentication strategy
	)

	return nil
}

// Close closes all connections
func (c *Container) Close() error {
	if c.RedisClient != nil {
		c.RedisClient.Close()
	}

	if c.DB != nil {
		sqlDB, err := c.DB.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}

	return nil
}