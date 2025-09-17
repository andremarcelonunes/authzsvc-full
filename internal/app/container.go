package app

import (
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
	PasswordSvc     domain.PasswordService
	TokenSvc        domain.TokenService
	NotificationSvc domain.NotificationService
	OTPSvc          domain.OTPService
	AuthSvc         domain.AuthService
	PolicySvc       domain.PolicyService
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

	return container, nil
}

func (c *Container) initDatabase() error {
	db, err := gorm.Open(postgres.Open(c.Config.DSN), &gorm.Config{})
	if err != nil {
		return err
	}

	// Auto-migrate
	if err := db.AutoMigrate(&repositories.DBUser{}); err != nil {
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

	// Initialize OTP service
	otpConfig := services.OTPConfig{
		Length:       c.Config.OTP_Length,
		TTL:          c.Config.OTP_TTL,
		MaxAttempts:  c.Config.OTP_MaxAttempts,
		ResendWindow: c.Config.OTP_ResendWindow,
	}
	c.OTPSvc = services.NewOTPService(c.NotificationSvc, c.UserRepo, c.RedisClient, otpConfig)

	// Initialize auth service (depends on all other services)
	c.AuthSvc = services.NewAuthService(
		c.UserRepo,
		c.SessionRepo,
		c.PasswordSvc,
		c.TokenSvc,
		c.OTPSvc,
		c.PolicySvc, // Will be initialized separately
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