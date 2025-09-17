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
	
	authSvc := services.NewAuthService(userRepo, sessionRepo, passwordSvc, tokenSvc, otpSvc, policySvc)
	
	// Initialize handlers  
	authH := handlers.NewAuthHandlers(authSvc, otpSvc, userRepo)
	polH := &handlers.PolicyHandlers{E: cas.E}
	
	// Initialize middleware
	jwtMW := middleware.NewAuthMW(tokenSvc, sessionRepo)
	casbinMW := middleware.NewCasbinMW(cas.E, cfg.OwnershipRules)
	
	// Build router
	r := httpx.BuildRouter(authH, polH, jwtMW, casbinMW)

	policies, _ := cas.E.GetPolicy()
	if len(policies) == 0 {
		cas.E.AddPolicy("role_admin", "/admin/*", "(GET|POST|PUT|DELETE)")
		cas.E.AddPolicy("role_user", "/auth/me", "GET")
		cas.E.AddPolicy("role_user", "/auth/logout", "POST")
		cas.E.AddPolicy("role_user", "/auth/otp/*", "POST")
		_ = cas.E.SavePolicy()
		log.Println("casbin: seeded default policies")
	}
	addr := ":" + cfg.Port
	log.Printf("listening on %s", addr)
	return http.ListenAndServe(addr, r)
}
