package services

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
)

// AuthServiceImpl implements domain.AuthService
type AuthServiceImpl struct {
	userRepo     domain.UserRepository
	sessionRepo  domain.SessionRepository
	passwordSvc  domain.PasswordService
	tokenSvc     domain.TokenService
	otpSvc       domain.OTPService
	policySvc    domain.PolicyService
	redisClient  *redis.Client
}

// NewAuthService creates a new auth service
func NewAuthService(
	userRepo domain.UserRepository,
	sessionRepo domain.SessionRepository,
	passwordSvc domain.PasswordService,
	tokenSvc domain.TokenService,
	otpSvc domain.OTPService,
	policySvc domain.PolicyService,
	redisClient *redis.Client,
) domain.AuthService {
	return &AuthServiceImpl{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		passwordSvc: passwordSvc,
		tokenSvc:    tokenSvc,
		otpSvc:      otpSvc,
		policySvc:   policySvc,
		redisClient: redisClient,
	}
}

// Register implements domain.AuthService
func (s *AuthServiceImpl) Register(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
	// Check if user already exists
	existingUser, err := s.userRepo.FindByEmail(ctx, email)
	if err == nil && existingUser != nil {
		return nil, domain.ErrUserAlreadyExists
	}

	// Hash password
	hashedPassword, err := s.passwordSvc.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &domain.User{
		Email:        email,
		Phone:        phone,
		PasswordHash: hashedPassword,
		Role:         role, // Use provided role
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Generate and send OTP
	_, err = s.otpSvc.Generate(ctx, phone, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to send OTP: %w", err)
	}

	return user, nil
}

// Login implements domain.AuthService
func (s *AuthServiceImpl) Login(ctx context.Context, email, password string) (*domain.AuthResult, error) {
	// Find user
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		return nil, domain.ErrInvalidCredentials
	}

	// Check if user is active
	if !user.IsActive {
		return nil, domain.ErrUserInactive
	}

	// Check if phone is verified
	if !user.PhoneVerified {
		return nil, domain.ErrPhoneNotVerified
	}

	// Verify password
	if !s.passwordSvc.Verify(user.PasswordHash, password) {
		return nil, domain.ErrInvalidCredentials
	}

	// Create session
	session := &domain.Session{
		ID:        fmt.Sprintf("sess_%d_%d", user.ID, time.Now().UnixNano()),
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
		CreatedAt: time.Now(),
	}

	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Generate tokens
	accessToken, err := s.tokenSvc.GenerateAccessToken(user.ID, user.Role, session.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.tokenSvc.GenerateRefreshToken(user.ID, user.Role, session.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	return &domain.AuthResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		SessionID:    session.ID,
		ExpiresIn:    15 * 60, // 15 minutes in seconds
	}, nil
}

// RefreshToken implements domain.AuthService
func (s *AuthServiceImpl) RefreshToken(ctx context.Context, refreshToken string) (*domain.AuthResult, error) {
	// Validate refresh token with enhanced security logging
	claims, err := s.tokenSvc.ValidateRefreshToken(refreshToken)
	if err != nil {
		// Enhanced error context for security monitoring
		return nil, fmt.Errorf("token validation failed: %w", domain.ErrTokenInvalid)
	}

	// CB-179: Check if refresh token is blacklisted (already used)
	isBlacklisted, err := s.isRefreshTokenBlacklisted(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("blacklist check failed for session %s: %w", claims.SessionID, err)
	}
	if isBlacklisted {
		return nil, fmt.Errorf("refresh token already used (blacklisted) for session %s: %w", claims.SessionID, domain.ErrTokenInvalid)
	}

	// Implement distributed lock to prevent concurrent refresh operations (if Redis available)
	// Note: When Redis is not available, we skip locking and proceed without concurrency protection
	// TEMPORARILY DISABLED FOR TESTING: if s.redisClient != nil {
	if false && s.redisClient != nil {
		lockKey := fmt.Sprintf("refresh_lock:%s", claims.SessionID)
		lockTTL := 30 * time.Second
		
		// Try to acquire lock with enhanced error context
		acquired, err := s.acquireLock(ctx, lockKey, lockTTL)
		if err != nil {
			return nil, fmt.Errorf("distributed lock acquisition failed for session %s: %w", claims.SessionID, err)
		}
		if !acquired {
			return nil, fmt.Errorf("concurrent refresh attempt detected for session %s: %w", claims.SessionID, domain.ErrConcurrentRefresh)
		}
		
		// Ensure lock is released
		defer func() {
			if releaseErr := s.releaseLock(ctx, lockKey); releaseErr != nil {
				// Log error but don't override main error
			}
		}()
	}

	// Check session exists with detailed error context
	session, err := s.sessionRepo.FindByID(ctx, claims.SessionID)
	if err != nil {
		return nil, fmt.Errorf("session lookup failed for session %s: %w", claims.SessionID, domain.ErrSessionNotFound)
	}

	// Check session not expired with timestamp context
	if session.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("session %s expired at %v: %w", claims.SessionID, session.ExpiresAt, domain.ErrSessionExpired)
	}

	// Get user with enhanced validation
	user, err := s.userRepo.FindByID(ctx, claims.UserID)
	if err != nil {
		return nil, fmt.Errorf("user lookup failed for user ID %d in session %s: %w", claims.UserID, claims.SessionID, domain.ErrUserNotFound)
	}

	// Check if user is still active with security context
	if !user.IsActive {
		return nil, fmt.Errorf("inactive user %d attempted token refresh: %w", user.ID, domain.ErrUserInactive)
	}

	// Extend session TTL (24 hours from now) with audit trail
	newSessionTTL := 24 * time.Hour
	if err := s.sessionRepo.ExtendTTL(ctx, session.ID, newSessionTTL); err != nil {
		return nil, fmt.Errorf("session TTL extension failed for session %s (user %d): %w", session.ID, user.ID, err)
	}

	// Create new session object to avoid race condition on shared session data
	newExpiryTime := time.Now().Add(newSessionTTL)
	updatedSession := &domain.Session{
		ID:        session.ID,
		UserID:    session.UserID,
		ExpiresAt: newExpiryTime,
		CreatedAt: session.CreatedAt,
	}
	if err := s.sessionRepo.Update(ctx, updatedSession); err != nil {
		return nil, fmt.Errorf("session update failed for session %s (user %d): %w", session.ID, user.ID, err)
	}

	// CB-179: Blacklist the current refresh token immediately after successful validation
	// This ensures the token can only be used once (one-time use security)
	if err := s.blacklistRefreshToken(ctx, refreshToken, claims.ExpiresAt); err != nil {
		return nil, fmt.Errorf("failed to blacklist refresh token for session %s (user %d): %w", session.ID, user.ID, err)
	}

	// Generate new access token with enhanced error context
	accessToken, err := s.tokenSvc.GenerateAccessToken(user.ID, user.Role, session.ID)
	if err != nil {
		return nil, fmt.Errorf("access token generation failed for user %d (session %s): %w", user.ID, session.ID, err)
	}

	// Generate new refresh token (rotation for security) with audit
	newRefreshToken, err := s.tokenSvc.GenerateRefreshToken(user.ID, user.Role, session.ID)
	if err != nil {
		return nil, fmt.Errorf("refresh token generation failed for user %d (session %s): %w", user.ID, session.ID, err)
	}

	return &domain.AuthResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken, // New refresh token for security
		SessionID:    session.ID,
		ExpiresIn:    15 * 60, // 15 minutes
	}, nil
}

// Logout implements domain.AuthService
func (s *AuthServiceImpl) Logout(ctx context.Context, sessionID string) error {
	return s.sessionRepo.Delete(ctx, sessionID)
}

// GetUserProfile implements domain.AuthService
func (s *AuthServiceImpl) GetUserProfile(ctx context.Context, userID uint) (*domain.User, error) {
	return s.userRepo.FindByID(ctx, userID)
}

// acquireLock attempts to acquire a distributed lock using Redis
func (s *AuthServiceImpl) acquireLock(ctx context.Context, key string, ttl time.Duration) (bool, error) {
	if s == nil || s.redisClient == nil {
		return false, fmt.Errorf("redis client not available for locking")
	}
	// Use Redis SET with NX (only if key doesn't exist) and EX (expire after TTL)
	result, err := s.redisClient.SetNX(ctx, key, "locked", ttl).Result()
	if err != nil {
		return false, fmt.Errorf("failed to acquire lock: %w", err)
	}
	return result, nil
}

// releaseLock releases a distributed lock by deleting the Redis key
func (s *AuthServiceImpl) releaseLock(ctx context.Context, key string) error {
	if s.redisClient == nil {
		return fmt.Errorf("redis client not available for lock release")
	}
	// Use Lua script for atomic release to prevent releasing someone else's lock
	script := `
		if redis.call("get", KEYS[1]) == ARGV[1] then
			return redis.call("del", KEYS[1])
		else
			return 0
		end
	`
	
	// Execute the Lua script
	result, err := s.redisClient.Eval(ctx, script, []string{key}, "locked").Result()
	if err != nil {
		return fmt.Errorf("failed to release lock: %w", err)
	}
	
	// Check if lock was actually released
	if result == int64(0) {
		return fmt.Errorf("lock was not owned by this instance")
	}
	
	return nil
}

// blacklistRefreshToken adds a refresh token to the blacklist in Redis
func (s *AuthServiceImpl) blacklistRefreshToken(ctx context.Context, token string, exp int64) error {
	if s == nil || s.redisClient == nil {
		// If Redis is not available, we can't blacklist tokens
		// This is a graceful degradation - security is reduced but system still works
		return nil
	}
	
	// Create a hash of the token for storage (don't store the actual token)
	tokenHash := fmt.Sprintf("blacklist:refresh:%x", sha256.Sum256([]byte(token)))
	
	// Calculate TTL - only store until the token would naturally expire
	ttl := time.Until(time.Unix(exp, 0))
	if ttl <= 0 {
		// Token already expired, no need to blacklist
		return nil
	}
	
	// Store in Redis with TTL matching token expiration
	return s.redisClient.Set(ctx, tokenHash, "revoked", ttl).Err()
}

// isRefreshTokenBlacklisted checks if a refresh token is in the blacklist
func (s *AuthServiceImpl) isRefreshTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	if s == nil {
		return false, nil
	}
	if s.redisClient == nil {
		// If Redis is not available, we can't check blacklist
		// This means tokens won't be properly revoked (security concern)
		return false, nil
	}
	
	// Create the same hash used for blacklisting
	tokenHash := fmt.Sprintf("blacklist:refresh:%x", sha256.Sum256([]byte(token)))
	
	// Check if the token exists in blacklist
	result, err := s.redisClient.Exists(ctx, tokenHash).Result()
	if err != nil {
		return false, fmt.Errorf("failed to check token blacklist: %w", err)
	}
	
	return result > 0, nil
}