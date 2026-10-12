package services

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
)

// AuthServiceImpl implements domain.AuthService
type AuthServiceImpl struct {
	userRepo        domain.UserRepository
	sessionRepo     domain.SessionRepository
	passwordSvc     domain.PasswordService
	tokenSvc        domain.TokenService
	otpSvc          domain.OTPService
	policySvc       domain.PolicyService
	redisClient     *redis.Client
	
	// Validation services
	requestValidator domain.RequestValidationService
	
	// Audit logging service - CB-183
	auditSvc        domain.ComprehensiveAuditService
	
	// CB-194: Authentication strategies and identifier resolution
	identifierResolver domain.IdentifierResolutionService
	emailAuthStrategy  domain.AuthenticationStrategy
	phoneAuthStrategy  domain.AuthenticationStrategy

	// phoneVerification is the single REQUIRE_PHONE_VERIFICATION switch (default: strict).
	phoneVerification domain.PhoneVerificationPolicy

	// passwordPolicy, when set, is checked before the request validator on registration and
	// admin creation (the same policy object the password change/reset flows use).
	passwordPolicy *domain.PasswordPolicy
}

// WithPasswordPolicy makes registration and admin creation enforce the password policy in the
// service itself, so the rule holds even when no request validator is wired. Unset by default.
func WithPasswordPolicy(policy domain.PasswordPolicy) AuthServiceOption {
	return func(s *AuthServiceImpl) { s.passwordPolicy = &policy }
}

// AuthServiceOption customises an AuthServiceImpl at construction.
type AuthServiceOption func(*AuthServiceImpl)

// WithPhoneVerificationPolicy sets the phone verification policy. The default is
// domain.StrictPhoneVerification(): unverified users cannot log in and registration sends an OTP.
func WithPhoneVerificationPolicy(policy domain.PhoneVerificationPolicy) AuthServiceOption {
	return func(s *AuthServiceImpl) {
		if policy != nil {
			s.phoneVerification = policy
		}
	}
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
	requestValidator domain.RequestValidationService,
	auditSvc domain.ComprehensiveAuditService,
	identifierResolver domain.IdentifierResolutionService,
	emailAuthStrategy domain.AuthenticationStrategy,
	phoneAuthStrategy domain.AuthenticationStrategy,
	opts ...AuthServiceOption,
) domain.AuthService {
	svc := &AuthServiceImpl{
		userRepo:           userRepo,
		sessionRepo:        sessionRepo,
		passwordSvc:        passwordSvc,
		tokenSvc:           tokenSvc,
		otpSvc:             otpSvc,
		policySvc:          policySvc,
		redisClient:        redisClient,
		requestValidator:   requestValidator,
		auditSvc:           auditSvc,
		identifierResolver: identifierResolver,
		emailAuthStrategy:  emailAuthStrategy,
		phoneAuthStrategy:  phoneAuthStrategy,
		phoneVerification:  domain.StrictPhoneVerification(),
	}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// Register implements domain.AuthService (public, unauthenticated registration).
// Only unprivileged roles may be self-registered; an empty role defaults to "user".
func (s *AuthServiceImpl) Register(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
	role = domain.NormalizeRegistrationRole(role)
	if !domain.IsRoleAllowedForPublicRegistration(role) {
		return nil, domain.ErrRoleNotAllowedForRegistration
	}
	return s.createUserAccount(ctx, "/auth/register", nil, email, phone, password, role)
}

// CreateUserByAdmin implements domain.AuthService. The creator (identity and role taken
// from the validated JWT) may only create the roles allowed by domain.CanCreateRole.
func (s *AuthServiceImpl) CreateUserByAdmin(ctx context.Context, creator *domain.User, email, phone, password, role string) (*domain.User, error) {
	if creator == nil || !domain.CanCreateRole(creator.Role, role) {
		return nil, domain.ErrRoleCreationNotAllowed
	}
	return s.createUserAccount(ctx, "/admin/users", creator, email, phone, password, role)
}

// createUserAccount holds the creation steps shared by public registration and privileged
// creation: validation, password hashing, persistence, audit event and OTP dispatch.
// creator is nil for public registration.
func (s *AuthServiceImpl) createUserAccount(ctx context.Context, endpoint string, creator *domain.User, email, phone, password, role string) (*domain.User, error) {
	if s.passwordPolicy != nil {
		// registration has never applied the e-mail similarity rule
		if violations := s.passwordPolicy.Check(password, ""); len(violations) > 0 {
			return nil, &domain.RegistrationValidationError{Code: violations[0].Code, Field: "password", Message: violations[0].Message}
		}
	}

	// Validate registration request if validator is available
	if s.requestValidator != nil {
		// Get client IP from context if available
		clientIP := "127.0.0.1" // default
		if ip, ok := ctx.Value("client_ip").(string); ok && ip != "" {
			clientIP = ip
		}

		validationCtx := &domain.ValidationContext{
			RequestID: fmt.Sprintf("reg_%d", time.Now().UnixNano()),
			Endpoint:  endpoint,
			Method:    "POST",
			Timestamp: time.Now(),
			IPAddress: clientIP,
			// Privileged creation is authenticated and authorized: no public per-IP rate limit.
			SkipRegistrationRateLimit: creator != nil,
		}

		validationResult, err := s.requestValidator.ValidateRegistrationRequest(ctx, email, phone, password, role, validationCtx)
		if err != nil {
			return nil, fmt.Errorf("registration validation failed: %w", err)
		}

		if !validationResult.Passed {
			// Convert validation errors to proper domain errors
			if len(validationResult.Errors) > 0 {
				firstError := validationResult.Errors[0]
				// Map validation error codes to domain errors
				switch firstError.Code {
				case "EMAIL_ALREADY_EXISTS", "PHONE_ALREADY_EXISTS":
					return nil, domain.ErrUserAlreadyExists
				case "RATE_LIMIT_EXCEEDED":
					return nil, domain.ErrRegistrationRateLimited
				default:
					// Client error: carry the validator's code, field and message
					return nil, &domain.RegistrationValidationError{Code: firstError.Code, Field: firstError.Field, Message: firstError.Message}
				}
			}
			return nil, domain.ErrValidationFailed
		}
	}

	// Phone is the only identifier of a user without e-mail and the database has no unique index
	// on it, so uniqueness is enforced here (also when no request validator is wired).
	if phone != "" {
		if existing, err := s.userRepo.FindByPhone(ctx, phone); err == nil && existing != nil {
			return nil, domain.ErrUserAlreadyExists
		}
	}

	// Hash password before transaction
	hashedPassword, err := s.passwordSvc.Hash(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user with atomic duplicate check using database constraints
	user := &domain.User{
		Email:        email,
		Phone:        phone,
		PasswordHash: hashedPassword,
		Role:         role,
		IsActive:     true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.userRepo.Create(ctx, user); err != nil {
		// Check if error is due to unique constraint violation (duplicate email/phone)
		errorMsg := err.Error()
		if strings.Contains(errorMsg, "duplicate key") ||
			strings.Contains(errorMsg, "UNIQUE constraint") ||
			strings.Contains(errorMsg, "violates unique constraint") ||
			strings.Contains(errorMsg, "duplicated key") ||
			strings.Contains(errorMsg, "already exists") {
			return nil, domain.ErrUserAlreadyExists
		}
		// Log failed registration attempt - CB-183
		if s.auditSvc != nil {
			metadata := map[string]interface{}{
				"email": email,
				"phone": phone,
				"role":  role,
				"error": err.Error(),
			}
			if creator != nil {
				metadata["created_by_user_id"] = creator.ID
				metadata["created_by_role"] = creator.Role
			}
			s.auditSvc.LogSystemEvent(ctx, "user_registration_failed",
				registrationFailureDescription(email),
				metadata)
		}
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Log successful registration - CB-183
	if s.auditSvc != nil {
		auditErr := s.auditSvc.LogUserRegistrationEvent(ctx, user.ID, email, phone, role)
		if auditErr != nil {
			// Log audit error but don't fail registration (graceful degradation)
			// In production, this could be logged to a monitoring system
		}
		// The registration event has no creator field, so the creator is recorded in the
		// metadata of a companion system event.
		if creator != nil {
			_ = s.auditSvc.LogSystemEvent(ctx, "user_created_by_admin",
				fmt.Sprintf("User %d created by user %d (%s)", user.ID, creator.ID, creator.Role),
				map[string]interface{}{
					"created_user_id":    user.ID,
					"created_user_role":  role,
					"created_by_user_id": creator.ID,
					"created_by_role":    creator.Role,
				})
		}
	}

	// Generate and send OTP only when phone verification is required; otherwise registration
	// never depends on (or fails because of) OTP sending or throttling.
	if s.phoneVerification.RequiresPhoneVerification() {
		_, err = s.otpSvc.Generate(ctx, phone, user.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to send OTP: %w", err)
		}
	}

	return user, nil
}

// registrationFailureDescription describes a failed registration without an empty e-mail.
func registrationFailureDescription(email string) string {
	if email == "" {
		return "Failed to register user without email"
	}
	return fmt.Sprintf("Failed to register user with email %s", email)
}

// Login implements domain.AuthService
func (s *AuthServiceImpl) Login(ctx context.Context, email, password string) (*domain.AuthResult, error) {
	// Validate login request if validator is available
	if s.requestValidator != nil {
		validationCtx := &domain.ValidationContext{
			RequestID: fmt.Sprintf("login_%d", time.Now().UnixNano()),
			Endpoint:  "/auth/login",
			Method:    "POST",
			Timestamp: time.Now(),
		}
		
		validationResult, err := s.requestValidator.ValidateLoginRequest(ctx, email, password, validationCtx)
		if err != nil {
			return nil, fmt.Errorf("login validation failed: %w", err)
		}
		
		if !validationResult.Passed {
			// Convert validation errors to domain errors
			if len(validationResult.Errors) > 0 {
				return nil, fmt.Errorf("login validation failed: %s", validationResult.Errors[0].Message)
			}
			return nil, domain.ErrValidationFailed
		}
	}

	// Find user
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		// Log failed login attempt - user not found - CB-183
		if s.auditSvc != nil {
			s.auditSvc.LogLoginAttempt(ctx, 0, email, "", false, "user not found")
		}
		return nil, domain.ErrInvalidCredentials
	}

	// Check if user is active
	if !user.IsActive {
		// Log failed login attempt - user inactive - CB-183
		if s.auditSvc != nil {
			s.auditSvc.LogLoginAttempt(ctx, user.ID, email, "", false, "user inactive")
		}
		return nil, domain.ErrUserInactive
	}

	// Check if phone is verified (REQUIRE_PHONE_VERIFICATION)
	if s.phoneVerification.ShouldEnforceVerification(user) {
		// Log failed login attempt - phone not verified - CB-183
		if s.auditSvc != nil {
			s.auditSvc.LogLoginAttempt(ctx, user.ID, email, "", false, "phone not verified")
		}
		return nil, domain.ErrPhoneNotVerified
	}

	// Verify password
	if !s.passwordSvc.Verify(user.PasswordHash, password) {
		// Log failed login attempt - invalid password - CB-183
		if s.auditSvc != nil {
			s.auditSvc.LogLoginAttempt(ctx, user.ID, email, "", false, "invalid password")
		}
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
	accessToken, err := s.tokenSvc.GenerateUserAccessToken(user.ID, user.Role, session.ID, user.Phone, user.PhoneVerified)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.tokenSvc.GenerateRefreshToken(user.ID, user.Role, session.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Log successful login - CB-183
	if s.auditSvc != nil {
		s.auditSvc.LogLoginAttempt(ctx, user.ID, email, "", true, "login successful")
	}

	return &domain.AuthResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		SessionID:    session.ID,
		ExpiresIn:    15 * 60, // 15 minutes in seconds
	}, nil
}

// AuthenticateUser implements domain.AuthService - CB-194
// Provides unified authentication with support for email or phone identifier
func (s *AuthServiceImpl) AuthenticateUser(ctx context.Context, request *domain.AuthRequest) (*domain.AuthResult, error) {
	startTime := time.Now()
	
	// Determine which identifier to use (backward compatibility support)
	var identifier string
	var authMethod domain.IdentifierType
	var resolution *domain.IdentifierResolution
	
	if request.Email != "" {
		// Legacy email field takes precedence for backward compatibility
		identifier = request.Email
		authMethod = domain.IdentifierTypeEmail
	} else if request.Identifier != "" {
		// Use unified identifier field and resolve its type
		identifier = request.Identifier
		
		// Resolve identifier type and normalize
		var err error
		resolution, err = s.identifierResolver.ResolveIdentifier(ctx, identifier)
		if err != nil {
			return nil, fmt.Errorf("identifier resolution failed: %w", err)
		}
		
		if !resolution.IsValid {
			return nil, fmt.Errorf("%w: %s", domain.ErrInvalidIdentifier, resolution.ValidationMessage)
		}
		
		authMethod = resolution.Type
		identifier = resolution.NormalizedValue
	} else {
		return nil, fmt.Errorf("either email or identifier field must be provided")
	}
	
	if request.Password == "" {
		return nil, fmt.Errorf("password is required")
	}
	
	resolutionDuration := time.Since(startTime)
	
	// Select appropriate authentication strategy
	var authStrategy domain.AuthenticationStrategy
	switch authMethod {
	case domain.IdentifierTypeEmail:
		authStrategy = s.emailAuthStrategy
	case domain.IdentifierTypePhone:
		authStrategy = s.phoneAuthStrategy
	default:
		return nil, fmt.Errorf("unsupported authentication method: %s", authMethod)
	}
	
	clientIP, _ := ctx.Value("client_ip").(string)

	// Perform authentication using selected strategy
	lookupStart := time.Now()
	user, err := authStrategy.Authenticate(ctx, identifier, request.Password)
	if err != nil {
		// Log failed authentication attempt - CB-183
		if s.auditSvc != nil {
			// The account the attempt was for, when the identifier resolved to one; 0 for an unknown identifier.
			var failedUserID uint
			var failure *domain.AuthFailureError
			if errors.As(err, &failure) {
				failedUserID = failure.UserID
			}
			s.auditSvc.LogLoginAttempt(ctx, failedUserID, identifier, clientIP, false, err.Error())
		}
		return nil, err
	}
	lookupDuration := time.Since(lookupStart)
	
	// Generate session and tokens
	sessionStart := time.Now()
	session := &domain.Session{
		ID:        fmt.Sprintf("sess_%d_%d", user.ID, time.Now().UnixNano()),
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}
	
	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}
	
	// Generate tokens
	accessToken, err := s.tokenSvc.GenerateUserAccessToken(user.ID, user.Role, session.ID, user.Phone, user.PhoneVerified)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}
	
	refreshToken, err := s.tokenSvc.GenerateRefreshToken(user.ID, user.Role, session.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}
	tokenDuration := time.Since(sessionStart)
	
	// Create authentication context for metadata
	authContext := &domain.AuthenticationContext{
		Method:               authMethod,
		OriginalIdentifier:   request.Identifier,
		NormalizedIdentifier: identifier,
		AuthenticatedAt:      time.Now(),
		ResolutionDuration:   resolutionDuration,
		LookupDuration:       lookupDuration,
		ValidationDuration:   tokenDuration,
	}
	
	// Add country code for phone authentication
	if resolution != nil && authMethod == domain.IdentifierTypePhone {
		authContext.CountryCode = resolution.CountryCode
	}
	
	// Extract client info from context if available
	if userAgent, ok := ctx.Value("user_agent").(string); ok {
		authContext.UserAgent = userAgent
	}
	if ipAddress, ok := ctx.Value("client_ip").(string); ok {
		authContext.IPAddress = ipAddress
	}
	
	// Log successful authentication - CB-183 with method metadata
	if s.auditSvc != nil {
		s.auditSvc.LogLoginAttempt(ctx, user.ID, identifier, clientIP, true, 
			fmt.Sprintf("authentication successful via %s", authMethod))
	}
	
	return &domain.AuthResult{
		User:                  user,
		AccessToken:           accessToken,
		RefreshToken:          refreshToken,
		SessionID:             session.ID,
		ExpiresIn:             15 * 60, // 15 minutes in seconds
		AuthenticationContext: authContext,
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
	// Use Redis distributed locking to prevent concurrent refresh token usage
	if s.redisClient != nil {
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
	accessToken, err := s.tokenSvc.GenerateUserAccessToken(user.ID, user.Role, session.ID, user.Phone, user.PhoneVerified)
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

// AddProfile implements domain.AuthService: the user adds the client or contact profile to their
// own account. The role rule is domain.NextRoleOnAddProfile; the new role is read from and written
// to the database, so the next refresh or login issues a token with it.
func (s *AuthServiceImpl) AddProfile(ctx context.Context, userID uint, add string) (*domain.User, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if !user.IsActive {
		return nil, domain.ErrUserInactive
	}

	newRole, err := domain.NextRoleOnAddProfile(user.Role, add)
	if err != nil {
		return nil, err
	}
	if newRole == user.Role {
		return user, nil // profile already held: no-op, nothing to persist or audit
	}

	oldRole := user.Role
	user.Role = newRole
	user.UpdatedAt = time.Now()
	if err := s.userRepo.Update(ctx, user); err != nil {
		return nil, fmt.Errorf("failed to update role: %w", err)
	}

	if s.auditSvc != nil {
		_ = s.auditSvc.LogSystemEvent(ctx, domain.EventTypeRoleChange,
			fmt.Sprintf("User %d added profile %s (%s -> %s)", user.ID, add, oldRole, newRole),
			map[string]interface{}{
				"user_id":  user.ID,
				"old_role": oldRole,
				"new_role": newRole,
				"added":    add,
			})
	}
	return user, nil
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
		// SECURITY: If Redis is not available, we cannot verify token blacklist
		// Return error to fail-safe and prevent potential token reuse
		return false, fmt.Errorf("blacklist verification unavailable: Redis connection required for security")
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