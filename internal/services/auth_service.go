package services

import (
	"context"
	"fmt"
	"time"

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
}

// NewAuthService creates a new auth service
func NewAuthService(
	userRepo domain.UserRepository,
	sessionRepo domain.SessionRepository,
	passwordSvc domain.PasswordService,
	tokenSvc domain.TokenService,
	otpSvc domain.OTPService,
	policySvc domain.PolicyService,
) domain.AuthService {
	return &AuthServiceImpl{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		passwordSvc: passwordSvc,
		tokenSvc:    tokenSvc,
		otpSvc:      otpSvc,
		policySvc:   policySvc,
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
	// Validate refresh token
	claims, err := s.tokenSvc.ValidateRefreshToken(refreshToken)
	if err != nil {
		return nil, domain.ErrTokenInvalid
	}

	// Check session exists
	session, err := s.sessionRepo.FindByID(ctx, claims.SessionID)
	if err != nil {
		return nil, domain.ErrSessionNotFound
	}

	// Check session not expired
	if session.ExpiresAt.Before(time.Now()) {
		return nil, domain.ErrSessionExpired
	}

	// Get user
	user, err := s.userRepo.FindByID(ctx, claims.UserID)
	if err != nil {
		return nil, domain.ErrUserNotFound
	}

	// Generate new access token
	accessToken, err := s.tokenSvc.GenerateAccessToken(user.ID, user.Role, session.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &domain.AuthResult{
		User:         user,
		AccessToken:  accessToken,
		RefreshToken: refreshToken, // Keep same refresh token
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