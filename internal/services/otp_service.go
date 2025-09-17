package services

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
)

// OTPServiceImpl implements domain.OTPService using Redis persistence
type OTPServiceImpl struct {
	notificationSvc domain.NotificationService
	userRepo        domain.UserRepository
	redisClient     *redis.Client
	config          OTPConfig
}

type OTPConfig struct {
	Length       int
	TTL          time.Duration
	MaxAttempts  int
	ResendWindow time.Duration
}

// NewOTPService creates a new Redis-based OTP service
func NewOTPService(notificationSvc domain.NotificationService, userRepo domain.UserRepository, redisClient *redis.Client, config OTPConfig) domain.OTPService {
	return &OTPServiceImpl{
		notificationSvc: notificationSvc,
		userRepo:        userRepo,
		redisClient:     redisClient,
		config:          config,
	}
}

// Generate implements domain.OTPService with Redis persistence
func (s *OTPServiceImpl) Generate(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) {
	otpKey := fmt.Sprintf("otp:%s:%d", phone, userID)
	resendKey := fmt.Sprintf("otp:res:%s", phone)
	attemptsKey := fmt.Sprintf("otp:att:%s:%d", phone, userID)

	// Check resend throttle
	if canResend, waitTime, _ := s.CanResend(ctx, phone); !canResend {
		return nil, fmt.Errorf("please wait %d seconds before requesting new OTP", waitTime)
	}

	// Generate secure OTP code
	code, err := s.generateSecureCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate OTP code: %w", err)
	}

	// Store OTP in Redis with TTL
	if err := s.redisClient.Set(ctx, otpKey, code, s.config.TTL).Err(); err != nil {
		return nil, fmt.Errorf("failed to store OTP in Redis: %w", err)
	}

	// Initialize attempts counter
	if err := s.redisClient.Set(ctx, attemptsKey, 0, s.config.TTL).Err(); err != nil {
		return nil, fmt.Errorf("failed to initialize attempts counter: %w", err)
	}

	// Set resend throttle
	if err := s.redisClient.Set(ctx, resendKey, 1, s.config.ResendWindow).Err(); err != nil {
		return nil, fmt.Errorf("failed to set resend throttle: %w", err)
	}

	// Create OTP request object for response
	otpReq := &domain.OTPRequest{
		Phone:     phone,
		Code:      code,
		UserID:    userID,
		ExpiresAt: time.Now().Add(s.config.TTL),
		Attempts:  0,
	}

	// Send SMS notification
	message := fmt.Sprintf("Your verification code is: %s. Valid for %d minutes.", code, int(s.config.TTL.Minutes()))
	if err := s.notificationSvc.SendSMS(phone, message); err != nil {
		// Clean up Redis entries if SMS fails
		s.redisClient.Del(ctx, otpKey, attemptsKey, resendKey)
		return nil, fmt.Errorf("failed to send OTP SMS: %w", err)
	}

	return otpReq, nil
}

// Verify implements domain.OTPService with Redis persistence
func (s *OTPServiceImpl) Verify(ctx context.Context, phone, code string, userID uint) (bool, error) {
	otpKey := fmt.Sprintf("otp:%s:%d", phone, userID)
	attemptsKey := fmt.Sprintf("otp:att:%s:%d", phone, userID)

	// Increment attempts counter atomically
	attempts, err := s.redisClient.Incr(ctx, attemptsKey).Result()
	if err != nil {
		return false, fmt.Errorf("failed to increment attempts: %w", err)
	}

	// Check max attempts
	if attempts > int64(s.config.MaxAttempts) {
		// Clean up Redis entries
		s.redisClient.Del(ctx, otpKey, attemptsKey)
		return false, domain.ErrOTPMaxAttempts
	}

	// Get stored OTP
	storedCode, err := s.redisClient.Get(ctx, otpKey).Result()
	if err == redis.Nil {
		return false, domain.ErrOTPNotFound
	}
	if err != nil {
		return false, fmt.Errorf("failed to get OTP from Redis: %w", err)
	}

	// Verify code
	if storedCode != code {
		return false, domain.ErrOTPInvalid
	}

	// Success - clean up Redis entries
	s.redisClient.Del(ctx, otpKey, attemptsKey)

	return true, nil
}

// CanResend implements domain.OTPService with Redis-based throttling
func (s *OTPServiceImpl) CanResend(ctx context.Context, phone string) (bool, int64, error) {
	resendKey := fmt.Sprintf("otp:res:%s", phone)
	
	ttl, err := s.redisClient.TTL(ctx, resendKey).Result()
	if err != nil {
		return false, 0, fmt.Errorf("failed to check resend TTL: %w", err)
	}

	// If TTL <= 0, key doesn't exist or has expired - can resend
	if ttl <= 0 {
		return true, 0, nil
	}

	// Must wait for TTL to expire
	return false, int64(ttl.Seconds()), nil
}

// generateSecureCode generates a cryptographically secure OTP code
func (s *OTPServiceImpl) generateSecureCode() (string, error) {
	digits := make([]byte, s.config.Length)
	
	for i := 0; i < s.config.Length; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", fmt.Errorf("failed to generate random digit: %w", err)
		}
		digits[i] = byte('0' + num.Int64())
	}
	
	return string(digits), nil
}