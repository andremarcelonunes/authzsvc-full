package services

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
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
	digester        *OTPDigester
	config          OTPConfig
}

type OTPConfig struct {
	Length       int
	TTL          time.Duration
	MaxAttempts  int
	ResendWindow time.Duration
	// Secret keys the digest under which codes are stored in Redis (the JWT secret in production).
	// Empty: a random per-process key is used. Codes are never stored in clear.
	Secret string
	// Brand opens the SMS text (SMS_BRAND); empty means domain.DefaultSMSBrand.
	Brand string
}

// otpResendThrottledError keeps the human-readable wait message while matching
// domain.ErrOTPResendThrottled through errors.Is.
type otpResendThrottledError struct {
	waitSeconds int64
}

func (e *otpResendThrottledError) Error() string {
	return fmt.Sprintf("please wait %d seconds before requesting new OTP", e.waitSeconds)
}

func (e *otpResendThrottledError) Unwrap() error {
	return domain.ErrOTPResendThrottled
}

// NewOTPService creates a new Redis-based OTP service
func NewOTPService(notificationSvc domain.NotificationService, userRepo domain.UserRepository, redisClient *redis.Client, config OTPConfig) domain.OTPService {
	return &OTPServiceImpl{
		notificationSvc: notificationSvc,
		userRepo:        userRepo,
		redisClient:     redisClient,
		digester:        NewOTPDigester(config.Secret),
		config:          config,
	}
}

// smsSender is implemented by the budgeted notifier: it takes the request context (caller address).
type smsSender interface {
	SendSMSContext(ctx context.Context, to, message string) error
}

func (s *OTPServiceImpl) sendSMS(ctx context.Context, to, message string) error {
	if sender, ok := s.notificationSvc.(smsSender); ok {
		return sender.SendSMSContext(ctx, to, message)
	}
	return s.notificationSvc.SendSMS(to, message)
}

// OTPMessage is the SMS text of a code. Every text is a single GSM-7 segment: no accented letters
// outside the GSM-7 alphabet (so no a-acute, a-circumflex, tilde, i-acute, o-acute, u-acute, e-circumflex,
// o-circumflex), and well under 160 characters.
func OTPMessage(brand string, purpose domain.OTPPurpose, code string, ttl time.Duration) string {
	if brand == "" {
		brand = domain.DefaultSMSBrand
	}
	minutes := int(ttl.Minutes())
	if minutes < 1 {
		minutes = 1
	}
	switch purpose {
	case domain.OTPPurposePasswordReset:
		return fmt.Sprintf("%s: codigo para redefinir a senha %s. Valido por %d min. Nao compartilhe.", brand, code, minutes)
	case domain.OTPPurposePasswordChange:
		return fmt.Sprintf("%s: codigo para confirmar a troca de senha %s. Valido por %d min. Nao compartilhe.", brand, code, minutes)
	default:
		return fmt.Sprintf("%s: codigo de verificacao %s. Valido por %d min. Nao compartilhe.", brand, code, minutes)
	}
}

// Generate implements domain.OTPService with Redis persistence.
//
// While a still-valid code is out, asking again answers like a fresh request but sends nothing
// (AlreadySent), unless the resend window and the SMS budget's minimum interval have both passed
// and every cap allows another SMS. The code is stored only after the SMS was accepted, so a
// refused resend never destroys the valid code.
func (s *OTPServiceImpl) Generate(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) {
	otpKey := fmt.Sprintf("otp:%s:%d", phone, userID)
	resendKey := fmt.Sprintf("otp:res:%s", phone)
	attemptsKey := fmt.Sprintf("otp:att:%s:%d", phone, userID)

	validCodeOut, err := s.redisClient.Exists(ctx, otpKey).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to check OTP in Redis: %w", err)
	}

	// Check resend throttle
	if canResend, waitTime, _ := s.CanResend(ctx, phone); !canResend {
		if validCodeOut == 1 {
			return s.alreadySent(ctx, otpKey, phone, userID), nil
		}
		return nil, &otpResendThrottledError{waitSeconds: waitTime}
	}

	// Generate secure OTP code
	code, err := s.generateSecureCode()
	if err != nil {
		return nil, fmt.Errorf("failed to generate OTP code: %w", err)
	}

	// Send SMS notification (the budget is consulted inside the notifier)
	message := OTPMessage(s.config.Brand, domain.OTPPurposeFrom(ctx), code, s.config.TTL)
	if err := s.sendSMS(ctx, phone, message); err != nil {
		var limit *domain.SMSLimitError
		if validCodeOut == 1 && (errors.As(err, &limit) || errors.Is(err, domain.ErrSMSUnavailable)) {
			log.Printf("OTP resend for user %d not sent, valid code still out: %v", userID, err)
			return s.alreadySent(ctx, otpKey, phone, userID), nil
		}
		return nil, fmt.Errorf("failed to send OTP SMS: %w", err)
	}

	// Store only the digest, reset attempts, start the resend window
	if err := s.redisClient.Set(ctx, otpKey, s.digester.Digest(otpKey, code), s.config.TTL).Err(); err != nil {
		return nil, fmt.Errorf("failed to store OTP in Redis: %w", err)
	}
	if err := s.redisClient.Set(ctx, attemptsKey, 0, s.config.TTL).Err(); err != nil {
		return nil, fmt.Errorf("failed to initialize attempts counter: %w", err)
	}
	if err := s.redisClient.Set(ctx, resendKey, 1, s.config.ResendWindow).Err(); err != nil {
		return nil, fmt.Errorf("failed to set resend throttle: %w", err)
	}

	return &domain.OTPRequest{
		Phone:     phone,
		Code:      code,
		UserID:    userID,
		ExpiresAt: time.Now().Add(s.config.TTL),
		Attempts:  0,
	}, nil
}

// alreadySent is the answer for a request that sent nothing because a valid code is already out.
func (s *OTPServiceImpl) alreadySent(ctx context.Context, otpKey, phone string, userID uint) *domain.OTPRequest {
	expires := time.Now().Add(s.config.TTL)
	if ttl, err := s.redisClient.TTL(ctx, otpKey).Result(); err == nil && ttl > 0 {
		expires = time.Now().Add(ttl)
	}
	return &domain.OTPRequest{Phone: phone, UserID: userID, ExpiresAt: expires, AlreadySent: true}
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
	if !otpMatches(s.digester, storedCode, otpKey, code) {
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
