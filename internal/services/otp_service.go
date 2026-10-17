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

// providerVerifier is implemented by the budgeted notifier when codes go through a provider that
// generates and checks them (Twilio Verify).
type providerVerifier interface {
	UsesProviderVerification(phone string) bool
	StartVerification(ctx context.Context, phone string) error
	CheckVerification(ctx context.Context, phone, code string) (bool, error)
}

// phoneChecker refuses a phone that must not be sent a code (not a mobile) before anything is sent.
type phoneChecker interface {
	CheckPhone(phone string) error
}

// verifyPendingMarker is stored under the OTP key while the provider holds the code. It is not a
// digest and a typed code is never compared with it.
const verifyPendingMarker = "provider-verify"

func (s *OTPServiceImpl) providerFor(phone string) (providerVerifier, bool) {
	if pv, ok := s.notificationSvc.(providerVerifier); ok && pv.UsesProviderVerification(phone) {
		return pv, true
	}
	return nil, false
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
	if pc, ok := s.notificationSvc.(phoneChecker); ok {
		if err := pc.CheckPhone(phone); err != nil {
			return nil, err
		}
	}
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

	// With the provider (Twilio Verify) it generates, sends and checks the code: nothing is generated
	// or kept here except a marker that carries the same expiry, attempts and resend rules.
	provider, viaProvider := s.providerFor(phone)
	code := ""
	var sendErr error
	if viaProvider {
		sendErr = provider.StartVerification(ctx, phone)
	} else {
		var err error
		code, err = s.generateSecureCode()
		if err != nil {
			return nil, fmt.Errorf("failed to generate OTP code: %w", err)
		}
		// Send SMS notification (the budget is consulted inside the notifier)
		sendErr = s.sendSMS(ctx, phone, OTPMessage(s.config.Brand, domain.OTPPurposeFrom(ctx), code, s.config.TTL))
	}
	if err := sendErr; err != nil {
		var limit *domain.SMSLimitError
		if validCodeOut == 1 && (errors.As(err, &limit) || errors.Is(err, domain.ErrSMSUnavailable)) {
			log.Printf("OTP resend for user %d not sent, valid code still out: %v", userID, err)
			return s.alreadySent(ctx, otpKey, phone, userID), nil
		}
		return nil, fmt.Errorf("failed to send OTP SMS: %w", err)
	}

	// Store only the digest, reset attempts, start the resend window
	stored := verifyPendingMarker
	if !viaProvider {
		stored = s.digester.Digest(otpKey, code)
	}
	if err := s.redisClient.Set(ctx, otpKey, stored, s.config.TTL).Err(); err != nil {
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

// Verify implements domain.OTPService with Redis persistence: it checks the code and, when right,
// consumes it.
func (s *OTPServiceImpl) Verify(ctx context.Context, phone, code string, userID uint) (bool, error) {
	ok, err := s.VerifyKeep(ctx, phone, code, userID)
	if ok && err == nil {
		s.Consume(ctx, phone, userID)
	}
	return ok, err
}

// VerifyKeep is Verify without consuming a right code: attempts are counted and every error is the
// same, but a correct code stays valid until Consume. A flow that still has work to do after the code
// (checks, a database write) uses it so an internal failure does not burn a code that cost an SMS.
func (s *OTPServiceImpl) VerifyKeep(ctx context.Context, phone, code string, userID uint) (bool, error) {
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

	if storedCode == verifyPendingMarker {
		return s.checkWithProvider(ctx, otpKey, attemptsKey, phone, code)
	}

	// Verify code
	if !otpMatches(s.digester, storedCode, otpKey, code) {
		return false, domain.ErrOTPInvalid
	}
	return true, nil
}

// Consume removes the code and its attempts counter.
func (s *OTPServiceImpl) Consume(ctx context.Context, phone string, userID uint) {
	s.redisClient.Del(ctx,
		fmt.Sprintf("otp:%s:%d", phone, userID),
		fmt.Sprintf("otp:att:%s:%d", phone, userID))
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

// checkWithProvider asks the provider to check code. Our attempts counter and expiry already ran. An
// approved code is remembered as a digest (same expiry) so a flow that keeps the code can check it
// again without asking the provider, which accepts a code only once.
func (s *OTPServiceImpl) checkWithProvider(ctx context.Context, otpKey, attemptsKey, phone, code string) (bool, error) {
	provider, ok := s.providerFor(phone)
	if !ok {
		return false, domain.ErrOTPNotFound
	}
	if !isDigits(code) || len(code) < 4 || len(code) > 10 {
		return false, domain.ErrOTPInvalid
	}
	approved, err := provider.CheckVerification(ctx, phone, code)
	if err != nil {
		if errors.Is(err, domain.ErrOTPMaxAttempts) || errors.Is(err, domain.ErrOTPExpired) {
			s.redisClient.Del(ctx, otpKey, attemptsKey)
			return false, err
		}
		if errors.Is(err, domain.ErrOTPInvalid) {
			return false, err
		}
		return false, fmt.Errorf("failed to check OTP with provider: %w", err)
	}
	if !approved {
		return false, domain.ErrOTPInvalid
	}
	if err := s.redisClient.Set(ctx, otpKey, s.digester.Digest(otpKey, code), redis.KeepTTL).Err(); err != nil {
		log.Printf("Warning: failed to remember an approved code: %v", err)
	}
	return true, nil
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}
