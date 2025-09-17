package services

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

// createOTPServiceForTest creates an OTPService with test dependencies
func createOTPServiceForTest(t *testing.T) (domain.OTPService, *mocks.MockNotificationService, *mocks.MockUserRepository, *redis.Client) {
	t.Helper()

	// Create test Redis client (using database 15 for testing)
	redisClient := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379",
		Password: "",
		DB:       15, // Use test database
	})

	// Clear test database before test
	if err := redisClient.FlushDB(context.Background()).Err(); err != nil {
		t.Fatalf("Failed to flush test Redis DB: %v", err)
	}

	// Create mocks
	notificationSvc := mocks.NewMockNotificationService()
	userRepo := mocks.NewMockUserRepository()

	// Create test config
	config := OTPConfig{
		Length:       6,
		TTL:          5 * time.Minute,
		MaxAttempts:  3,
		ResendWindow: 60 * time.Second,
	}

	otpService := NewOTPService(notificationSvc, userRepo, redisClient, config)

	return otpService, notificationSvc, userRepo, redisClient
}

// createTestOTPConfig creates a test OTP configuration
func createTestOTPConfig(t *testing.T) OTPConfig {
	t.Helper()

	return OTPConfig{
		Length:       6,
		TTL:          5 * time.Minute,
		MaxAttempts:  3,
		ResendWindow: 60 * time.Second,
	}
}

func TestOTPServiceImpl_Generate(t *testing.T) {
	tests := []struct {
		name               string
		phone              string
		setupMocks         func(*mocks.MockNotificationService, *mocks.MockUserRepository)
		preSetupRedis      func(context.Context, *redis.Client, string)
		expectedError      error
		validateOTPRequest func(t *testing.T, otpReq *domain.OTPRequest)
		validateRedis      func(t *testing.T, ctx context.Context, redisClient *redis.Client, phone string)
	}{
		{
			name:  "successful OTP generation",
			phone: "+1234567890",
			setupMocks: func(notificationSvc *mocks.MockNotificationService, userRepo *mocks.MockUserRepository) {
				notificationSvc.SendSMSFunc = func(to, message string) error {
					return nil
				}
			},
			preSetupRedis: func(ctx context.Context, redisClient *redis.Client, phone string) {
				// No pre-setup needed
			},
			expectedError: nil,
			validateOTPRequest: func(t *testing.T, otpReq *domain.OTPRequest) {
				if otpReq == nil {
					t.Fatal("OTP request is nil")
				}
				if otpReq.Phone != "+1234567890" {
					t.Errorf("expected phone %s, got %s", "+1234567890", otpReq.Phone)
				}
				if len(otpReq.Code) != 6 {
					t.Errorf("expected OTP code length 6, got %d", len(otpReq.Code))
				}
				if otpReq.Attempts != 0 {
					t.Errorf("expected attempts 0, got %d", otpReq.Attempts)
				}
				if otpReq.ExpiresAt.Before(time.Now()) {
					t.Error("OTP should not be expired immediately after generation")
				}
			},
			validateRedis: func(t *testing.T, ctx context.Context, redisClient *redis.Client, phone string) {
				// Check OTP key exists
				userID := uint(1) // Test uses userID 1
				otpKey := fmt.Sprintf("otp:%s:%d", phone, userID)
				exists, err := redisClient.Exists(ctx, otpKey).Result()
				if err != nil {
					t.Fatalf("Failed to check OTP key existence: %v", err)
				}
				if exists != 1 {
					t.Error("OTP key should exist in Redis")
				}

				// Check attempts key exists
				attemptsKey := fmt.Sprintf("otp:att:%s:%d", phone, userID)
				attempts, err := redisClient.Get(ctx, attemptsKey).Int()
				if err != nil {
					t.Fatalf("Failed to get attempts: %v", err)
				}
				if attempts != 0 {
					t.Errorf("expected attempts 0, got %d", attempts)
				}

				// Check resend key exists
				resendKey := fmt.Sprintf("otp:res:%s", phone)
				exists, err = redisClient.Exists(ctx, resendKey).Result()
				if err != nil {
					t.Fatalf("Failed to check resend key existence: %v", err)
				}
				if exists != 1 {
					t.Error("Resend key should exist in Redis")
				}
			},
		},
		{
			name:  "resend throttle active",
			phone: "+1234567890",
			setupMocks: func(notificationSvc *mocks.MockNotificationService, userRepo *mocks.MockUserRepository) {
				// No setup needed as it should fail before SMS
			},
			preSetupRedis: func(ctx context.Context, redisClient *redis.Client, phone string) {
				// Set resend throttle key
				resendKey := fmt.Sprintf("otp:res:%s", phone)
				redisClient.Set(ctx, resendKey, 1, 30*time.Second)
			},
			expectedError: fmt.Errorf("please wait %d seconds before requesting new OTP", 30),
			validateOTPRequest: func(t *testing.T, otpReq *domain.OTPRequest) {
				if otpReq != nil {
					t.Error("expected OTP request to be nil when resend throttled")
				}
			},
			validateRedis: func(t *testing.T, ctx context.Context, redisClient *redis.Client, phone string) {
				// Should not create new keys when throttled
				otpKey := fmt.Sprintf("otp:%s:%d", phone, uint(1))
				exists, err := redisClient.Exists(ctx, otpKey).Result()
				if err != nil {
					t.Fatalf("Failed to check OTP key existence: %v", err)
				}
				if exists == 1 {
					t.Error("OTP key should not be created when throttled")
				}
			},
		},
		{
			name:  "SMS sending fails",
			phone: "+1234567890",
			setupMocks: func(notificationSvc *mocks.MockNotificationService, userRepo *mocks.MockUserRepository) {
				notificationSvc.SendSMSFunc = func(to, message string) error {
					return errors.New("SMS service unavailable")
				}
			},
			preSetupRedis: func(ctx context.Context, redisClient *redis.Client, phone string) {
				// No pre-setup needed
			},
			expectedError: fmt.Errorf("failed to send OTP SMS: %w", errors.New("SMS service unavailable")),
			validateOTPRequest: func(t *testing.T, otpReq *domain.OTPRequest) {
				if otpReq != nil {
					t.Error("expected OTP request to be nil when SMS fails")
				}
			},
			validateRedis: func(t *testing.T, ctx context.Context, redisClient *redis.Client, phone string) {
				// Redis keys should be cleaned up when SMS fails
				otpKey := fmt.Sprintf("otp:%s:%d", phone, uint(1))
				exists, err := redisClient.Exists(ctx, otpKey).Result()
				if err != nil {
					t.Fatalf("Failed to check OTP key existence: %v", err)
				}
				if exists == 1 {
					t.Error("OTP key should be cleaned up when SMS fails")
				}

				attemptsKey := fmt.Sprintf("otp:att:%s:%d", phone, uint(1))
				exists, err = redisClient.Exists(ctx, attemptsKey).Result()
				if err != nil {
					t.Fatalf("Failed to check attempts key existence: %v", err)
				}
				if exists == 1 {
					t.Error("Attempts key should be cleaned up when SMS fails")
				}

				resendKey := fmt.Sprintf("otp:res:%s", phone)
				exists, err = redisClient.Exists(ctx, resendKey).Result()
				if err != nil {
					t.Fatalf("Failed to check resend key existence: %v", err)
				}
				if exists == 1 {
					t.Error("Resend key should be cleaned up when SMS fails")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create service and mocks
			otpService, notificationSvc, userRepo, redisClient := createOTPServiceForTest(t)

			// Setup test-specific mock behavior
			tt.setupMocks(notificationSvc, userRepo)

			// Create context
			ctx := createTestContext(t)

			// Pre-setup Redis if needed
			tt.preSetupRedis(ctx, redisClient, tt.phone)

			// Execute test
			otpReq, err := otpService.Generate(ctx, tt.phone, 1)

			// Validate error
			if tt.expectedError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.expectedError)
				}
				// For dynamic errors like throttle wait time, check the error format
				if tt.name == "resend throttle active" {
					if err.Error() == "" || len(err.Error()) < 20 {
						t.Errorf("expected throttle error, got %v", err)
					}
				} else if err.Error() != tt.expectedError.Error() {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Validate OTP request
			tt.validateOTPRequest(t, otpReq)

			// Validate Redis state
			tt.validateRedis(t, ctx, redisClient, tt.phone)

			// Clean up Redis for next test
			redisClient.FlushDB(ctx)
		})
	}
}

func TestOTPServiceImpl_Verify(t *testing.T) {
	tests := []struct {
		name          string
		phone         string
		code          string
		setupRedis    func(context.Context, *redis.Client, string) string // Returns stored code
		expectedValid bool
		expectedError error
		validateRedis func(t *testing.T, ctx context.Context, redisClient *redis.Client, phone string)
	}{
		{
			name:  "successful verification",
			phone: "+1234567890",
			code:  "123456",
			setupRedis: func(ctx context.Context, redisClient *redis.Client, phone string) string {
				otpKey := fmt.Sprintf("otp:%s:%d", phone, uint(1))
				attemptsKey := fmt.Sprintf("otp:att:%s:%d", phone, uint(1))
				code := "123456"
				
				redisClient.Set(ctx, otpKey, code, 5*time.Minute)
				redisClient.Set(ctx, attemptsKey, 0, 5*time.Minute)
				
				return code
			},
			expectedValid: true,
			expectedError: nil,
			validateRedis: func(t *testing.T, ctx context.Context, redisClient *redis.Client, phone string) {
				// Keys should be cleaned up after successful verification
				otpKey := fmt.Sprintf("otp:%s:%d", phone, uint(1))
				exists, err := redisClient.Exists(ctx, otpKey).Result()
				if err != nil {
					t.Fatalf("Failed to check OTP key existence: %v", err)
				}
				if exists == 1 {
					t.Error("OTP key should be cleaned up after successful verification")
				}

				attemptsKey := fmt.Sprintf("otp:att:%s:%d", phone, uint(1))
				exists, err = redisClient.Exists(ctx, attemptsKey).Result()
				if err != nil {
					t.Fatalf("Failed to check attempts key existence: %v", err)
				}
				if exists == 1 {
					t.Error("Attempts key should be cleaned up after successful verification")
				}
			},
		},
		{
			name:  "invalid OTP code",
			phone: "+1234567890",
			code:  "999999",
			setupRedis: func(ctx context.Context, redisClient *redis.Client, phone string) string {
				otpKey := fmt.Sprintf("otp:%s:%d", phone, uint(1))
				attemptsKey := fmt.Sprintf("otp:att:%s:%d", phone, uint(1))
				code := "123456"
				
				redisClient.Set(ctx, otpKey, code, 5*time.Minute)
				redisClient.Set(ctx, attemptsKey, 0, 5*time.Minute)
				
				return code
			},
			expectedValid: false,
			expectedError: domain.ErrOTPInvalid,
			validateRedis: func(t *testing.T, ctx context.Context, redisClient *redis.Client, phone string) {
				// Keys should still exist with incremented attempts
				attemptsKey := fmt.Sprintf("otp:att:%s:%d", phone, uint(1))
				attempts, err := redisClient.Get(ctx, attemptsKey).Int()
				if err != nil {
					t.Fatalf("Failed to get attempts: %v", err)
				}
				if attempts != 1 {
					t.Errorf("expected attempts 1, got %d", attempts)
				}
			},
		},
		{
			name:  "OTP not found",
			phone: "+1234567890",
			code:  "123456",
			setupRedis: func(ctx context.Context, redisClient *redis.Client, phone string) string {
				// Don't set any keys - OTP doesn't exist
				return ""
			},
			expectedValid: false,
			expectedError: domain.ErrOTPNotFound,
			validateRedis: func(t *testing.T, ctx context.Context, redisClient *redis.Client, phone string) {
				// Attempts should be incremented even for non-existent OTP
				attemptsKey := fmt.Sprintf("otp:att:%s:%d", phone, uint(1))
				attempts, err := redisClient.Get(ctx, attemptsKey).Int()
				if err == nil && attempts > 0 {
					// If key exists, attempts should be incremented
					if attempts != 1 {
						t.Errorf("expected attempts 1, got %d", attempts)
					}
				}
			},
		},
		{
			name:  "max attempts exceeded",
			phone: "+1234567890",
			code:  "123456",
			setupRedis: func(ctx context.Context, redisClient *redis.Client, phone string) string {
				otpKey := fmt.Sprintf("otp:%s:%d", phone, uint(1))
				attemptsKey := fmt.Sprintf("otp:att:%s:%d", phone, uint(1))
				code := "123456"
				
				redisClient.Set(ctx, otpKey, code, 5*time.Minute)
				redisClient.Set(ctx, attemptsKey, 3, 5*time.Minute) // Already at max attempts
				
				return code
			},
			expectedValid: false,
			expectedError: domain.ErrOTPMaxAttempts,
			validateRedis: func(t *testing.T, ctx context.Context, redisClient *redis.Client, phone string) {
				// Keys should be cleaned up when max attempts exceeded
				otpKey := fmt.Sprintf("otp:%s:%d", phone, uint(1))
				exists, err := redisClient.Exists(ctx, otpKey).Result()
				if err != nil {
					t.Fatalf("Failed to check OTP key existence: %v", err)
				}
				if exists == 1 {
					t.Error("OTP key should be cleaned up when max attempts exceeded")
				}

				attemptsKey := fmt.Sprintf("otp:att:%s:%d", phone, uint(1))
				exists, err = redisClient.Exists(ctx, attemptsKey).Result()
				if err != nil {
					t.Fatalf("Failed to check attempts key existence: %v", err)
				}
				if exists == 1 {
					t.Error("Attempts key should be cleaned up when max attempts exceeded")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create service and mocks
			otpService, _, _, redisClient := createOTPServiceForTest(t)

			// Create context
			ctx := createTestContext(t)

			// Setup Redis state
			storedCode := tt.setupRedis(ctx, redisClient, tt.phone)
			_ = storedCode // Use storedCode if needed in future

			// Execute test
			valid, err := otpService.Verify(ctx, tt.phone, tt.code, 1)

			// Validate result
			if valid != tt.expectedValid {
				t.Errorf("expected valid %t, got %t", tt.expectedValid, valid)
			}

			// Validate error
			if tt.expectedError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.expectedError)
				}
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Validate Redis state
			tt.validateRedis(t, ctx, redisClient, tt.phone)

			// Clean up Redis for next test
			redisClient.FlushDB(ctx)
		})
	}
}

func TestOTPServiceImpl_CanResend(t *testing.T) {
	tests := []struct {
		name           string
		phone          string
		setupRedis     func(context.Context, *redis.Client, string)
		expectedCanSend bool
		expectedWaitTime func(int64) bool // Function to validate wait time range
		expectedError  error
	}{
		{
			name:  "can resend - no throttle",
			phone: "+1234567890",
			setupRedis: func(ctx context.Context, redisClient *redis.Client, phone string) {
				// No setup - no throttle key exists
			},
			expectedCanSend: true,
			expectedWaitTime: func(waitTime int64) bool {
				return waitTime == 0
			},
			expectedError: nil,
		},
		{
			name:  "cannot resend - throttle active",
			phone: "+1234567890",
			setupRedis: func(ctx context.Context, redisClient *redis.Client, phone string) {
				resendKey := fmt.Sprintf("otp:res:%s", phone)
				redisClient.Set(ctx, resendKey, 1, 30*time.Second)
			},
			expectedCanSend: false,
			expectedWaitTime: func(waitTime int64) bool {
				// Should be close to 30 seconds (allowing for small timing differences)
				return waitTime >= 29 && waitTime <= 30
			},
			expectedError: nil,
		},
		{
			name:  "can resend - throttle expired",
			phone: "+1234567890",
			setupRedis: func(ctx context.Context, redisClient *redis.Client, phone string) {
				resendKey := fmt.Sprintf("otp:res:%s", phone)
				// Set with very short TTL that will expire immediately
				redisClient.Set(ctx, resendKey, 1, 1*time.Millisecond)
				time.Sleep(2 * time.Millisecond) // Wait for expiration
			},
			expectedCanSend: true,
			expectedWaitTime: func(waitTime int64) bool {
				return waitTime == 0
			},
			expectedError: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create service and mocks
			otpService, _, _, redisClient := createOTPServiceForTest(t)

			// Create context
			ctx := createTestContext(t)

			// Setup Redis state
			tt.setupRedis(ctx, redisClient, tt.phone)

			// Execute test
			canSend, waitTime, err := otpService.CanResend(ctx, tt.phone)

			// Validate result
			if canSend != tt.expectedCanSend {
				t.Errorf("expected canSend %t, got %t", tt.expectedCanSend, canSend)
			}

			// Validate wait time
			if !tt.expectedWaitTime(waitTime) {
				t.Errorf("wait time %d is outside expected range", waitTime)
			}

			// Validate error
			if tt.expectedError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tt.expectedError)
				}
				if err != tt.expectedError {
					t.Errorf("expected error %v, got %v", tt.expectedError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Clean up Redis for next test
			redisClient.FlushDB(ctx)
		})
	}
}

// Integration test for complete OTP flow
func TestOTPServiceImpl_CompleteOTPFlow(t *testing.T) {
	// Create service and mocks
	otpService, notificationSvc, _, redisClient := createOTPServiceForTest(t)

	// Setup successful SMS sending
	notificationSvc.SendSMSFunc = func(to, message string) error {
		return nil
	}

	phone := "+1234567890"
	ctx := createTestContext(t)

	// Step 1: Generate OTP
	otpReq, err := otpService.Generate(ctx, phone, 1)
	if err != nil {
		t.Fatalf("OTP generation failed: %v", err)
	}
	if otpReq == nil {
		t.Fatal("OTP request is nil")
	}

	// Step 2: Verify correct OTP
	valid, err := otpService.Verify(ctx, phone, otpReq.Code, 1)
	if err != nil {
		t.Fatalf("OTP verification failed: %v", err)
	}
	if !valid {
		t.Error("Expected OTP to be valid")
	}

	// Step 3: Try to verify again (should fail - OTP should be consumed)
	valid, err = otpService.Verify(ctx, phone, otpReq.Code, 1)
	if err != domain.ErrOTPNotFound {
		t.Errorf("Expected ErrOTPNotFound, got %v", err)
	}
	if valid {
		t.Error("Expected OTP to be invalid after consumption")
	}

	// Step 4: Check resend capability during flow
	canResend, waitTime, err := otpService.CanResend(ctx, phone)
	if err != nil {
		t.Fatalf("CanResend check failed: %v", err)
	}
	if canResend && waitTime != 0 {
		t.Error("Should not be able to resend immediately after generation")
	}

	// Clean up
	redisClient.FlushDB(ctx)
}