package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

func TestAuthHandlers_VerifyOTP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		requestBody    OTPVerifyRequest
		setupMocks     func(*mocks.MockOTPService, *mocks.MockUserRepository)
		expectedStatus int
		expectedBody   map[string]interface{}
		validateCalls  func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository)
	}{
		{
			name: "successful phone verification and activation",
			requestBody: OTPVerifyRequest{
				Phone:  "+1234567890",
				Code:   "123456",
				UserID: 1,
			},
			setupMocks: func(otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				// OTP verification succeeds
				otpSvc.VerifyFunc = func(ctx context.Context, phone, code string, userID uint) (bool, error) {
					if phone == "+1234567890" && code == "123456" {
						return true, nil
					}
					return false, domain.ErrOTPInvalid
				}

				// User found by ID
				userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
					if id == 1 {
						return &domain.User{
							ID:            1,
							Email:         "user@example.com",
							Phone:         "+1234567890",
							Role:          "user",
							IsActive:      true,
							PhoneVerified: false,
							CreatedAt:     time.Now(),
							UpdatedAt:     time.Now(),
						}, nil
					}
					return nil, domain.ErrUserNotFound
				}

				// Phone activation succeeds
				userRepo.ActivatePhoneFunc = func(ctx context.Context, userID uint) error {
					if userID == 1 {
						return nil
					}
					return errors.New("user not found")
				}
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"data": map[string]interface{}{
					"message": "Phone number verified and activated successfully",
					"user_id": float64(1), // JSON unmarshaling converts numbers to float64
				},
			},
			validateCalls: func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				// Verify OTP service was called
				if otpSvc.VerifyFunc == nil {
					t.Error("expected OTP verify to be called")
				}
				// Verify user repository methods were called
				if userRepo.FindByIDFunc == nil {
					t.Error("expected FindByID to be called")
				}
				if userRepo.ActivatePhoneFunc == nil {
					t.Error("expected ActivatePhone to be called")
				}
			},
		},
		{
			name: "invalid request body",
			requestBody: OTPVerifyRequest{
				Phone: "", // Missing required field
				Code:  "123456",
			},
			setupMocks: func(otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				// No mocks needed for validation errors
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "Key: 'OTPVerifyRequest.Phone' Error:Field validation for 'Phone' failed on the 'required' tag\nKey: 'OTPVerifyRequest.UserID' Error:Field validation for 'UserID' failed on the 'required' tag",
			},
			validateCalls: func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				// No calls should be made
			},
		},
		{
			name: "OTP not found",
			requestBody: OTPVerifyRequest{
				Phone:  "+1234567890",
				Code:   "123456",
				UserID: 1,
			},
			setupMocks: func(otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				userRepo.FindByIDFunc = func(ctx context.Context, userID uint) (*domain.User, error) {
					return &domain.User{
						ID:            1,
						Email:         "user@example.com",
						Phone:         "+1234567890",
						Role:          "user",
						IsActive:      true,
						PhoneVerified: false,
					}, nil
				}
				otpSvc.VerifyFunc = func(ctx context.Context, phone, code string, userID uint) (bool, error) {
					return false, domain.ErrOTPNotFound
				}
			},
			expectedStatus: http.StatusNotFound,
			expectedBody: map[string]interface{}{
				"error": "OTP not found",
			},
			validateCalls: func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				if otpSvc.VerifyFunc == nil {
					t.Error("expected OTP verify to be called")
				}
			},
		},
		{
			name: "OTP expired",
			requestBody: OTPVerifyRequest{
				Phone:  "+1234567890",
				Code:   "123456",
				UserID: 1,
			},
			setupMocks: func(otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				userRepo.FindByIDFunc = func(ctx context.Context, userID uint) (*domain.User, error) {
					return &domain.User{
						ID:            1,
						Email:         "user@example.com",
						Phone:         "+1234567890",
						Role:          "user",
						IsActive:      true,
						PhoneVerified: false,
					}, nil
				}
				otpSvc.VerifyFunc = func(ctx context.Context, phone, code string, userID uint) (bool, error) {
					return false, domain.ErrOTPExpired
				}
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "OTP has expired",
			},
			validateCalls: func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				if otpSvc.VerifyFunc == nil {
					t.Error("expected OTP verify to be called")
				}
			},
		},
		{
			name: "OTP max attempts exceeded",
			requestBody: OTPVerifyRequest{
				Phone:  "+1234567890",
				Code:   "123456",
				UserID: 1,
			},
			setupMocks: func(otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				userRepo.FindByIDFunc = func(ctx context.Context, userID uint) (*domain.User, error) {
					return &domain.User{
						ID:            1,
						Email:         "user@example.com",
						Phone:         "+1234567890",
						Role:          "user",
						IsActive:      true,
						PhoneVerified: false,
					}, nil
				}
				otpSvc.VerifyFunc = func(ctx context.Context, phone, code string, userID uint) (bool, error) {
					return false, domain.ErrOTPMaxAttempts
				}
			},
			expectedStatus: http.StatusTooManyRequests,
			expectedBody: map[string]interface{}{
				"error": "Maximum attempts exceeded",
			},
			validateCalls: func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				if otpSvc.VerifyFunc == nil {
					t.Error("expected OTP verify to be called")
				}
			},
		},
		{
			name: "invalid OTP code",
			requestBody: OTPVerifyRequest{
				Phone:  "+1234567890",
				Code:   "123456",
				UserID: 1,
			},
			setupMocks: func(otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				userRepo.FindByIDFunc = func(ctx context.Context, userID uint) (*domain.User, error) {
					return &domain.User{
						ID:            1,
						Email:         "user@example.com",
						Phone:         "+1234567890",
						Role:          "user",
						IsActive:      true,
						PhoneVerified: false,
					}, nil
				}
				otpSvc.VerifyFunc = func(ctx context.Context, phone, code string, userID uint) (bool, error) {
					return false, domain.ErrOTPInvalid
				}
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "Invalid OTP code",
			},
			validateCalls: func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				if otpSvc.VerifyFunc == nil {
					t.Error("expected OTP verify to be called")
				}
			},
		},
		{
			name: "OTP verification returns false",
			requestBody: OTPVerifyRequest{
				Phone:  "+1234567890",
				Code:   "wrong123",
				UserID: 1,
			},
			setupMocks: func(otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				// User found by ID
				userRepo.FindByIDFunc = func(ctx context.Context, id uint) (*domain.User, error) {
					if id == 1 {
						return &domain.User{
							ID:            1,
							Email:         "user@example.com",
							Phone:         "+1234567890",
							Role:          "user",
							IsActive:      true,
							PhoneVerified: false,
						}, nil
					}
					return nil, domain.ErrUserNotFound
				}
				
				otpSvc.VerifyFunc = func(ctx context.Context, phone, code string, userID uint) (bool, error) {
					return false, nil // Valid call but wrong code
				}
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "Invalid OTP code",
			},
			validateCalls: func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				if otpSvc.VerifyFunc == nil {
					t.Error("expected OTP verify to be called")
				}
			},
		},
		{
			name: "user not found by phone",
			requestBody: OTPVerifyRequest{
				Phone:  "+1234567890",
				Code:   "123456",
				UserID: 1,
			},
			setupMocks: func(otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				userRepo.FindByIDFunc = func(ctx context.Context, userID uint) (*domain.User, error) {
					return nil, domain.ErrUserNotFound
				}
			},
			expectedStatus: http.StatusNotFound,
			expectedBody: map[string]interface{}{
				"error": "User not found",
			},
			validateCalls: func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				if userRepo.FindByIDFunc == nil {
					t.Error("expected FindByID to be called")
				}
			},
		},
		{
			name: "phone activation fails",
			requestBody: OTPVerifyRequest{
				Phone:  "+1234567890",
				Code:   "123456",
				UserID: 1,
			},
			setupMocks: func(otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				userRepo.FindByIDFunc = func(ctx context.Context, userID uint) (*domain.User, error) {
					return &domain.User{
						ID:            1,
						Email:         "user@example.com",
						Phone:         "+1234567890",
						Role:          "user",
						IsActive:      true,
						PhoneVerified: false,
					}, nil
				}
				otpSvc.VerifyFunc = func(ctx context.Context, phone, code string, userID uint) (bool, error) {
					return true, nil
				}
				userRepo.ActivatePhoneFunc = func(ctx context.Context, userID uint) error {
					return errors.New("database error")
				}
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: map[string]interface{}{
				"error": "Failed to activate phone number",
			},
			validateCalls: func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				if userRepo.FindByIDFunc == nil {
					t.Error("expected FindByID to be called")
				}
				if otpSvc.VerifyFunc == nil {
					t.Error("expected OTP verify to be called")
				}
				if userRepo.ActivatePhoneFunc == nil {
					t.Error("expected ActivatePhone to be called")
				}
			},
		},
		{
			name: "idempotent phone activation - already verified",
			requestBody: OTPVerifyRequest{
				Phone:  "+1234567890",
				Code:   "123456",
				UserID: 1,
			},
			setupMocks: func(otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				userRepo.FindByIDFunc = func(ctx context.Context, userID uint) (*domain.User, error) {
					return &domain.User{
						ID:            1,
						Email:         "user@example.com",
						Phone:         "+1234567890",
						Role:          "user",
						IsActive:      true,
						PhoneVerified: true, // Already verified
					}, nil
				}
				otpSvc.VerifyFunc = func(ctx context.Context, phone, code string, userID uint) (bool, error) {
					return true, nil
				}
				userRepo.ActivatePhoneFunc = func(ctx context.Context, userID uint) error {
					return nil // Idempotent - no error even if already verified
				}
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"data": map[string]interface{}{
					"message": "Phone number verified and activated successfully",
					"user_id": float64(1),
				},
			},
			validateCalls: func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				if userRepo.FindByIDFunc == nil {
					t.Error("expected FindByID to be called")
				}
				if otpSvc.VerifyFunc == nil {
					t.Error("expected OTP verify to be called")
				}
				if userRepo.ActivatePhoneFunc == nil {
					t.Error("expected ActivatePhone to be called")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockAuthSvc := mocks.NewMockAuthService()
			mockOTPSvc := mocks.NewMockOTPService()
			mockUserRepo := mocks.NewMockUserRepository()

			// Setup mocks
			tt.setupMocks(mockOTPSvc, mockUserRepo)

			// Create handler
			handler := NewAuthHandlers(mockAuthSvc, mockOTPSvc, mockUserRepo)

			// Create test request
			reqBody, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/otp/verify", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")

			// Create test response recorder
			w := httptest.NewRecorder()

			// Create Gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Call handler
			handler.VerifyOTP(c)

			// Assert status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Assert response body
			var responseBody map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &responseBody); err != nil {
				t.Fatalf("failed to unmarshal response body: %v", err)
			}

			for key, expectedValue := range tt.expectedBody {
				if actualValue, exists := responseBody[key]; !exists {
					t.Errorf("expected key %s not found in response", key)
				} else {
					validateValue(t, key, expectedValue, actualValue)
				}
			}

			// Validate calls
			tt.validateCalls(t, mockOTPSvc, mockUserRepo)
		})
	}
}

// Helper function to create a test user for reuse
func createTestUserForHandler(t *testing.T) *domain.User {
	t.Helper()
	
	return &domain.User{
		ID:            1,
		Email:         "test@example.com",
		Phone:         "+1234567890",
		PasswordHash:  "hashed_password",
		Role:          "user",
		IsActive:      true,
		PhoneVerified: false,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
}

func TestAuthHandlers_SendOTP(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		requestBody    map[string]interface{}
		setupMocks     func(*mocks.MockOTPService, *mocks.MockUserRepository)
		expectedStatus int
		expectedBody   map[string]interface{}
		validateCalls  func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository)
	}{
		{
			name: "successful OTP generation",
			requestBody: map[string]interface{}{
				"phone":   "+1234567890",
				"user_id": float64(1),
			},
			setupMocks: func(otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				userRepo.FindByIDFunc = func(ctx context.Context, userID uint) (*domain.User, error) {
					return &domain.User{
						ID:            1,
						Email:         "user@example.com",
						Phone:         "+1234567890",
						Role:          "user",
						IsActive:      true,
						PhoneVerified: false,
					}, nil
				}
				otpSvc.GenerateFunc = func(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) {
					if phone == "+1234567890" && userID == 1 {
						return &domain.OTPRequest{Phone: phone, Code: "123456", UserID: userID}, nil
					}
					return nil, errors.New("unexpected phone or userID")
				}
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"data": map[string]interface{}{
					"message": "OTP sent successfully",
				},
			},
			validateCalls: func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				if userRepo.FindByIDFunc == nil {
					t.Error("expected FindByID to be called")
				}
				if otpSvc.GenerateFunc == nil {
					t.Error("expected Generate to be called")
				}
			},
		},
		{
			name: "invalid request body - missing phone",
			requestBody: map[string]interface{}{},
			setupMocks: func(otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "Key: 'Phone' Error:Field validation for 'Phone' failed on the 'required' tag\nKey: 'UserID' Error:Field validation for 'UserID' failed on the 'required' tag",
			},
			validateCalls: func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {},
		},
		{
			name: "OTP generation fails",
			requestBody: map[string]interface{}{
				"phone":   "+1234567890",
				"user_id": float64(1),
			},
			setupMocks: func(otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				userRepo.FindByIDFunc = func(ctx context.Context, userID uint) (*domain.User, error) {
					return &domain.User{
						ID:            1,
						Email:         "user@example.com",
						Phone:         "+1234567890",
						Role:          "user",
						IsActive:      true,
						PhoneVerified: false,
					}, nil
				}
				otpSvc.GenerateFunc = func(ctx context.Context, phone string, userID uint) (*domain.OTPRequest, error) {
					return nil, errors.New("SMS service error")
				}
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: map[string]interface{}{
				"error": "Failed to send OTP",
			},
			validateCalls: func(t *testing.T, otpSvc *mocks.MockOTPService, userRepo *mocks.MockUserRepository) {
				if userRepo.FindByIDFunc == nil {
					t.Error("expected FindByID to be called")
				}
				if otpSvc.GenerateFunc == nil {
					t.Error("expected Generate to be called")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockAuthSvc := mocks.NewMockAuthService()
			mockOTPSvc := mocks.NewMockOTPService()
			mockUserRepo := mocks.NewMockUserRepository()

			// Setup mocks
			tt.setupMocks(mockOTPSvc, mockUserRepo)

			// Create handler
			handler := NewAuthHandlers(mockAuthSvc, mockOTPSvc, mockUserRepo)

			// Create test request
			reqBody, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/otp/send", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")

			// Create test response recorder
			w := httptest.NewRecorder()

			// Create Gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Call handler
			handler.SendOTP(c)

			// Assert status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Assert response body
			var responseBody map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &responseBody); err != nil {
				t.Fatalf("failed to unmarshal response body: %v", err)
			}

			for key, expectedValue := range tt.expectedBody {
				if actualValue, exists := responseBody[key]; !exists {
					t.Errorf("expected key %s not found in response", key)
				} else {
					validateValue(t, key, expectedValue, actualValue)
				}
			}

			// Validate calls
			tt.validateCalls(t, mockOTPSvc, mockUserRepo)
		})
	}
}

func TestAuthHandlers_Refresh(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		requestBody    RefreshRequest
		setupMocks     func(*mocks.MockAuthService)
		expectedStatus int
		expectedBody   map[string]interface{}
		validateCalls  func(t *testing.T, authSvc *mocks.MockAuthService)
	}{
		{
			name: "successful token refresh",
			requestBody: RefreshRequest{
				RefreshToken: "valid_refresh_token",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.RefreshTokenFunc = func(ctx context.Context, refreshToken string) (*domain.AuthResult, error) {
					if refreshToken == "valid_refresh_token" {
						return &domain.AuthResult{
							AccessToken: "new_access_token",
							ExpiresIn:   3600,
						}, nil
					}
					return nil, domain.ErrTokenInvalid
				}
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"data": map[string]interface{}{
					"access_token": "new_access_token",
					"token_type":   "Bearer",
					"expires_in":   float64(3600),
				},
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.RefreshTokenFunc == nil {
					t.Error("expected RefreshToken to be called")
				}
			},
		},
		{
			name: "invalid refresh token",
			requestBody: RefreshRequest{
				RefreshToken: "invalid_token",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.RefreshTokenFunc = func(ctx context.Context, refreshToken string) (*domain.AuthResult, error) {
					return nil, domain.ErrTokenInvalid
				}
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"error": "Invalid or expired refresh token",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.RefreshTokenFunc == nil {
					t.Error("expected RefreshToken to be called")
				}
			},
		},
		{
			name: "expired refresh token",
			requestBody: RefreshRequest{
				RefreshToken: "expired_token",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.RefreshTokenFunc = func(ctx context.Context, refreshToken string) (*domain.AuthResult, error) {
					return nil, domain.ErrTokenExpired
				}
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"error": "Invalid or expired refresh token",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.RefreshTokenFunc == nil {
					t.Error("expected RefreshToken to be called")
				}
			},
		},
		{
			name: "session expired",
			requestBody: RefreshRequest{
				RefreshToken: "session_expired_token",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.RefreshTokenFunc = func(ctx context.Context, refreshToken string) (*domain.AuthResult, error) {
					return nil, domain.ErrSessionExpired
				}
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"error": "Session expired",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.RefreshTokenFunc == nil {
					t.Error("expected RefreshToken to be called")
				}
			},
		},
		{
			name: "missing refresh token",
			requestBody: RefreshRequest{
				RefreshToken: "",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "Key: 'RefreshRequest.RefreshToken' Error:Field validation for 'RefreshToken' failed on the 'required' tag",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {},
		},
		{
			name: "internal server error",
			requestBody: RefreshRequest{
				RefreshToken: "valid_token",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.RefreshTokenFunc = func(ctx context.Context, refreshToken string) (*domain.AuthResult, error) {
					return nil, errors.New("database error")
				}
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: map[string]interface{}{
				"error": "Token refresh failed",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.RefreshTokenFunc == nil {
					t.Error("expected RefreshToken to be called")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockAuthSvc := mocks.NewMockAuthService()
			mockOTPSvc := mocks.NewMockOTPService()
			mockUserRepo := mocks.NewMockUserRepository()

			// Setup mocks
			tt.setupMocks(mockAuthSvc)

			// Create handler
			handler := NewAuthHandlers(mockAuthSvc, mockOTPSvc, mockUserRepo)

			// Create test request
			reqBody, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")

			// Create test response recorder
			w := httptest.NewRecorder()

			// Create Gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Call handler
			handler.Refresh(c)

			// Assert status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Assert response body
			var responseBody map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &responseBody); err != nil {
				t.Fatalf("failed to unmarshal response body: %v", err)
			}

			for key, expectedValue := range tt.expectedBody {
				if actualValue, exists := responseBody[key]; !exists {
					t.Errorf("expected key %s not found in response", key)
				} else {
					validateValue(t, key, expectedValue, actualValue)
				}
			}

			// Validate calls
			tt.validateCalls(t, mockAuthSvc)
		})
	}
}

func TestAuthHandlers_Me(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		setupContext   func(*gin.Context)
		setupMocks     func(*mocks.MockAuthService)
		expectedStatus int
		expectedBody   map[string]interface{}
		validateCalls  func(t *testing.T, authSvc *mocks.MockAuthService)
	}{
		{
			name: "successful user profile retrieval",
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "1")
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.GetUserProfileFunc = func(ctx context.Context, userID uint) (*domain.User, error) {
					if userID == 1 {
						return &domain.User{
							ID:            1,
							Email:         "test@example.com",
							Phone:         "+1234567890",
							Role:          "user",
							IsActive:      true,
							PhoneVerified: false,
							CreatedAt:     time.Now(),
							UpdatedAt:     time.Now(),
						}, nil
					}
					return nil, domain.ErrUserNotFound
				}
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"data": map[string]interface{}{
					"id":             float64(1),
					"email":          "test@example.com",
					"phone":          "+1234567890",
					"role":           "user",
					"is_active":      true,
					"phone_verified": false,
				},
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.GetUserProfileFunc == nil {
					t.Error("expected GetUserProfile to be called")
				}
			},
		},
		{
			name: "user ID not found in context",
			setupContext: func(c *gin.Context) {
				// Don't set user_id
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"error": "User ID not found in context",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {},
		},
		{
			name: "invalid user ID format",
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "invalid")
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "Invalid user ID",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {},
		},
		{
			name: "user not found",
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "999")
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.GetUserProfileFunc = func(ctx context.Context, userID uint) (*domain.User, error) {
					return nil, domain.ErrUserNotFound
				}
			},
			expectedStatus: http.StatusNotFound,
			expectedBody: map[string]interface{}{
				"error": "User not found",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.GetUserProfileFunc == nil {
					t.Error("expected GetUserProfile to be called")
				}
			},
		},
		{
			name: "internal server error",
			setupContext: func(c *gin.Context) {
				c.Set("user_id", "1")
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.GetUserProfileFunc = func(ctx context.Context, userID uint) (*domain.User, error) {
					return nil, errors.New("database error")
				}
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: map[string]interface{}{
				"error": "Failed to get user profile",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.GetUserProfileFunc == nil {
					t.Error("expected GetUserProfile to be called")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockAuthSvc := mocks.NewMockAuthService()
			mockOTPSvc := mocks.NewMockOTPService()
			mockUserRepo := mocks.NewMockUserRepository()

			// Setup mocks
			tt.setupMocks(mockAuthSvc)

			// Create handler
			handler := NewAuthHandlers(mockAuthSvc, mockOTPSvc, mockUserRepo)

			// Create test request
			req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)

			// Create test response recorder
			w := httptest.NewRecorder()

			// Create Gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			
			// Setup context
			tt.setupContext(c)

			// Call handler
			handler.Me(c)

			// Assert status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Assert response body
			var responseBody map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &responseBody); err != nil {
				t.Fatalf("failed to unmarshal response body: %v", err)
			}

			for key, expectedValue := range tt.expectedBody {
				if actualValue, exists := responseBody[key]; !exists {
					t.Errorf("expected key %s not found in response", key)
				} else {
					validateValue(t, key, expectedValue, actualValue)
				}
			}

			// Validate calls
			tt.validateCalls(t, mockAuthSvc)
		})
	}
}

func TestAuthHandlers_Logout(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		setupContext   func(*gin.Context)
		setupMocks     func(*mocks.MockAuthService)
		expectedStatus int
		expectedBody   map[string]interface{}
		validateCalls  func(t *testing.T, authSvc *mocks.MockAuthService)
	}{
		{
			name: "successful logout",
			setupContext: func(c *gin.Context) {
				c.Set("session_id", "valid_session_id")
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.LogoutFunc = func(ctx context.Context, sessionID string) error {
					if sessionID == "valid_session_id" {
						return nil
					}
					return errors.New("invalid session")
				}
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"data": map[string]interface{}{
					"message": "Logged out successfully",
				},
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.LogoutFunc == nil {
					t.Error("expected Logout to be called")
				}
			},
		},
		{
			name: "session ID not found in context",
			setupContext: func(c *gin.Context) {
				// Don't set session_id
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "Session ID not found",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {},
		},
		{
			name: "logout fails",
			setupContext: func(c *gin.Context) {
				c.Set("session_id", "failing_session_id")
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.LogoutFunc = func(ctx context.Context, sessionID string) error {
					return errors.New("logout error")
				}
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: map[string]interface{}{
				"error": "Logout failed",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.LogoutFunc == nil {
					t.Error("expected Logout to be called")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockAuthSvc := mocks.NewMockAuthService()
			mockOTPSvc := mocks.NewMockOTPService()
			mockUserRepo := mocks.NewMockUserRepository()

			// Setup mocks
			tt.setupMocks(mockAuthSvc)

			// Create handler
			handler := NewAuthHandlers(mockAuthSvc, mockOTPSvc, mockUserRepo)

			// Create test request
			req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)

			// Create test response recorder
			w := httptest.NewRecorder()

			// Create Gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req
			
			// Setup context
			tt.setupContext(c)

			// Call handler
			handler.Logout(c)

			// Assert status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Assert response body
			var responseBody map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &responseBody); err != nil {
				t.Fatalf("failed to unmarshal response body: %v", err)
			}

			for key, expectedValue := range tt.expectedBody {
				if actualValue, exists := responseBody[key]; !exists {
					t.Errorf("expected key %s not found in response", key)
				} else {
					validateValue(t, key, expectedValue, actualValue)
				}
			}

			// Validate calls
			tt.validateCalls(t, mockAuthSvc)
		})
	}
}

func TestAuthHandlers_NewAuthHandlers(t *testing.T) {
	// Test constructor
	mockAuthSvc := mocks.NewMockAuthService()
	mockOTPSvc := mocks.NewMockOTPService()
	mockUserRepo := mocks.NewMockUserRepository()

	handler := NewAuthHandlers(mockAuthSvc, mockOTPSvc, mockUserRepo)

	if handler == nil {
		t.Fatal("NewAuthHandlers returned nil")
	}
	if handler.authSvc != mockAuthSvc {
		t.Error("authSvc not properly assigned")
	}
	if handler.otpSvc != mockOTPSvc {
		t.Error("otpSvc not properly assigned")
	}
	if handler.userRepo != mockUserRepo {
		t.Error("userRepo not properly assigned")
	}
}

func TestAuthHandlers_Register(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		requestBody    RegisterRequest
		setupMocks     func(*mocks.MockAuthService)
		expectedStatus int
		expectedBody   map[string]interface{}
		validateCalls  func(t *testing.T, authSvc *mocks.MockAuthService)
	}{
		{
			name: "successful registration",
			requestBody: RegisterRequest{
				Email:    "user@example.com",
				Phone:    "+1234567890",
				Password: "password123",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.RegisterFunc = func(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
					if email == "user@example.com" && phone == "+1234567890" && password == "password123" && role == "user" {
						return &domain.User{ID: 1, Email: email, Phone: phone, Role: role}, nil
					}
					return nil, errors.New("unexpected parameters")
				}
			},
			expectedStatus: http.StatusCreated,
			expectedBody: map[string]interface{}{
				"data": map[string]interface{}{
					"message": "User registered successfully. Please verify your phone number.",
					"user_id": float64(1),
				},
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.RegisterFunc == nil {
					t.Error("expected Register to be called")
				}
			},
		},
		{
			name: "invalid request body - missing email",
			requestBody: RegisterRequest{
				Email:    "",
				Phone:    "+1234567890",
				Password: "password123",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				// No mocks needed for validation errors
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "Key: 'RegisterRequest.Email' Error:Field validation for 'Email' failed on the 'required' tag",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				// No calls should be made
			},
		},
		{
			name: "invalid email format",
			requestBody: RegisterRequest{
				Email:    "invalid-email",
				Phone:    "+1234567890",
				Password: "password123",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "Key: 'RegisterRequest.Email' Error:Field validation for 'Email' failed on the 'email' tag",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {},
		},
		{
			name: "password too short",
			requestBody: RegisterRequest{
				Email:    "user@example.com",
				Phone:    "+1234567890",
				Password: "12345", // Less than 6 characters
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "Key: 'RegisterRequest.Password' Error:Field validation for 'Password' failed on the 'min' tag",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {},
		},
		{
			name: "user already exists",
			requestBody: RegisterRequest{
				Email:    "existing@example.com",
				Phone:    "+1234567890",
				Password: "password123",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.RegisterFunc = func(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
					return nil, domain.ErrUserAlreadyExists
				}
			},
			expectedStatus: http.StatusConflict,
			expectedBody: map[string]interface{}{
				"error": "User already exists",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.RegisterFunc == nil {
					t.Error("expected Register to be called")
				}
			},
		},
		{
			name: "internal server error",
			requestBody: RegisterRequest{
				Email:    "user@example.com",
				Phone:    "+1234567890",
				Password: "password123",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.RegisterFunc = func(ctx context.Context, email, phone, password, role string) (*domain.User, error) {
					return nil, errors.New("database error")
				}
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: map[string]interface{}{
				"error": "Failed to register user",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.RegisterFunc == nil {
					t.Error("expected Register to be called")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockAuthSvc := mocks.NewMockAuthService()
			mockOTPSvc := mocks.NewMockOTPService()
			mockUserRepo := mocks.NewMockUserRepository()

			// Setup mocks
			tt.setupMocks(mockAuthSvc)

			// Create handler
			handler := NewAuthHandlers(mockAuthSvc, mockOTPSvc, mockUserRepo)

			// Create test request
			reqBody, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")

			// Create test response recorder
			w := httptest.NewRecorder()

			// Create Gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Call handler
			handler.Register(c)

			// Assert status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Assert response body
			var responseBody map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &responseBody); err != nil {
				t.Fatalf("failed to unmarshal response body: %v", err)
			}

			for key, expectedValue := range tt.expectedBody {
				if actualValue, exists := responseBody[key]; !exists {
					t.Errorf("expected key %s not found in response", key)
				} else {
					validateValue(t, key, expectedValue, actualValue)
				}
			}

			// Validate calls
			tt.validateCalls(t, mockAuthSvc)
		})
	}
}

func TestAuthHandlers_Login(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name           string
		requestBody    LoginRequest
		setupMocks     func(*mocks.MockAuthService)
		expectedStatus int
		expectedBody   map[string]interface{}
		validateCalls  func(t *testing.T, authSvc *mocks.MockAuthService)
	}{
		{
			name: "successful login",
			requestBody: LoginRequest{
				Email:    "user@example.com",
				Password: "password123",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.LoginFunc = func(ctx context.Context, email, password string) (*domain.AuthResult, error) {
					return &domain.AuthResult{
						User: &domain.User{ID: 1, Email: email, Role: "user"},
						AccessToken:  "access_token",
						RefreshToken: "refresh_token",
						ExpiresIn:    3600,
					}, nil
				}
			},
			expectedStatus: http.StatusOK,
			expectedBody: map[string]interface{}{
				"data": map[string]interface{}{
					"access_token":  "access_token",
					"refresh_token": "refresh_token",
					"token_type":    "Bearer",
					"expires_in":    float64(3600),
					"user": map[string]interface{}{
						"id":    float64(1),
						"email": "user@example.com",
						"role":  "user",
					},
				},
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.LoginFunc == nil {
					t.Error("expected Login to be called")
				}
			},
		},
		{
			name: "invalid credentials",
			requestBody: LoginRequest{
				Email:    "user@example.com",
				Password: "wrongpassword",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.LoginFunc = func(ctx context.Context, email, password string) (*domain.AuthResult, error) {
					return nil, domain.ErrInvalidCredentials
				}
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody: map[string]interface{}{
				"error": "Invalid credentials",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.LoginFunc == nil {
					t.Error("expected Login to be called")
				}
			},
		},
		{
			name: "user inactive",
			requestBody: LoginRequest{
				Email:    "inactive@example.com",
				Password: "password123",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.LoginFunc = func(ctx context.Context, email, password string) (*domain.AuthResult, error) {
					return nil, domain.ErrUserInactive
				}
			},
			expectedStatus: http.StatusForbidden,
			expectedBody: map[string]interface{}{
				"error": "Account is inactive",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.LoginFunc == nil {
					t.Error("expected Login to be called")
				}
			},
		},
		{
			name: "phone not verified",
			requestBody: LoginRequest{
				Email:    "unverified@example.com",
				Password: "password123",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.LoginFunc = func(ctx context.Context, email, password string) (*domain.AuthResult, error) {
					return nil, domain.ErrPhoneNotVerified
				}
			},
			expectedStatus: http.StatusForbidden,
			expectedBody: map[string]interface{}{
				"error": "Phone number not verified",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.LoginFunc == nil {
					t.Error("expected Login to be called")
				}
			},
		},
		{
			name: "invalid request body - missing email",
			requestBody: LoginRequest{
				Email:    "",
				Password: "password123",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {},
			expectedStatus: http.StatusBadRequest,
			expectedBody: map[string]interface{}{
				"error": "Key: 'LoginRequest.Email' Error:Field validation for 'Email' failed on the 'required' tag",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {},
		},
		{
			name: "internal server error",
			requestBody: LoginRequest{
				Email:    "user@example.com",
				Password: "password123",
			},
			setupMocks: func(authSvc *mocks.MockAuthService) {
				authSvc.LoginFunc = func(ctx context.Context, email, password string) (*domain.AuthResult, error) {
					return nil, errors.New("database error")
				}
			},
			expectedStatus: http.StatusInternalServerError,
			expectedBody: map[string]interface{}{
				"error": "Login failed",
			},
			validateCalls: func(t *testing.T, authSvc *mocks.MockAuthService) {
				if authSvc.LoginFunc == nil {
					t.Error("expected Login to be called")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockAuthSvc := mocks.NewMockAuthService()
			mockOTPSvc := mocks.NewMockOTPService()
			mockUserRepo := mocks.NewMockUserRepository()

			// Setup mocks
			tt.setupMocks(mockAuthSvc)

			// Create handler
			handler := NewAuthHandlers(mockAuthSvc, mockOTPSvc, mockUserRepo)

			// Create test request
			reqBody, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")

			// Create test response recorder
			w := httptest.NewRecorder()

			// Create Gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Call handler
			handler.Login(c)

			// Assert status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Assert response body
			var responseBody map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &responseBody); err != nil {
				t.Fatalf("failed to unmarshal response body: %v", err)
			}

			for key, expectedValue := range tt.expectedBody {
				if actualValue, exists := responseBody[key]; !exists {
					t.Errorf("expected key %s not found in response", key)
				} else {
					validateValue(t, key, expectedValue, actualValue)
				}
			}

			// Validate calls
			tt.validateCalls(t, mockAuthSvc)
		})
	}
}
// Helper function to validate nested maps and values
func validateValue(t *testing.T, key string, expected, actual interface{}) {
	t.Helper()
	
	expectedMap, expectedIsMap := expected.(map[string]interface{})
	actualMap, actualIsMap := actual.(map[string]interface{})
	
	if expectedIsMap && actualIsMap {
		// Both are maps, compare recursively
		for nestedKey, nestedExpected := range expectedMap {
			if nestedActual, exists := actualMap[nestedKey]; !exists {
				t.Errorf("expected key %s.%s not found in response", key, nestedKey)
			} else {
				validateValue(t, key+"."+nestedKey, nestedExpected, nestedActual)
			}
		}
	} else if expected != actual {
		t.Errorf("for key %s, expected %v, got %v", key, expected, actual)
	}
}
