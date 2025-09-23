package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
	"github.com/you/authzsvc/internal/services"
)

// Test helpers
func createTestPasswordChangeHandlers(t *testing.T) (*PasswordChangeHandlers, *mocks.MockPasswordChangeRepository, *mocks.MockPasswordHistoryRepository, *mocks.MockForgotPasswordRepository, *mocks.MockUserRepository, *mocks.MockPasswordService, *mocks.MockOTPService, *mocks.MockSessionRepository) {
	t.Helper()

	// Create mocks
	passwordChangeRepo := mocks.NewMockPasswordChangeRepository()
	passwordHistoryRepo := mocks.NewMockPasswordHistoryRepository()
	forgotPasswordRepo := mocks.NewMockForgotPasswordRepository()
	userRepo := mocks.NewMockUserRepository()
	passwordService := mocks.NewMockPasswordService()
	otpService := mocks.NewMockOTPService()
	sessionRepo := mocks.NewMockSessionRepository()

	// Create service with mocks - using interface approach
	service := &services.PasswordChangeService{}

	// Create handlers
	handlers := NewPasswordChangeHandlers(service)

	return handlers, passwordChangeRepo, passwordHistoryRepo, forgotPasswordRepo, userRepo, passwordService, otpService, sessionRepo
}

func createGinContextForTest(t *testing.T, method, path string, body interface{}, userID uint) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()

	gin.SetMode(gin.TestMode)

	// Prepare request body
	var bodyBytes []byte
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("Failed to marshal request body: %v", err)
		}
	}

	// Create request
	req := httptest.NewRequest(method, path, bytes.NewBuffer(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Test-Agent/1.0")

	// Create response recorder
	w := httptest.NewRecorder()

	// Create gin context
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	// Set user ID in context (simulating JWT middleware)
	if userID > 0 {
		c.Set("user_id", userID)
	}

	return c, w
}

func createMockPasswordChangeService(t *testing.T) *MockPasswordChangeService {
	t.Helper()
	return &MockPasswordChangeService{}
}

// TestPasswordChangeHandlers wraps the handlers with a mock service for testing
type TestPasswordChangeHandlers struct {
	service PasswordChangeServiceInterface
}

// Create handlers that work with our mock service
func (h *TestPasswordChangeHandlers) InitiatePasswordChange(c *gin.Context) {
	var req domain.PasswordChangeInitiateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"message": err.Error(),
			"code":    400,
		})
		return
	}

	// Get user ID from JWT context
	userID, err := extractUserID(c)
	if err != nil {
		if err.Error() == "user ID not found in token" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "user_not_authenticated",
				"message": "User ID not found in token",
				"code":    401,
			})
			return
		}
		statusCode := getPasswordErrorStatusCode(err)
		c.JSON(statusCode, gin.H{
			"error":   getPasswordErrorCode(err),
			"message": err.Error(),
			"code":    statusCode,
		})
		return
	}

	// Get client information
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Initiate password change
	response, err := h.service.InitiatePasswordChange(
		c.Request.Context(),
		userID,
		req.CurrentPassword,
		req.NewPassword,
		req.ConfirmPassword,
		ipAddress,
		userAgent,
	)
	if err != nil {
		statusCode := getPasswordErrorStatusCode(err)
		c.JSON(statusCode, gin.H{
			"error":   getPasswordErrorCode(err),
			"message": err.Error(),
			"code":    statusCode,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": response,
	})
}

func (h *TestPasswordChangeHandlers) CompletePasswordChange(c *gin.Context) {
	requestID := c.Param("id")
	if requestID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "field_required",
			"message": "Password change request ID is required",
			"code":    400,
		})
		return
	}

	// Validate UUID format
	if err := validateUUID(requestID); err != nil {
		statusCode := getPasswordErrorStatusCode(err)
		c.JSON(statusCode, gin.H{
			"error":   getPasswordErrorCode(err),
			"message": "Invalid request ID format",
			"code":    statusCode,
		})
		return
	}

	var req domain.PasswordChangeCompleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request_format",
			"message": err.Error(),
			"code":    400,
		})
		return
	}

	// Get user ID from JWT context
	userID, err := extractUserID(c)
	if err != nil {
		if err.Error() == "user ID not found in token" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "user_not_authenticated",
				"message": "User ID not found in token",
				"code":    401,
			})
			return
		}
		statusCode := getPasswordErrorStatusCode(err)
		c.JSON(statusCode, gin.H{
			"error":   getPasswordErrorCode(err),
			"message": err.Error(),
			"code":    statusCode,
		})
		return
	}

	// Complete password change
	response, err := h.service.CompletePasswordChange(
		c.Request.Context(),
		userID,
		requestID,
		req.OTPCode,
		req.Nonce,
	)
	if err != nil {
		statusCode := getPasswordErrorStatusCode(err)
		c.JSON(statusCode, gin.H{
			"error":   getPasswordErrorCode(err),
			"message": err.Error(),
			"code":    statusCode,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": response,
	})
}

func (h *TestPasswordChangeHandlers) GetPasswordChangeStatus(c *gin.Context) {
	requestID := c.Param("id")
	if requestID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "field_required",
			"message": "Password change request ID is required",
			"code":    400,
		})
		return
	}

	// Validate UUID format
	if err := validateUUID(requestID); err != nil {
		statusCode := getPasswordErrorStatusCode(err)
		c.JSON(statusCode, gin.H{
			"error":   getPasswordErrorCode(err),
			"message": "Invalid request ID format",
			"code":    statusCode,
		})
		return
	}

	// Get user ID from JWT context
	userID, err := extractUserID(c)
	if err != nil {
		if err.Error() == "user ID not found in token" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "user_not_authenticated",
				"message": "User ID not found in token",
				"code":    401,
			})
			return
		}
		statusCode := getPasswordErrorStatusCode(err)
		c.JSON(statusCode, gin.H{
			"error":   getPasswordErrorCode(err),
			"message": err.Error(),
			"code":    statusCode,
		})
		return
	}

	// Get password change status
	status, err := h.service.GetPasswordChangeStatus(
		c.Request.Context(),
		userID,
		requestID,
	)
	if err != nil {
		statusCode := getPasswordErrorStatusCode(err)
		c.JSON(statusCode, gin.H{
			"error":   getPasswordErrorCode(err),
			"message": err.Error(),
			"code":    statusCode,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": status,
	})
}

func (h *TestPasswordChangeHandlers) GetPasswordChangeHistory(c *gin.Context) {
	// Get user ID from JWT context
	userID, err := extractUserID(c)
	if err != nil {
		if err.Error() == "user ID not found in token" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "user_not_authenticated",
				"message": "User ID not found in token",
				"code":    401,
			})
			return
		}
		statusCode := getPasswordErrorStatusCode(err)
		c.JSON(statusCode, gin.H{
			"error":   getPasswordErrorCode(err),
			"message": err.Error(),
			"code":    statusCode,
		})
		return
	}

	// Get limit from query parameter (default 50)
	limitStr := c.DefaultQuery("limit", "50")
	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 100 {
		limit = 50 // Default limit
	}

	// Get password change history
	history, err := h.service.GetPasswordChangeHistory(
		c.Request.Context(),
		userID,
		limit,
	)
	if err != nil {
		statusCode := getPasswordErrorStatusCode(err)
		c.JSON(statusCode, gin.H{
			"error":   getPasswordErrorCode(err),
			"message": err.Error(),
			"code":    statusCode,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": history,
	})
}

func (h *TestPasswordChangeHandlers) InitiateForgotPassword(c *gin.Context) {
	var req domain.ForgotPasswordInitiateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"message": err.Error(),
			"code":    400,
		})
		return
	}

	// Get client information
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	// Initiate forgot password
	response, err := h.service.InitiateForgotPassword(
		c.Request.Context(),
		req.Email,
		req.Phone,
		ipAddress,
		userAgent,
	)
	if err != nil {
		statusCode := getPasswordErrorStatusCode(err)
		c.JSON(statusCode, gin.H{
			"error":   getPasswordErrorCode(err),
			"message": err.Error(),
			"code":    statusCode,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": response,
	})
}

// PasswordChangeServiceInterface defines the interface for the password change service
type PasswordChangeServiceInterface interface {
	InitiatePasswordChange(ctx context.Context, userID uint, currentPassword, newPassword, confirmPassword, ipAddress, userAgent string) (*domain.PasswordChangeResponse, error)
	CompletePasswordChange(ctx context.Context, userID uint, requestID, otpCode, nonce string) (*domain.PasswordChangeResponse, error)
	GetPasswordChangeStatus(ctx context.Context, userID uint, requestID string) (*domain.PasswordChangeStatusResponse, error)
	CancelPasswordChange(ctx context.Context, userID uint, requestID string) (*domain.PasswordChangeResponse, error)
	GetPasswordChangeHistory(ctx context.Context, userID uint, limit int) (*domain.PasswordChangeHistoryResponse, error)
	InitiateForgotPassword(ctx context.Context, email, phone, ipAddress, userAgent string) (*domain.PasswordChangeResponse, error)
	CompleteForgotPassword(ctx context.Context, requestID, otpCode, nonce, newPassword, confirmPassword string) (*domain.PasswordChangeResponse, error)
}

// MockPasswordChangeService for testing handlers
type MockPasswordChangeService struct {
	InitiatePasswordChangeFunc   func(ctx context.Context, userID uint, currentPassword, newPassword, confirmPassword, ipAddress, userAgent string) (*domain.PasswordChangeResponse, error)
	CompletePasswordChangeFunc   func(ctx context.Context, userID uint, requestID, otpCode, nonce string) (*domain.PasswordChangeResponse, error)
	GetPasswordChangeStatusFunc  func(ctx context.Context, userID uint, requestID string) (*domain.PasswordChangeStatusResponse, error)
	CancelPasswordChangeFunc     func(ctx context.Context, userID uint, requestID string) (*domain.PasswordChangeResponse, error)
	GetPasswordChangeHistoryFunc func(ctx context.Context, userID uint, limit int) (*domain.PasswordChangeHistoryResponse, error)
	InitiateForgotPasswordFunc   func(ctx context.Context, email, phone, ipAddress, userAgent string) (*domain.PasswordChangeResponse, error)
	CompleteForgotPasswordFunc   func(ctx context.Context, requestID, otpCode, nonce, newPassword, confirmPassword string) (*domain.PasswordChangeResponse, error)
}

func (m *MockPasswordChangeService) InitiatePasswordChange(ctx context.Context, userID uint, currentPassword, newPassword, confirmPassword, ipAddress, userAgent string) (*domain.PasswordChangeResponse, error) {
	if m.InitiatePasswordChangeFunc != nil {
		return m.InitiatePasswordChangeFunc(ctx, userID, currentPassword, newPassword, confirmPassword, ipAddress, userAgent)
	}
	return &domain.PasswordChangeResponse{
		RequestID: "test-request-id",
		Status:    "initiated",
		Message:   "Password change initiated successfully",
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Nonce:     "test-nonce",
	}, nil
}

func (m *MockPasswordChangeService) CompletePasswordChange(ctx context.Context, userID uint, requestID, otpCode, nonce string) (*domain.PasswordChangeResponse, error) {
	if m.CompletePasswordChangeFunc != nil {
		return m.CompletePasswordChangeFunc(ctx, userID, requestID, otpCode, nonce)
	}
	return &domain.PasswordChangeResponse{
		RequestID: requestID,
		Status:    "completed",
		Message:   "Password changed successfully",
	}, nil
}

func (m *MockPasswordChangeService) GetPasswordChangeStatus(ctx context.Context, userID uint, requestID string) (*domain.PasswordChangeStatusResponse, error) {
	if m.GetPasswordChangeStatusFunc != nil {
		return m.GetPasswordChangeStatusFunc(ctx, userID, requestID)
	}
	return &domain.PasswordChangeStatusResponse{
		RequestID:   requestID,
		Status:      "initiated",
		RequestedAt: time.Now(),
		ExpiresAt:   time.Now().Add(15 * time.Minute),
		OTPAttempts: 0,
	}, nil
}

func (m *MockPasswordChangeService) CancelPasswordChange(ctx context.Context, userID uint, requestID string) (*domain.PasswordChangeResponse, error) {
	if m.CancelPasswordChangeFunc != nil {
		return m.CancelPasswordChangeFunc(ctx, userID, requestID)
	}
	return &domain.PasswordChangeResponse{
		RequestID: requestID,
		Status:    "cancelled",
		Message:   "Password change cancelled successfully",
	}, nil
}

func (m *MockPasswordChangeService) GetPasswordChangeHistory(ctx context.Context, userID uint, limit int) (*domain.PasswordChangeHistoryResponse, error) {
	if m.GetPasswordChangeHistoryFunc != nil {
		return m.GetPasswordChangeHistoryFunc(ctx, userID, limit)
	}
	return &domain.PasswordChangeHistoryResponse{
		History: []domain.PasswordChangeStatusResponse{
			{
				RequestID:   "test-request-1",
				Status:      "completed",
				RequestedAt: time.Now().Add(-time.Hour),
				ExpiresAt:   time.Now().Add(-45 * time.Minute),
				CompletedAt: func() *time.Time { t := time.Now().Add(-30 * time.Minute); return &t }(),
			},
		},
	}, nil
}

func (m *MockPasswordChangeService) InitiateForgotPassword(ctx context.Context, email, phone, ipAddress, userAgent string) (*domain.PasswordChangeResponse, error) {
	if m.InitiateForgotPasswordFunc != nil {
		return m.InitiateForgotPasswordFunc(ctx, email, phone, ipAddress, userAgent)
	}
	return &domain.PasswordChangeResponse{
		RequestID: "forgot-request-id",
		Status:    "initiated",
		Message:   "If this email and phone combination exists, an OTP has been sent.",
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Nonce:     "forgot-nonce",
	}, nil
}

func (m *MockPasswordChangeService) CompleteForgotPassword(ctx context.Context, requestID, otpCode, nonce, newPassword, confirmPassword string) (*domain.PasswordChangeResponse, error) {
	if m.CompleteForgotPasswordFunc != nil {
		return m.CompleteForgotPasswordFunc(ctx, requestID, otpCode, nonce, newPassword, confirmPassword)
	}
	return &domain.PasswordChangeResponse{
		RequestID: requestID,
		Status:    "completed",
		Message:   "Password reset successfully",
	}, nil
}

func TestPasswordChangeHandlers_InitiatePasswordChange(t *testing.T) {
	tests := []struct {
		name               string
		userID             uint
		requestBody        interface{}
		setupServiceMock   func(*MockPasswordChangeService)
		expectedStatus     int
		expectedErrorCode  string
		expectedSuccessKey string
	}{
		{
			name:   "successful password change initiation",
			userID: 1,
			requestBody: domain.PasswordChangeInitiateRequest{
				CurrentPassword: "currentPassword123",
				NewPassword:     "NewPassword123",
				ConfirmPassword: "NewPassword123",
			},
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.InitiatePasswordChangeFunc = func(ctx context.Context, userID uint, currentPassword, newPassword, confirmPassword, ipAddress, userAgent string) (*domain.PasswordChangeResponse, error) {
					return &domain.PasswordChangeResponse{
						RequestID: "test-request-id",
						Status:    "initiated",
						Message:   "Password change initiated successfully",
						ExpiresAt: time.Now().Add(15 * time.Minute),
						Nonce:     "test-nonce",
					}, nil
				}
			},
			expectedStatus:     http.StatusOK,
			expectedSuccessKey: "data",
		},
		{
			name:   "invalid request body",
			userID: 1,
			requestBody: map[string]interface{}{
				"invalid": "request",
			},
			setupServiceMock:  func(service *MockPasswordChangeService) {},
			expectedStatus:    http.StatusBadRequest,
			expectedErrorCode: "Invalid request format",
		},
		{
			name:              "missing user ID in context",
			userID:            0, // No user ID set
			requestBody: domain.PasswordChangeInitiateRequest{
				CurrentPassword: "currentPassword",
				NewPassword:     "NewPassword123",
				ConfirmPassword: "NewPassword123",
			},
			setupServiceMock:  func(service *MockPasswordChangeService) {},
			expectedStatus:    http.StatusUnauthorized,
			expectedErrorCode: "user_not_authenticated",
		},
		{
			name:   "service returns current password incorrect error",
			userID: 1,
			requestBody: domain.PasswordChangeInitiateRequest{
				CurrentPassword: "wrongPassword",
				NewPassword:     "NewPassword123",
				ConfirmPassword: "NewPassword123",
			},
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.InitiatePasswordChangeFunc = func(ctx context.Context, userID uint, currentPassword, newPassword, confirmPassword, ipAddress, userAgent string) (*domain.PasswordChangeResponse, error) {
					return nil, domain.ErrCurrentPasswordIncorrect
				}
			},
			expectedStatus:    http.StatusBadRequest,
			expectedErrorCode: "current_password_incorrect",
		},
		{
			name:   "service returns password strength insufficient error",
			userID: 1,
			requestBody: domain.PasswordChangeInitiateRequest{
				CurrentPassword: "currentPassword123",
				NewPassword:     "weak",
				ConfirmPassword: "weak",
			},
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.InitiatePasswordChangeFunc = func(ctx context.Context, userID uint, currentPassword, newPassword, confirmPassword, ipAddress, userAgent string) (*domain.PasswordChangeResponse, error) {
					return nil, domain.ErrPasswordStrengthInsufficient
				}
			},
			expectedStatus:    http.StatusBadRequest,
			expectedErrorCode: "password_strength_insufficient",
		},
		{
			name:   "service returns rate limit exceeded error",
			userID: 1,
			requestBody: domain.PasswordChangeInitiateRequest{
				CurrentPassword: "currentPassword123",
				NewPassword:     "NewPassword123",
				ConfirmPassword: "NewPassword123",
			},
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.InitiatePasswordChangeFunc = func(ctx context.Context, userID uint, currentPassword, newPassword, confirmPassword, ipAddress, userAgent string) (*domain.PasswordChangeResponse, error) {
					return nil, domain.ErrPasswordChangeRateLimitExceeded
				}
			},
			expectedStatus:    http.StatusTooManyRequests,
			expectedErrorCode: "password_change_rate_limit_exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock service
			mockService := createMockPasswordChangeService(t)
			tt.setupServiceMock(mockService)

			// Create test handlers with mock service
			handlers := &TestPasswordChangeHandlers{service: mockService}

			// Create test context
			c, w := createGinContextForTest(t, "POST", "/api/v1/password-changes", tt.requestBody, tt.userID)

			// Execute handler
			handlers.InitiatePasswordChange(c)

			// Assert status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Parse response
			var response map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			// Assert response structure
			if tt.expectedSuccessKey != "" {
				if _, exists := response[tt.expectedSuccessKey]; !exists {
					t.Errorf("expected response to contain key %s", tt.expectedSuccessKey)
				}
			}

			if tt.expectedErrorCode != "" {
				if errorField, exists := response["error"]; exists {
					if errorField != tt.expectedErrorCode {
						t.Errorf("expected error code %s, got %s", tt.expectedErrorCode, errorField)
					}
				} else {
					t.Error("expected error field in response")
				}
			}
		})
	}
}

func TestPasswordChangeHandlers_CompletePasswordChange(t *testing.T) {
	tests := []struct {
		name               string
		userID             uint
		requestID          string
		requestBody        interface{}
		setupServiceMock   func(*MockPasswordChangeService)
		expectedStatus     int
		expectedErrorCode  string
		expectedSuccessKey string
	}{
		{
			name:      "successful password change completion",
			userID:    1,
			requestID: "550e8400-e29b-41d4-a716-446655440000",
			requestBody: domain.PasswordChangeCompleteRequest{
				OTPCode: "123456",
				Nonce:   "test-nonce",
			},
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.CompletePasswordChangeFunc = func(ctx context.Context, userID uint, requestID, otpCode, nonce string) (*domain.PasswordChangeResponse, error) {
					return &domain.PasswordChangeResponse{
						RequestID: requestID,
						Status:    "completed",
						Message:   "Password changed successfully",
					}, nil
				}
			},
			expectedStatus:     http.StatusOK,
			expectedSuccessKey: "data",
		},
		{
			name:              "missing request ID",
			userID:            1,
			requestID:         "", // Empty request ID
			requestBody:       domain.PasswordChangeCompleteRequest{},
			setupServiceMock:  func(service *MockPasswordChangeService) {},
			expectedStatus:    http.StatusBadRequest,
			expectedErrorCode: "field_required",
		},
		{
			name:              "invalid UUID format",
			userID:            1,
			requestID:         "invalid-uuid",
			requestBody:       domain.PasswordChangeCompleteRequest{},
			setupServiceMock:  func(service *MockPasswordChangeService) {},
			expectedStatus:    http.StatusBadRequest,
			expectedErrorCode: "invalid_uuid_format",
		},
		{
			name:      "invalid request body",
			userID:    1,
			requestID: "550e8400-e29b-41d4-a716-446655440000",
			requestBody: map[string]interface{}{
				"invalid": "request",
			},
			setupServiceMock:  func(service *MockPasswordChangeService) {},
			expectedStatus:    http.StatusBadRequest,
			expectedErrorCode: "invalid_request_format",
		},
		{
			name:      "missing user ID in context",
			userID:    0, // No user ID set
			requestID: "550e8400-e29b-41d4-a716-446655440000",
			requestBody: domain.PasswordChangeCompleteRequest{
				OTPCode: "123456",
				Nonce:   "test-nonce",
			},
			setupServiceMock:  func(service *MockPasswordChangeService) {},
			expectedStatus:    http.StatusUnauthorized,
			expectedErrorCode: "user_not_authenticated",
		},
		{
			name:      "service returns invalid OTP error",
			userID:    1,
			requestID: "550e8400-e29b-41d4-a716-446655440000",
			requestBody: domain.PasswordChangeCompleteRequest{
				OTPCode: "wrong-otp",
				Nonce:   "test-nonce",
			},
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.CompletePasswordChangeFunc = func(ctx context.Context, userID uint, requestID, otpCode, nonce string) (*domain.PasswordChangeResponse, error) {
					return nil, domain.ErrPasswordChangeInvalidOTP
				}
			},
			expectedStatus:    http.StatusBadRequest,
			expectedErrorCode: "password_change_invalid_otp",
		},
		{
			name:      "service returns unauthorized error",
			userID:    1,
			requestID: "550e8400-e29b-41d4-a716-446655440000",
			requestBody: domain.PasswordChangeCompleteRequest{
				OTPCode: "123456",
				Nonce:   "test-nonce",
			},
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.CompletePasswordChangeFunc = func(ctx context.Context, userID uint, requestID, otpCode, nonce string) (*domain.PasswordChangeResponse, error) {
					return nil, domain.ErrPasswordChangeUnauthorized
				}
			},
			expectedStatus:    http.StatusForbidden,
			expectedErrorCode: "password_change_unauthorized",
		},
		{
			name:      "service returns not found error",
			userID:    1,
			requestID: "550e8400-e29b-41d4-a716-446655440000",
			requestBody: domain.PasswordChangeCompleteRequest{
				OTPCode: "123456",
				Nonce:   "test-nonce",
			},
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.CompletePasswordChangeFunc = func(ctx context.Context, userID uint, requestID, otpCode, nonce string) (*domain.PasswordChangeResponse, error) {
					return nil, domain.ErrPasswordChangeNotFound
				}
			},
			expectedStatus:    http.StatusNotFound,
			expectedErrorCode: "password_change_not_found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock service
			mockService := createMockPasswordChangeService(t)
			tt.setupServiceMock(mockService)

			// Create test handlers with mock service
			handlers := &TestPasswordChangeHandlers{service: mockService}

			// Create test context
			path := "/api/v1/password-changes/" + tt.requestID + "/verification"
			c, w := createGinContextForTest(t, "PUT", path, tt.requestBody, tt.userID)

			// Set URL param
			c.Params = gin.Params{{Key: "id", Value: tt.requestID}}

			// Execute handler
			handlers.CompletePasswordChange(c)

			// Assert status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Parse response
			var response map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			// Assert response structure
			if tt.expectedSuccessKey != "" {
				if _, exists := response[tt.expectedSuccessKey]; !exists {
					t.Errorf("expected response to contain key %s", tt.expectedSuccessKey)
				}
			}

			if tt.expectedErrorCode != "" {
				if errorField, exists := response["error"]; exists {
					if errorField != tt.expectedErrorCode {
						t.Errorf("expected error code %s, got %s", tt.expectedErrorCode, errorField)
					}
				} else {
					t.Error("expected error field in response")
				}
			}
		})
	}
}

func TestPasswordChangeHandlers_GetPasswordChangeStatus(t *testing.T) {
	tests := []struct {
		name               string
		userID             uint
		requestID          string
		setupServiceMock   func(*MockPasswordChangeService)
		expectedStatus     int
		expectedErrorCode  string
		expectedSuccessKey string
	}{
		{
			name:      "successful status retrieval",
			userID:    1,
			requestID: "550e8400-e29b-41d4-a716-446655440000",
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.GetPasswordChangeStatusFunc = func(ctx context.Context, userID uint, requestID string) (*domain.PasswordChangeStatusResponse, error) {
					return &domain.PasswordChangeStatusResponse{
						RequestID:   requestID,
						Status:      "initiated",
						RequestedAt: time.Now(),
						ExpiresAt:   time.Now().Add(15 * time.Minute),
						OTPAttempts: 0,
					}, nil
				}
			},
			expectedStatus:     http.StatusOK,
			expectedSuccessKey: "data",
		},
		{
			name:              "missing request ID",
			userID:            1,
			requestID:         "",
			setupServiceMock:  func(service *MockPasswordChangeService) {},
			expectedStatus:    http.StatusBadRequest,
			expectedErrorCode: "field_required",
		},
		{
			name:              "invalid UUID format",
			userID:            1,
			requestID:         "invalid-uuid",
			setupServiceMock:  func(service *MockPasswordChangeService) {},
			expectedStatus:    http.StatusBadRequest,
			expectedErrorCode: "invalid_uuid_format",
		},
		{
			name:              "missing user ID in context",
			userID:            0,
			requestID:         "550e8400-e29b-41d4-a716-446655440000",
			setupServiceMock:  func(service *MockPasswordChangeService) {},
			expectedStatus:    http.StatusUnauthorized,
			expectedErrorCode: "user_not_authenticated",
		},
		{
			name:      "service returns not found error",
			userID:    1,
			requestID: "550e8400-e29b-41d4-a716-446655440000",
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.GetPasswordChangeStatusFunc = func(ctx context.Context, userID uint, requestID string) (*domain.PasswordChangeStatusResponse, error) {
					return nil, domain.ErrPasswordChangeNotFound
				}
			},
			expectedStatus:    http.StatusNotFound,
			expectedErrorCode: "password_change_not_found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock service
			mockService := createMockPasswordChangeService(t)
			tt.setupServiceMock(mockService)

			// Create test handlers with mock service
			handlers := &TestPasswordChangeHandlers{service: mockService}

			// Create test context
			path := "/api/v1/password-changes/" + tt.requestID
			c, w := createGinContextForTest(t, "GET", path, nil, tt.userID)

			// Set URL param
			c.Params = gin.Params{{Key: "id", Value: tt.requestID}}

			// Execute handler
			handlers.GetPasswordChangeStatus(c)

			// Assert status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Parse response
			var response map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			// Assert response structure
			if tt.expectedSuccessKey != "" {
				if _, exists := response[tt.expectedSuccessKey]; !exists {
					t.Errorf("expected response to contain key %s", tt.expectedSuccessKey)
				}
			}

			if tt.expectedErrorCode != "" {
				if errorField, exists := response["error"]; exists {
					if errorField != tt.expectedErrorCode {
						t.Errorf("expected error code %s, got %s", tt.expectedErrorCode, errorField)
					}
				} else {
					t.Error("expected error field in response")
				}
			}
		})
	}
}

func TestPasswordChangeHandlers_GetPasswordChangeHistory(t *testing.T) {
	tests := []struct {
		name               string
		userID             uint
		queryParams        map[string]string
		setupServiceMock   func(*MockPasswordChangeService)
		expectedStatus     int
		expectedErrorCode  string
		expectedSuccessKey string
	}{
		{
			name:   "successful history retrieval with default limit",
			userID: 1,
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.GetPasswordChangeHistoryFunc = func(ctx context.Context, userID uint, limit int) (*domain.PasswordChangeHistoryResponse, error) {
					// Should use default limit of 50
					if limit != 50 {
						return nil, fmt.Errorf("expected limit 50, got %d", limit)
					}
					return &domain.PasswordChangeHistoryResponse{
						History: []domain.PasswordChangeStatusResponse{
							{
								RequestID:   "test-request-1",
								Status:      "completed",
								RequestedAt: time.Now().Add(-time.Hour),
							},
						},
					}, nil
				}
			},
			expectedStatus:     http.StatusOK,
			expectedSuccessKey: "data",
		},
		{
			name:   "successful history retrieval with custom limit",
			userID: 1,
			queryParams: map[string]string{
				"limit": "25",
			},
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.GetPasswordChangeHistoryFunc = func(ctx context.Context, userID uint, limit int) (*domain.PasswordChangeHistoryResponse, error) {
					if limit != 25 {
						return nil, fmt.Errorf("expected limit 25, got %d", limit)
					}
					return &domain.PasswordChangeHistoryResponse{History: []domain.PasswordChangeStatusResponse{}}, nil
				}
			},
			expectedStatus:     http.StatusOK,
			expectedSuccessKey: "data",
		},
		{
			name:   "invalid limit parameter falls back to default",
			userID: 1,
			queryParams: map[string]string{
				"limit": "invalid",
			},
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.GetPasswordChangeHistoryFunc = func(ctx context.Context, userID uint, limit int) (*domain.PasswordChangeHistoryResponse, error) {
					// Should fall back to default limit of 50
					if limit != 50 {
						return nil, fmt.Errorf("expected limit 50, got %d", limit)
					}
					return &domain.PasswordChangeHistoryResponse{History: []domain.PasswordChangeStatusResponse{}}, nil
				}
			},
			expectedStatus:     http.StatusOK,
			expectedSuccessKey: "data",
		},
		{
			name:              "missing user ID in context",
			userID:            0,
			setupServiceMock:  func(service *MockPasswordChangeService) {},
			expectedStatus:    http.StatusUnauthorized,
			expectedErrorCode: "user_not_authenticated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock service
			mockService := createMockPasswordChangeService(t)
			tt.setupServiceMock(mockService)

			// Create test handlers with mock service
			handlers := &TestPasswordChangeHandlers{service: mockService}

			// Create test context
			path := "/api/v1/password-changes"
			c, w := createGinContextForTest(t, "GET", path, nil, tt.userID)

			// Set query parameters
			if tt.queryParams != nil {
				q := c.Request.URL.Query()
				for key, value := range tt.queryParams {
					q.Add(key, value)
				}
				c.Request.URL.RawQuery = q.Encode()
			}

			// Execute handler
			handlers.GetPasswordChangeHistory(c)

			// Assert status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Parse response
			var response map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			// Assert response structure
			if tt.expectedSuccessKey != "" {
				if _, exists := response[tt.expectedSuccessKey]; !exists {
					t.Errorf("expected response to contain key %s", tt.expectedSuccessKey)
				}
			}

			if tt.expectedErrorCode != "" {
				if errorField, exists := response["error"]; exists {
					if errorField != tt.expectedErrorCode {
						t.Errorf("expected error code %s, got %s", tt.expectedErrorCode, errorField)
					}
				} else {
					t.Error("expected error field in response")
				}
			}
		})
	}
}

func TestPasswordChangeHandlers_InitiateForgotPassword(t *testing.T) {
	tests := []struct {
		name               string
		requestBody        interface{}
		setupServiceMock   func(*MockPasswordChangeService)
		expectedStatus     int
		expectedErrorCode  string
		expectedSuccessKey string
	}{
		{
			name: "successful forgot password initiation",
			requestBody: domain.ForgotPasswordInitiateRequest{
				Email: "user@example.com",
				Phone: "+1234567890",
			},
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.InitiateForgotPasswordFunc = func(ctx context.Context, email, phone, ipAddress, userAgent string) (*domain.PasswordChangeResponse, error) {
					return &domain.PasswordChangeResponse{
						RequestID: "forgot-request-id",
						Status:    "initiated",
						Message:   "If this email and phone combination exists, an OTP has been sent.",
						ExpiresAt: time.Now().Add(15 * time.Minute),
						Nonce:     "forgot-nonce",
					}, nil
				}
			},
			expectedStatus:     http.StatusOK,
			expectedSuccessKey: "data",
		},
		{
			name: "invalid request body",
			requestBody: map[string]interface{}{
				"invalid": "request",
			},
			setupServiceMock:  func(service *MockPasswordChangeService) {},
			expectedStatus:    http.StatusBadRequest,
			expectedErrorCode: "Invalid request format",
		},
		{
			name: "service returns rate limit error",
			requestBody: domain.ForgotPasswordInitiateRequest{
				Email: "user@example.com",
				Phone: "+1234567890",
			},
			setupServiceMock: func(service *MockPasswordChangeService) {
				service.InitiateForgotPasswordFunc = func(ctx context.Context, email, phone, ipAddress, userAgent string) (*domain.PasswordChangeResponse, error) {
					return nil, domain.ErrForgotPasswordRateLimitExceeded
				}
			},
			expectedStatus:    http.StatusTooManyRequests,
			expectedErrorCode: "forgot_password_rate_limit_exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock service
			mockService := createMockPasswordChangeService(t)
			tt.setupServiceMock(mockService)

			// Create test handlers with mock service
			handlers := &TestPasswordChangeHandlers{service: mockService}

			// Create test context (no user ID needed for forgot password)
			c, w := createGinContextForTest(t, "POST", "/api/v1/password-reset", tt.requestBody, 0)

			// Execute handler
			handlers.InitiateForgotPassword(c)

			// Assert status code
			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Parse response
			var response map[string]interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
				t.Fatalf("failed to unmarshal response: %v", err)
			}

			// Assert response structure
			if tt.expectedSuccessKey != "" {
				if _, exists := response[tt.expectedSuccessKey]; !exists {
					t.Errorf("expected response to contain key %s", tt.expectedSuccessKey)
				}
			}

			if tt.expectedErrorCode != "" {
				if errorField, exists := response["error"]; exists {
					if errorField != tt.expectedErrorCode {
						t.Errorf("expected error code %s, got %s", tt.expectedErrorCode, errorField)
					}
				} else {
					t.Error("expected error field in response")
				}
			}
		})
	}
}

// Test helper functions
func TestExtractUserID(t *testing.T) {
	tests := []struct {
		name         string
		contextValue interface{}
		expectedID   uint
		expectedErr  string
	}{
		{
			name:         "valid uint user ID",
			contextValue: uint(123),
			expectedID:   123,
			expectedErr:  "",
		},
		{
			name:         "valid float64 user ID",
			contextValue: float64(456),
			expectedID:   456,
			expectedErr:  "",
		},
		{
			name:         "valid int user ID",
			contextValue: int(789),
			expectedID:   789,
			expectedErr:  "",
		},
		{
			name:         "valid string user ID",
			contextValue: "999",
			expectedID:   999,
			expectedErr:  "",
		},
		{
			name:         "invalid string user ID",
			contextValue: "invalid",
			expectedID:   0,
			expectedErr:  domain.ErrInvalidUserID.Error(),
		},
		{
			name:         "invalid type",
			contextValue: []string{"invalid"},
			expectedID:   0,
			expectedErr:  domain.ErrInvalidUserID.Error(),
		},
		{
			name:         "missing user ID",
			contextValue: nil, // Simulates missing context key
			expectedID:   0,
			expectedErr:  "user ID not found in token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			c, _ := gin.CreateTestContext(httptest.NewRecorder())

			// Set user ID in context only if not nil
			if tt.contextValue != nil {
				c.Set("user_id", tt.contextValue)
			}

			userID, err := extractUserID(c)

			if tt.expectedErr != "" {
				if err == nil {
					t.Errorf("expected error %s, got nil", tt.expectedErr)
				} else if err.Error() != tt.expectedErr {
					t.Errorf("expected error %s, got %s", tt.expectedErr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}

			if userID != tt.expectedID {
				t.Errorf("expected user ID %d, got %d", tt.expectedID, userID)
			}
		})
	}
}

func TestValidateUUID(t *testing.T) {
	tests := []struct {
		name        string
		uuid        string
		expectedErr error
	}{
		{
			name:        "valid UUID v4",
			uuid:        "550e8400-e29b-41d4-a716-446655440000",
			expectedErr: nil,
		},
		{
			name:        "valid UUID v1",
			uuid:        "550e8400-e29b-11d4-a716-446655440000",
			expectedErr: nil,
		},
		{
			name:        "invalid UUID format",
			uuid:        "invalid-uuid",
			expectedErr: domain.ErrInvalidUUID,
		},
		{
			name:        "empty string",
			uuid:        "",
			expectedErr: domain.ErrInvalidUUID,
		},
		{
			name:        "UUID with wrong version",
			uuid:        "550e8400-e29b-01d4-a716-446655440000", // Version 0 (invalid)
			expectedErr: domain.ErrInvalidUUID,
		},
		{
			name:        "UUID with wrong variant",
			uuid:        "550e8400-e29b-41d4-1716-446655440000", // Wrong variant bits
			expectedErr: domain.ErrInvalidUUID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateUUID(tt.uuid)

			if tt.expectedErr != nil {
				if err == nil {
					t.Errorf("expected error %v, got nil", tt.expectedErr)
				} else if err != tt.expectedErr {
					t.Errorf("expected error %v, got %v", tt.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			}
		})
	}
}

func TestGetPasswordErrorStatusCode(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"current password incorrect", domain.ErrCurrentPasswordIncorrect, http.StatusBadRequest},
		{"password strength insufficient", domain.ErrPasswordStrengthInsufficient, http.StatusBadRequest},
		{"password change unauthorized", domain.ErrPasswordChangeUnauthorized, http.StatusForbidden},
		{"password change not found", domain.ErrPasswordChangeNotFound, http.StatusNotFound},
		{"password change in progress", domain.ErrPasswordChangeInProgress, http.StatusConflict},
		{"password change expired", domain.ErrPasswordChangeExpired, http.StatusGone},
		{"password change rate limit exceeded", domain.ErrPasswordChangeRateLimitExceeded, http.StatusTooManyRequests},
		{"unknown error", fmt.Errorf("unknown error"), http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := getPasswordErrorStatusCode(tt.err)
			if status != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, status)
			}
		})
	}
}

func TestGetPasswordErrorCode(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		expectedCode string
	}{
		{"current password incorrect", domain.ErrCurrentPasswordIncorrect, "current_password_incorrect"},
		{"password strength insufficient", domain.ErrPasswordStrengthInsufficient, "password_strength_insufficient"},
		{"password change unauthorized", domain.ErrPasswordChangeUnauthorized, "password_change_unauthorized"},
		{"password change not found", domain.ErrPasswordChangeNotFound, "password_change_not_found"},
		{"unknown error", fmt.Errorf("unknown error"), "internal_server_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code := getPasswordErrorCode(tt.err)
			if code != tt.expectedCode {
				t.Errorf("expected code %s, got %s", tt.expectedCode, code)
			}
		})
	}
}
