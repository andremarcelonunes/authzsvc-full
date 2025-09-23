package handlers

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/services"
)

// PasswordChangeHandlers handles password change and forgot password requests
type PasswordChangeHandlers struct {
	passwordChangeService *services.PasswordChangeService
}

// NewPasswordChangeHandlers creates new password change handlers
func NewPasswordChangeHandlers(passwordChangeService *services.PasswordChangeService) *PasswordChangeHandlers {
	return &PasswordChangeHandlers{
		passwordChangeService: passwordChangeService,
	}
}

// InitiatePasswordChange handles POST /api/v1/password-changes
func (h *PasswordChangeHandlers) InitiatePasswordChange(c *gin.Context) {
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
	response, err := h.passwordChangeService.InitiatePasswordChange(
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

// CompletePasswordChange handles PUT /api/v1/password-changes/:id/verification
func (h *PasswordChangeHandlers) CompletePasswordChange(c *gin.Context) {
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
	response, err := h.passwordChangeService.CompletePasswordChange(
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

// GetPasswordChangeStatus handles GET /api/v1/password-changes/:id
func (h *PasswordChangeHandlers) GetPasswordChangeStatus(c *gin.Context) {
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
	status, err := h.passwordChangeService.GetPasswordChangeStatus(
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

// CancelPasswordChange handles DELETE /api/v1/password-changes/:id
func (h *PasswordChangeHandlers) CancelPasswordChange(c *gin.Context) {
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

	// Cancel password change
	response, err := h.passwordChangeService.CancelPasswordChange(
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
		"data": response,
	})
}

// GetPasswordChangeHistory handles GET /api/v1/password-changes
func (h *PasswordChangeHandlers) GetPasswordChangeHistory(c *gin.Context) {
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
	history, err := h.passwordChangeService.GetPasswordChangeHistory(
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

// InitiateForgotPassword handles POST /api/v1/password-reset
func (h *PasswordChangeHandlers) InitiateForgotPassword(c *gin.Context) {
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
	response, err := h.passwordChangeService.InitiateForgotPassword(
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

// CompleteForgotPassword handles PUT /api/v1/password-reset/:id/complete
func (h *PasswordChangeHandlers) CompleteForgotPassword(c *gin.Context) {
	requestID := c.Param("id")
	if requestID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "field_required",
			"message": "Forgot password request ID is required",
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

	var req domain.ForgotPasswordCompleteRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request format",
			"message": err.Error(),
			"code":    400,
		})
		return
	}

	// Complete forgot password
	response, err := h.passwordChangeService.CompleteForgotPassword(
		c.Request.Context(),
		requestID,
		req.OTPCode,
		req.Nonce,
		req.NewPassword,
		req.ConfirmPassword,
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

// Helper functions for validation and error handling

// validateUUID validates if a string is a valid UUID format
func validateUUID(uuid string) error {
	// UUID v4 regex pattern
	uuidPattern := `^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`
	matched, err := regexp.MatchString(uuidPattern, uuid)
	if err != nil {
		return fmt.Errorf("regex error: %w", err)
	}
	if !matched {
		return domain.ErrInvalidUUID
	}
	return nil
}

// extractUserID safely extracts and validates user ID from gin context
func extractUserID(c *gin.Context) (uint, error) {
	userIDInterface, exists := c.Get("user_id")
	if !exists {
		return 0, fmt.Errorf("user ID not found in token")
	}

	switch v := userIDInterface.(type) {
	case uint:
		return v, nil
	case float64:
		return uint(v), nil
	case int:
		return uint(v), nil
	case string:
		parsed, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return 0, domain.ErrInvalidUserID
		}
		return uint(parsed), nil
	default:
		return 0, domain.ErrInvalidUserID
	}
}

func getPasswordErrorStatusCode(err error) int {
	switch err {
	case domain.ErrCurrentPasswordIncorrect,
		domain.ErrPasswordSameAsCurrent,
		domain.ErrPasswordStrengthInsufficient,
		domain.ErrPasswordCommonlyUsed,
		domain.ErrPasswordContainsUserInfo,
		domain.ErrPasswordReused,
		domain.ErrPasswordChangeInvalidNonce,
		domain.ErrPasswordChangeInvalidOTP,
		domain.ErrForgotPasswordInvalidNonce,
		domain.ErrForgotPasswordInvalidOTP,
		domain.ErrEmailPhoneMismatch,
		domain.ErrInvalidUUID,
		domain.ErrInvalidUserID,
		domain.ErrInvalidInput,
		domain.ErrFieldRequired,
		domain.ErrFieldInvalid,
		domain.ErrFieldFormatInvalid:
		return http.StatusBadRequest
	case domain.ErrPasswordChangeUnauthorized:
		return http.StatusForbidden
	case domain.ErrPasswordChangeNotFound,
		domain.ErrForgotPasswordNotFound:
		return http.StatusNotFound
	case domain.ErrPasswordChangeInProgress:
		return http.StatusConflict
	case domain.ErrPasswordChangeExpired,
		domain.ErrPasswordChangeCancelled,
		domain.ErrForgotPasswordExpired:
		return http.StatusGone
	case domain.ErrPasswordChangeRateLimitExceeded,
		domain.ErrForgotPasswordRateLimitExceeded,
		domain.ErrPasswordChangeOTPMaxAttempts,
		domain.ErrForgotPasswordOTPMaxAttempts:
		return http.StatusTooManyRequests
	case domain.ErrPasswordChangeOTPExpired,
		domain.ErrForgotPasswordOTPExpired:
		return http.StatusGone
	default:
		return http.StatusInternalServerError
	}
}

func getPasswordErrorCode(err error) string {
	switch err {
	case domain.ErrCurrentPasswordIncorrect:
		return "current_password_incorrect"
	case domain.ErrPasswordSameAsCurrent:
		return "password_same_as_current"
	case domain.ErrPasswordStrengthInsufficient:
		return "password_strength_insufficient"
	case domain.ErrPasswordCommonlyUsed:
		return "password_commonly_used"
	case domain.ErrPasswordContainsUserInfo:
		return "password_contains_user_info"
	case domain.ErrPasswordReused:
		return "password_reused"
	case domain.ErrPasswordChangeInProgress:
		return "password_change_in_progress"
	case domain.ErrPasswordChangeRateLimitExceeded:
		return "password_change_rate_limit_exceeded"
	case domain.ErrPasswordChangeExpired:
		return "password_change_expired"
	case domain.ErrPasswordChangeInvalidNonce:
		return "password_change_invalid_nonce"
	case domain.ErrPasswordChangeCancelled:
		return "password_change_cancelled"
	case domain.ErrPasswordChangeNotFound:
		return "password_change_not_found"
	case domain.ErrPasswordChangeUnauthorized:
		return "password_change_unauthorized"
	case domain.ErrPasswordChangeInvalidOTP:
		return "password_change_invalid_otp"
	case domain.ErrPasswordChangeOTPExpired:
		return "password_change_otp_expired"
	case domain.ErrPasswordChangeOTPMaxAttempts:
		return "password_change_otp_max_attempts"
	case domain.ErrForgotPasswordRateLimitExceeded:
		return "forgot_password_rate_limit_exceeded"
	case domain.ErrForgotPasswordExpired:
		return "forgot_password_expired"
	case domain.ErrForgotPasswordInvalidNonce:
		return "forgot_password_invalid_nonce"
	case domain.ErrForgotPasswordNotFound:
		return "forgot_password_not_found"
	case domain.ErrForgotPasswordInvalidOTP:
		return "forgot_password_invalid_otp"
	case domain.ErrForgotPasswordOTPExpired:
		return "forgot_password_otp_expired"
	case domain.ErrForgotPasswordOTPMaxAttempts:
		return "forgot_password_otp_max_attempts"
	case domain.ErrEmailPhoneMismatch:
		return "email_phone_mismatch"
	case domain.ErrInvalidUUID:
		return "invalid_uuid_format"
	case domain.ErrInvalidUserID:
		return "invalid_user_id_format"
	case domain.ErrInvalidInput:
		return "invalid_input"
	case domain.ErrFieldRequired:
		return "field_required"
	case domain.ErrFieldInvalid:
		return "field_invalid"
	case domain.ErrFieldFormatInvalid:
		return "field_format_invalid"
	default:
		return "internal_server_error"
	}
}