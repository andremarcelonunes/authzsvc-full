package handlers

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
)

// AuthHandlers handles authentication HTTP requests using clean architecture
type AuthHandlers struct {
	authSvc  domain.AuthService
	otpSvc   domain.OTPService
	userRepo domain.UserRepository
}

// NewAuthHandlers creates new auth handlers
func NewAuthHandlers(authSvc domain.AuthService, otpSvc domain.OTPService, userRepo domain.UserRepository) *AuthHandlers {
	return &AuthHandlers{
		authSvc:  authSvc,
		otpSvc:   otpSvc,
		userRepo: userRepo,
	}
}

// RegisterRequest represents registration request
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Phone    string `json:"phone" binding:"required"`
	Password string `json:"password" binding:"required,min=6"`
	Role     string `json:"role,omitempty"` // Optional role field, defaults to "user"
}

// LoginRequest represents login request
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// OTPVerifyRequest represents OTP verification request
type OTPVerifyRequest struct {
	Phone  string `json:"phone" binding:"required"`
	Code   string `json:"code" binding:"required"`
	UserID uint   `json:"user_id" binding:"required"`
}

// RefreshRequest represents token refresh request
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// Register handles user registration
func (h *AuthHandlers) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Set default role if not provided
	role := req.Role
	if role == "" {
		role = "user"
	}
	
	user, err := h.authSvc.Register(c.Request.Context(), req.Email, req.Phone, req.Password, role)
	if err != nil {
		if err == domain.ErrUserAlreadyExists {
			c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"data": gin.H{
			"message": "User registered successfully. Please verify your phone number.",
			"user_id": user.ID,
		},
	})
}

// Login handles user login
func (h *AuthHandlers) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.authSvc.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		switch err {
		case domain.ErrInvalidCredentials:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		case domain.ErrUserInactive:
			c.JSON(http.StatusForbidden, gin.H{"error": "Account is inactive"})
		case domain.ErrPhoneNotVerified:
			c.JSON(http.StatusForbidden, gin.H{"error": "Phone number not verified"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Login failed"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"access_token":  result.AccessToken,
			"refresh_token": result.RefreshToken,
			"token_type":    "Bearer",
			"expires_in":    result.ExpiresIn,
			"user": gin.H{
				"id":    result.User.ID,
				"email": result.User.Email,
				"role":  result.User.Role,
			},
		},
	})
}

// SendOTP handles OTP generation and sending
func (h *AuthHandlers) SendOTP(c *gin.Context) {
	var req struct {
		Phone  string `json:"phone" binding:"required"`
		UserID uint   `json:"user_id" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Verify the user exists and owns this phone number
	user, err := h.userRepo.FindByID(c.Request.Context(), req.UserID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find user"})
		return
	}

	// Verify the phone number matches the user
	if user.Phone != req.Phone {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone number does not match user"})
		return
	}

	_, err = h.otpSvc.Generate(c.Request.Context(), req.Phone, req.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"message": "OTP sent successfully",
		},
	})
}

// Refresh handles token refresh
func (h *AuthHandlers) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := h.authSvc.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		switch err {
		case domain.ErrTokenInvalid, domain.ErrTokenExpired:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		case domain.ErrSessionNotFound, domain.ErrSessionExpired:
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Token refresh failed"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"access_token": result.AccessToken,
			"token_type":   "Bearer",
			"expires_in":   result.ExpiresIn,
		},
	})
}

// VerifyOTP handles OTP verification
func (h *AuthHandlers) VerifyOTP(c *gin.Context) {
	var req OTPVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// First verify the user exists and owns this phone number
	user, err := h.userRepo.FindByID(c.Request.Context(), req.UserID)
	if err != nil {
		if err == domain.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to find user"})
		return
	}

	// Verify the phone number matches the user
	if user.Phone != req.Phone {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone number does not match user"})
		return
	}

	valid, err := h.otpSvc.Verify(c.Request.Context(), req.Phone, req.Code, req.UserID)
	if err != nil {
		switch err {
		case domain.ErrOTPNotFound:
			c.JSON(http.StatusNotFound, gin.H{"error": "OTP not found"})
		case domain.ErrOTPExpired:
			c.JSON(http.StatusBadRequest, gin.H{"error": "OTP has expired"})
		case domain.ErrOTPMaxAttempts:
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "Maximum attempts exceeded"})
		case domain.ErrOTPInvalid:
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OTP code"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "OTP verification failed"})
		}
		return
	}

	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OTP code"})
		return
	}

	// Activate phone number in database (idempotent operation)
	if err := h.userRepo.ActivatePhone(c.Request.Context(), user.ID); err != nil {
		log.Printf("PHONE_ACTIVATION_FAILED: user_id=%d phone=%s error=%v timestamp=%s", 
			user.ID, req.Phone, err, time.Now().UTC().Format(time.RFC3339))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to activate phone number"})
		return
	}

	// Audit log for successful phone activation
	log.Printf("PHONE_ACTIVATED: user_id=%d phone=%s email=%s timestamp=%s", 
		user.ID, req.Phone, user.Email, time.Now().UTC().Format(time.RFC3339))

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"message": "Phone number verified and activated successfully",
			"user_id": user.ID,
		},
	})
}

// Me handles getting user profile (requires authentication)
func (h *AuthHandlers) Me(c *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userIDStr, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context"})
		return
	}

	userID, err := strconv.ParseUint(userIDStr.(string), 10, 32)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
		return
	}

	user, err := h.authSvc.GetUserProfile(c.Request.Context(), uint(userID))
	if err != nil {
		if err == domain.ErrUserNotFound {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user profile"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"id":             user.ID,
			"email":          user.Email,
			"phone":          user.Phone,
			"role":           user.Role,
			"is_active":      user.IsActive,
			"phone_verified": user.PhoneVerified,
			"created_at":     user.CreatedAt,
			"updated_at":     user.UpdatedAt,
		},
	})
}

// Logout handles user logout (requires authentication)
func (h *AuthHandlers) Logout(c *gin.Context) {
	// Get session ID from context (set by auth middleware)
	sessionID, exists := c.Get("session_id")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Session ID not found"})
		return
	}

	err := h.authSvc.Logout(c.Request.Context(), sessionID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Logout failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"message": "Logged out successfully",
		},
	})
}