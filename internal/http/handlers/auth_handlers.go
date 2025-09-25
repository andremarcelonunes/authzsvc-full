package handlers

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
)

// AuthHandlers handles authentication HTTP requests using clean architecture
type AuthHandlers struct {
	authSvc     domain.AuthService
	otpSvc      domain.OTPService
	userRepo    domain.UserRepository
	tokenSvc    domain.TokenService
	sessionRepo domain.SessionRepository
}

// NewAuthHandlers creates new auth handlers
func NewAuthHandlers(authSvc domain.AuthService, otpSvc domain.OTPService, userRepo domain.UserRepository, tokenSvc domain.TokenService, sessionRepo domain.SessionRepository) *AuthHandlers {
	return &AuthHandlers{
		authSvc:     authSvc,
		otpSvc:      otpSvc,
		userRepo:    userRepo,
		tokenSvc:    tokenSvc,
		sessionRepo: sessionRepo,
	}
}

// RegisterRequest represents registration request
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Phone    string `json:"phone" binding:"required"`
	Password string `json:"password" binding:"required,min=6"`
	Role     string `json:"role,omitempty"` // Optional role field, defaults to "user"
}

// LoginRequest represents login request - CB-194: Extended for unified authentication
type LoginRequest struct {
	// Unified identifier field - can be email or phone number
	Identifier string `json:"identifier,omitempty"`
	
	// Legacy email field for backward compatibility - when provided, takes precedence over Identifier
	Email    string `json:"email,omitempty"`
	
	// Password for authentication
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
	
	// Get client IP for rate limiting
	clientIP := c.ClientIP()
	ctx := context.WithValue(c.Request.Context(), "client_ip", clientIP)
	
	user, err := h.authSvc.Register(ctx, req.Email, req.Phone, req.Password, role)
	if err != nil {
		if errors.Is(err, domain.ErrUserAlreadyExists) {
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

// Login handles user login - CB-194: Enhanced with unified authentication
func (h *AuthHandlers) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validation: ensure either email or identifier is provided
	if req.Email == "" && req.Identifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Either email or identifier field must be provided",
		})
		return
	}

	// Create AuthRequest for unified authentication
	authRequest := &domain.AuthRequest{
		Email:      req.Email,      // Legacy field for backward compatibility
		Identifier: req.Identifier, // New unified field
		Password:   req.Password,
	}

	// Add client context information for authentication metadata
	ctx := context.WithValue(c.Request.Context(), "user_agent", c.GetHeader("User-Agent"))
	ctx = context.WithValue(ctx, "client_ip", c.ClientIP())

	// Use the new AuthenticateUser method which supports both email and phone
	result, err := h.authSvc.AuthenticateUser(ctx, authRequest)
	if err != nil {
		// Enhanced error handling with specific messages for different identifier types
		switch {
		case errors.Is(err, domain.ErrInvalidCredentials):
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Invalid credentials",
			})
		case errors.Is(err, domain.ErrUserInactive):
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Account is inactive",
			})
		case errors.Is(err, domain.ErrPhoneNotVerified):
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Phone number not verified. Please verify your phone number to login with phone.",
			})
		case errors.Is(err, domain.ErrInvalidIdentifier):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid identifier format. Please provide a valid email address or phone number.",
			})
		case errors.Is(err, domain.ErrIdentifierTypeUnknown):
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Unable to determine identifier type. Please provide a valid email address or phone number.",
			})
		default:
			log.Printf("Login failed for identifier %s: %v", getLogSafeIdentifier(req), err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Login failed",
			})
		}
		return
	}

	// Enhanced response with authentication method metadata
	response := gin.H{
		"data": gin.H{
			"access_token":  result.AccessToken,
			"refresh_token": result.RefreshToken,
			"token_type":    "Bearer",
			"expires_in":    result.ExpiresIn,
			"user": gin.H{
				"id":    result.User.ID,
				"email": result.User.Email,
				"phone": result.User.Phone,
				"role":  result.User.Role,
			},
		},
	}

	// Include authentication metadata if available
	if result.AuthenticationContext != nil {
		response["data"].(gin.H)["authentication"] = gin.H{
			"method":              string(result.AuthenticationContext.Method),
			"authenticated_at":    result.AuthenticationContext.AuthenticatedAt,
			"country_code":        result.AuthenticationContext.CountryCode,
		}
		
		// Performance metrics (optional, can be enabled for monitoring)
		if c.GetHeader("X-Include-Performance") == "true" {
			response["data"].(gin.H)["performance"] = gin.H{
				"resolution_duration_ms": result.AuthenticationContext.ResolutionDuration.Milliseconds(),
				"lookup_duration_ms":     result.AuthenticationContext.LookupDuration.Milliseconds(),
				"validation_duration_ms": result.AuthenticationContext.ValidationDuration.Milliseconds(),
			}
		}
	}

	c.JSON(http.StatusOK, response)
}

// getLogSafeIdentifier returns a safe version of the identifier for logging (masks sensitive parts)
func getLogSafeIdentifier(req LoginRequest) string {
	if req.Email != "" {
		if len(req.Email) > 3 {
			return req.Email[:3] + "***"
		}
		return "***"
	}
	if req.Identifier != "" {
		if len(req.Identifier) > 3 {
			return req.Identifier[:3] + "***"
		}
		return "***"
	}
	return "unknown"
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
		// Use errors.Is for wrapped errors from CB-179 enhanced security implementation
		if errors.Is(err, domain.ErrTokenInvalid) || errors.Is(err, domain.ErrTokenExpired) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		} else if errors.Is(err, domain.ErrSessionNotFound) || errors.Is(err, domain.ErrSessionExpired) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired"})
		} else if errors.Is(err, domain.ErrUserInactive) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User account is inactive"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Token refresh failed"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"access_token":  result.AccessToken,
			"refresh_token": result.RefreshToken, // CB-179: Return new refresh token for security rotation
			"token_type":    "Bearer",
			"expires_in":    result.ExpiresIn,
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

// VerifyTokenResponse represents the response for token verification
type VerifyTokenResponse struct {
	Valid     bool   `json:"valid"`
	TokenType string `json:"token_type,omitempty"`
	User      *struct {
		ID        uint   `json:"id"`
		Role      string `json:"role"`
		SessionID string `json:"session_id"`
		IssuedAt  int64  `json:"issued_at"`
		ExpiresAt int64  `json:"expires_at"`
	} `json:"user,omitempty"`
	Error     string `json:"error,omitempty"`
	ErrorCode string `json:"error_code,omitempty"`
}

// VerifyToken handles token verification for external services
func (h *AuthHandlers) VerifyToken(c *gin.Context) {
	// Get Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"valid":      false,
			"error":      "Authorization header required",
			"error_code": "MISSING_AUTHORIZATION_HEADER",
		})
		return
	}

	// Check Bearer token format
	tokenParts := strings.SplitN(authHeader, " ", 2)
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		c.JSON(http.StatusBadRequest, gin.H{
			"valid":      false,
			"error":      "Invalid authorization header format",
			"error_code": "INVALID_AUTHORIZATION_FORMAT",
		})
		return
	}

	token := tokenParts[1]

	// Validate token
	claims, err := h.tokenSvc.ValidateAccessToken(token)
	if err != nil {
		var errorCode string
		var errorMessage string

		switch {
		case errors.Is(err, domain.ErrTokenExpired):
			errorCode = "TOKEN_EXPIRED"
			errorMessage = "Token expired"
		case errors.Is(err, domain.ErrTokenMalformed):
			errorCode = "TOKEN_MALFORMED"
			errorMessage = "Token malformed"
		case errors.Is(err, domain.ErrTokenInvalid):
			errorCode = "TOKEN_INVALID"
			errorMessage = "Token invalid"
		default:
			errorCode = "TOKEN_VALIDATION_FAILED"
			errorMessage = "Token validation failed"
		}

		c.JSON(http.StatusUnauthorized, gin.H{
			"valid":      false,
			"error":      errorMessage,
			"error_code": errorCode,
		})
		return
	}

	// Verify session exists in Redis if session ID is present
	if claims.SessionID != "" {
		session, err := h.sessionRepo.FindByID(c.Request.Context(), claims.SessionID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"valid":      false,
				"error":      "Session invalid or expired",
				"error_code": "SESSION_INVALID",
			})
			return
		}

		// Ensure session belongs to the same user
		if session.UserID != claims.UserID {
			c.JSON(http.StatusUnauthorized, gin.H{
				"valid":      false,
				"error":      "Session user mismatch",
				"error_code": "SESSION_USER_MISMATCH",
			})
			return
		}

		// Check if session is expired
		if time.Now().After(session.ExpiresAt) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"valid":      false,
				"error":      "Session expired",
				"error_code": "SESSION_EXPIRED",
			})
			return
		}
	}

	// Token and session are valid, return success response
	c.JSON(http.StatusOK, gin.H{
		"valid":      true,
		"token_type": "access_token",
		"user": gin.H{
			"id":         claims.UserID,
			"role":       claims.Role,
			"session_id": claims.SessionID,
			"issued_at":  claims.IssuedAt,
			"expires_at": claims.ExpiresAt,
		},
	})
}