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
	"github.com/you/authzsvc/internal/http/middleware"
)

// AuthHandlers handles authentication HTTP requests using clean architecture
type AuthHandlers struct {
	authSvc     domain.AuthService
	otpSvc      domain.OTPService
	userRepo    domain.UserRepository
	tokenSvc    domain.TokenService
	sessionRepo domain.SessionRepository

	// requireRegistrationEmail is REQUIRE_REGISTRATION_EMAIL (default true: e-mail is mandatory).
	requireRegistrationEmail bool
	// requirePhoneVerification is REQUIRE_PHONE_VERIFICATION (default true); it only changes
	// the message returned by registration, the rule itself lives in the services.
	requirePhoneVerification bool
	// passwordPolicyEnforced is true when the auth service enforces the configured password policy
	// (PASSWORD_MIN_LENGTH / PASSWORD_REQUIRE_COMPLEXITY). Without it the handler keeps its
	// historical floor of 6 characters.
	passwordPolicyEnforced bool
}

// legacyMinPasswordLength is the floor the request binding used to enforce (min=6).
const legacyMinPasswordLength = 6

// WithPasswordPolicyEnforced tells the handler that the auth service applies the configured
// password policy, so the fixed 6-character floor must not override a lower PASSWORD_MIN_LENGTH.
func WithPasswordPolicyEnforced(enforced bool) AuthHandlersOption {
	return func(h *AuthHandlers) { h.passwordPolicyEnforced = enforced }
}

// rejectShortPassword answers 400 when no policy is wired and the password is under the legacy floor.
func (h *AuthHandlers) rejectShortPassword(c *gin.Context, requestType, password string) bool {
	if h.passwordPolicyEnforced || len(password) >= legacyMinPasswordLength {
		return false
	}
	// Same text the binding tag min=6 produced, so the response is unchanged.
	c.JSON(http.StatusBadRequest, gin.H{"error": "Key: '" + requestType + ".Password' Error:Field validation for 'Password' failed on the 'min' tag"})
	return true
}

// AuthHandlersOption customises AuthHandlers at construction.
type AuthHandlersOption func(*AuthHandlers)

// WithRequireRegistrationEmail sets whether registration (public and admin) requires an e-mail.
// The default is true.
func WithRequireRegistrationEmail(required bool) AuthHandlersOption {
	return func(h *AuthHandlers) { h.requireRegistrationEmail = required }
}

// WithRequirePhoneVerification sets whether registration tells the user to verify the phone.
// The default is true.
func WithRequirePhoneVerification(required bool) AuthHandlersOption {
	return func(h *AuthHandlers) { h.requirePhoneVerification = required }
}

// NewAuthHandlers creates new auth handlers
func NewAuthHandlers(authSvc domain.AuthService, otpSvc domain.OTPService, userRepo domain.UserRepository, tokenSvc domain.TokenService, sessionRepo domain.SessionRepository, opts ...AuthHandlersOption) *AuthHandlers {
	h := &AuthHandlers{
		authSvc:                  authSvc,
		otpSvc:                   otpSvc,
		userRepo:                 userRepo,
		tokenSvc:                 tokenSvc,
		sessionRepo:              sessionRepo,
		requireRegistrationEmail: true,
		requirePhoneVerification: true,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// RegisterRequest represents registration request
type RegisterRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Phone    string `json:"phone" binding:"required"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role,omitempty"` // Optional role field, defaults to "user"
}

// registerRequestOptionalEmail is RegisterRequest when REQUIRE_REGISTRATION_EMAIL=false: the e-mail
// may be missing or empty, but an e-mail that is sent must still be valid.
type registerRequestOptionalEmail struct {
	Email    string `json:"email" binding:"omitempty,email"`
	Phone    string `json:"phone" binding:"required"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role,omitempty"`
}

// bindRegisterRequest binds the registration body with the e-mail rule selected by the switch.
func (h *AuthHandlers) bindRegisterRequest(c *gin.Context) (RegisterRequest, error) {
	if h.requireRegistrationEmail {
		var req RegisterRequest
		err := c.ShouldBindJSON(&req)
		return req, err
	}
	var relaxed registerRequestOptionalEmail
	if err := c.ShouldBindJSON(&relaxed); err != nil {
		return RegisterRequest{}, err
	}
	return RegisterRequest(relaxed), nil
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
	req, err := h.bindRegisterRequest(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.rejectShortPassword(c, "RegisterRequest", req.Password) {
		return
	}

	// Set default role if not provided
	role := domain.NormalizeRegistrationRole(req.Role)
	
	// Get client IP for rate limiting
	clientIP := c.ClientIP()
	ctx := context.WithValue(c.Request.Context(), "client_ip", clientIP)
	
	user, err := h.authSvc.Register(ctx, req.Email, req.Phone, req.Password, role)
	if err != nil {
		if errors.Is(err, domain.ErrRoleNotAllowedForRegistration) {
			c.JSON(http.StatusForbidden, gin.H{"error": roleNotSelfRegistrableMessage})
			return
		}
		if errors.Is(err, domain.ErrUserAlreadyExists) {
			c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
			return
		}
		if errors.Is(err, domain.ErrRegistrationRateLimited) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": registrationRateLimitedMessage})
			return
		}
		if respondRegistrationValidationError(c, err) {
			return
		}
		if respondPhoneCodeError(c, err) {
			return
		}
		if respondSMSError(c, err) {
			// The user row was already created and is kept; the client retries /auth/otp/send later.
			return
		}
		if errors.Is(err, domain.ErrOTPResendThrottled) {
			// The user row was already created and is kept: a retry of /auth/register
			// answers 409, so the client should call /auth/otp/send after waiting.
			c.JSON(http.StatusTooManyRequests, gin.H{"error": otpResendThrottledMessage})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	message := "User registered successfully."
	if h.requirePhoneVerification {
		message = "User registered successfully. Please verify your phone number."
	}
	c.JSON(http.StatusCreated, gin.H{
		"data": gin.H{
			"message": message,
			"user_id": user.ID,
		},
	})
}

// roleNotSelfRegistrableMessage is the client-facing message for domain.ErrRoleNotAllowedForRegistration (HTTP 403).
const roleNotSelfRegistrableMessage = "This role cannot be self-registered; only user, client or contact accounts can be created through public registration"

// registrationRateLimitedMessage is the client-facing message for domain.ErrRegistrationRateLimited (HTTP 429).
const registrationRateLimitedMessage = "Too many registration attempts. Please try again later"

// securityRejectedMessage is the fixed message for SECURITY_THREAT: scanner detail and input are never echoed.
const securityRejectedMessage = "Request rejected by security validation"

// respondRegistrationValidationError answers 400 for a domain.RegistrationValidationError and
// reports whether it did. Body follows the validation middleware's flat keys ("error", "code")
// plus "field" when known.
func respondRegistrationValidationError(c *gin.Context, err error) bool {
	var verr *domain.RegistrationValidationError
	if !errors.As(err, &verr) {
		return false
	}
	body := gin.H{"error": verr.Message, "code": verr.Code}
	if verr.Code == "SECURITY_THREAT" {
		body["error"] = securityRejectedMessage
	} else if verr.Field != "" {
		body["field"] = verr.Field
	}
	c.JSON(http.StatusBadRequest, body)
	return true
}

// roleCreationNotAllowedMessage is the client-facing message for domain.ErrRoleCreationNotAllowed (HTTP 403).
const roleCreationNotAllowedMessage = "Your role is not allowed to create accounts with the requested role"

// AdminCreateUserRequest represents the privileged user creation request (POST /admin/users).
type AdminCreateUserRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Phone    string `json:"phone" binding:"required"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role" binding:"required"`
}

// adminCreateUserRequestOptionalEmail is AdminCreateUserRequest when REQUIRE_REGISTRATION_EMAIL=false.
type adminCreateUserRequestOptionalEmail struct {
	Email    string `json:"email" binding:"omitempty,email"`
	Phone    string `json:"phone" binding:"required"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role" binding:"required"`
}

// AdminCreateUser handles POST /admin/users: root/admin create accounts for other roles.
// The creator's identity and role come from the validated JWT (set by the auth middleware).
// Which role may create which is enforced by the service (domain.CanCreateRole).
func (h *AuthHandlers) AdminCreateUser(c *gin.Context) {
	var req AdminCreateUserRequest
	var err error
	if h.requireRegistrationEmail {
		err = c.ShouldBindJSON(&req)
	} else {
		var relaxed adminCreateUserRequestOptionalEmail
		if err = c.ShouldBindJSON(&relaxed); err == nil {
			req = AdminCreateUserRequest(relaxed)
		}
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if h.rejectShortPassword(c, "AdminCreateUserRequest", req.Password) {
		return
	}

	creatorIDRaw, idOK := c.Get("user_id")
	creatorRoleRaw, roleOK := c.Get("user_role")
	creatorIDStr, _ := creatorIDRaw.(string)
	creatorRole, _ := creatorRoleRaw.(string)
	creatorID, parseErr := strconv.ParseUint(creatorIDStr, 10, 64)
	if !idOK || !roleOK || parseErr != nil || creatorRole == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}
	creator := &domain.User{ID: uint(creatorID), Role: creatorRole}

	ctx := context.WithValue(c.Request.Context(), "client_ip", c.ClientIP())

	user, err := h.authSvc.CreateUserByAdmin(ctx, creator, req.Email, req.Phone, req.Password, req.Role)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrRoleCreationNotAllowed):
			c.JSON(http.StatusForbidden, gin.H{"error": roleCreationNotAllowedMessage})
		case errors.Is(err, domain.ErrUserAlreadyExists):
			c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		case errors.Is(err, domain.ErrOTPResendThrottled):
			// The user row was already created and is kept (see Register).
			c.JSON(http.StatusTooManyRequests, gin.H{"error": otpResendThrottledMessage})
		case respondRegistrationValidationError(c, err):
			// answered with 400
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		}
		return
	}

	message := "User created successfully."
	if h.requirePhoneVerification {
		message = "User created successfully. The user must verify their phone number."
	}
	c.JSON(http.StatusCreated, gin.H{
		"data": gin.H{
			"user_id": user.ID,
			"role":    user.Role,
			"message": message,
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
			body := gin.H{
				"error": "Phone number not verified. Please verify your phone number to login with phone.",
				"code":  "phone_not_verified",
			}
			// Only after the password was verified: what /auth/otp/send and /auth/otp/verify need.
			var failure *domain.AuthFailureError
			if errors.As(err, &failure) && failure.UserID != 0 {
				body["user_id"] = failure.UserID
				body["phone"] = failure.Phone
			}
			c.JSON(http.StatusForbidden, body)
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

// respondPhoneCodeError answers the errors of a code that could not be started because of the phone:
// the same 400 shape as a registration validation error (error, code, field).
func respondPhoneCodeError(c *gin.Context, err error) bool {
	switch {
	case errors.Is(err, domain.ErrPhoneNotMobile):
		c.JSON(http.StatusBadRequest, gin.H{"error": domain.PhoneNotMobileMessage, "code": "PHONE_FORMAT_INVALID", "field": "phone"})
		return true
	case errors.Is(err, domain.ErrSMSInvalidPhone):
		c.JSON(http.StatusBadRequest, gin.H{"error": "Phone number format is invalid", "code": "PHONE_FORMAT_INVALID", "field": "phone"})
		return true
	}
	return false
}

// otpResendThrottledMessage is the client-facing message for domain.ErrOTPResendThrottled (HTTP 429).
const otpResendThrottledMessage = "Please wait before requesting a new verification code"

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

	// "Only once": a verified phone is never sent a verification code again.
	if user.PhoneVerified {
		c.JSON(http.StatusConflict, gin.H{"error": "phone_already_verified", "message": "Phone number already verified"})
		return
	}

	ctx := domain.WithClientIP(c.Request.Context(), c.ClientIP())
	_, err = h.otpSvc.Generate(ctx, req.Phone, req.UserID)
	if err != nil {
		if respondPhoneCodeError(c, err) {
			return
		}
		if respondSMSError(c, err) {
			return
		}
		if errors.Is(err, domain.ErrOTPResendThrottled) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": otpResendThrottledMessage})
			return
		}
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
		// The reason (session id included, never the token) so a dropped session can be explained afterwards
		log.Printf("REFRESH_REJECTED: ip=%s error=%v", c.ClientIP(), err)
		// Use errors.Is for wrapped errors from CB-179 enhanced security implementation
		if errors.Is(err, domain.ErrTokenInvalid) || errors.Is(err, domain.ErrTokenExpired) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired refresh token"})
		} else if errors.Is(err, domain.ErrSessionNotFound) || errors.Is(err, domain.ErrSessionExpired) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Session expired"})
		} else if errors.Is(err, domain.ErrUserInactive) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User account is inactive"})
		} else if errors.Is(err, domain.ErrConcurrentRefresh) {
			// Another refresh of this session is running: retry the same token shortly. NOT a logout.
			c.Header("Retry-After", "1")
			c.JSON(http.StatusConflict, gin.H{"error": "Refresh already in progress, retry shortly"})
		} else if errors.Is(err, domain.ErrTemporarilyUnavailable) {
			// A dependency (Redis...) failed: retry the same token. NOT a logout.
			c.Header("Retry-After", "2")
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Token refresh temporarily unavailable, retry shortly"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Token refresh failed"})
		}
		return
	}

	var userID uint
	if result.User != nil {
		userID = result.User.ID
	}
	log.Printf("REFRESH_OK: user_id=%d session=%s ip=%s", userID, result.SessionID, c.ClientIP())
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
		log.Printf("PHONE_ACTIVATION_FAILED: user_id=%d error=%v timestamp=%s",
			user.ID, middleware.RedactSensitive(err.Error()), time.Now().UTC().Format(time.RFC3339))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to activate phone number"})
		return
	}

	// Audit log for successful phone activation
	log.Printf("PHONE_ACTIVATED: user_id=%d timestamp=%s", user.ID, time.Now().UTC().Format(time.RFC3339))

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

// AddRoleRequest is the body of POST /auth/roles.
type AddRoleRequest struct {
	// Add is the profile to add to the caller's own account: "client" or "contact".
	Add string `json:"add" binding:"required"`
}

// roleTransitionNotAllowedMessage is the client-facing message for domain.ErrRoleTransitionNotAllowed (HTTP 403).
const roleTransitionNotAllowedMessage = "This profile cannot be added to your account"

// AddRole handles POST /auth/roles: the authenticated user adds the client or contact profile to
// their own account. The transition rule is domain.NextRoleOnAddProfile (enforced by the service).
// The new role reaches tokens at the next refresh or login.
func (h *AuthHandlers) AddRole(c *gin.Context) {
	var req AddRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	userIDStr, _ := c.Get("user_id")
	idStr, _ := userIDStr.(string)
	userID, parseErr := strconv.ParseUint(idStr, 10, 32)
	if parseErr != nil || userID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
		return
	}

	user, err := h.authSvc.AddProfile(c.Request.Context(), uint(userID), req.Add)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrRoleTransitionNotAllowed), errors.Is(err, domain.ErrUserInactive):
			c.JSON(http.StatusForbidden, gin.H{"error": roleTransitionNotAllowedMessage})
		case errors.Is(err, domain.ErrUserNotFound):
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update role"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data": gin.H{
			"user_id": user.ID,
			"role":    user.Role,
			"message": "Role updated. Refresh your token to receive the new role.",
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
			"phone_verified": claims.PhoneVerified,
		},
	})
}