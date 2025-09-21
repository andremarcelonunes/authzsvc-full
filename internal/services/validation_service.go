package services

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
)

// RequestValidationServiceImpl implements domain.RequestValidationService
type RequestValidationServiceImpl struct {
	securityValidator     domain.SecurityValidationService
	businessValidator     domain.BusinessValidationService
	rateLimitValidator    domain.RateLimitValidationService
	redisClient          *redis.Client
	logger               *slog.Logger
	
	// Validation configuration
	enableCaching        bool
	cacheTimeout         time.Duration
	maxValidationTime    time.Duration
	enableMetrics        bool
}

// RequestValidationConfig holds configuration for the validation service
type RequestValidationConfig struct {
	EnableCaching        bool
	CacheTimeout         time.Duration
	MaxValidationTime    time.Duration
	EnableMetrics        bool
}

// NewRequestValidationService creates a new request validation service
func NewRequestValidationService(
	securityValidator domain.SecurityValidationService,
	businessValidator domain.BusinessValidationService,
	rateLimitValidator domain.RateLimitValidationService,
	redisClient *redis.Client,
	config RequestValidationConfig,
) domain.RequestValidationService {
	if config.CacheTimeout == 0 {
		config.CacheTimeout = 5 * time.Minute
	}
	if config.MaxValidationTime == 0 {
		config.MaxValidationTime = 30 * time.Second
	}

	return &RequestValidationServiceImpl{
		securityValidator:     securityValidator,
		businessValidator:     businessValidator,
		rateLimitValidator:    rateLimitValidator,
		redisClient:          redisClient,
		logger:               slog.Default(),
		enableCaching:        config.EnableCaching,
		cacheTimeout:         config.CacheTimeout,
		maxValidationTime:    config.MaxValidationTime,
		enableMetrics:        config.EnableMetrics,
	}
}

// ValidateRequest orchestrates the complete validation pipeline
func (s *RequestValidationServiceImpl) ValidateRequest(ctx context.Context, request interface{}, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
	startTime := time.Now()
	
	// Create timeout context
	ctx, cancel := context.WithTimeout(ctx, s.maxValidationTime)
	defer cancel()
	
	// Initialize result (assume valid until proven otherwise)
	result := &domain.ValidationResult{
		ValidationID: fmt.Sprintf("val_%d", time.Now().UnixNano()),
		Timestamp:    startTime,
		Context:      validationCtx,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		FieldResults: make(map[string]domain.FieldValidationResult),
		RulesApplied: 0,
		IsValid:      true,  // Start as valid, set to false if errors found
		Passed:       true,  // Start as passed, set to false if errors found
	}

	// Check cache first if enabled
	if s.enableCaching {
		if cachedResult, err := s.getCachedResult(ctx, request, validationCtx); err == nil && cachedResult != nil {
			s.logger.Debug("Validation result served from cache", 
				"validation_id", cachedResult.ValidationID,
				"endpoint", validationCtx.Endpoint)
			return cachedResult, nil
		}
	}

	// Phase 1: Rate limiting validation
	if rateLimitResult, err := s.validateRateLimit(ctx, validationCtx); err != nil {
		return nil, fmt.Errorf("rate limit validation failed: %w", err)
	} else if !rateLimitResult.Passed {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, rateLimitResult.Errors...)
		result.ValidationTime = time.Since(startTime)
		return result, nil
	}

	// Phase 2: Security validation
	if securityResult, err := s.validateSecurity(ctx, request, validationCtx); err != nil {
		return nil, fmt.Errorf("security validation failed: %w", err)
	} else if securityResult != nil {
		result.SecurityResult = securityResult
		if securityResult.ThreatLevel == domain.ThreatHigh || securityResult.ThreatLevel == domain.ThreatCritical {
			result.IsValid = false
			result.Passed = false
			result.Errors = append(result.Errors, domain.ValidationError{
				Code:      "SECURITY_THREAT",
				Message:   fmt.Sprintf("Security threat detected: %s", securityResult.ThreatLevel),
				Severity:  domain.SeverityError,
				Category:  domain.CategorySecurity,
				Timestamp: time.Now(),
			})
		}
	}

	// Phase 3: Field validation
	if fieldResult, err := s.validateFields(ctx, request); err != nil {
		return nil, fmt.Errorf("field validation failed: %w", err)
	} else {
		result.FieldResults = fieldResult.FieldResults
		result.Errors = append(result.Errors, fieldResult.Errors...)
		result.Warnings = append(result.Warnings, fieldResult.Warnings...)
		result.RulesApplied += fieldResult.RulesApplied
		if !fieldResult.IsValid {
			result.IsValid = false
			result.Passed = false
		}
	}

	// Phase 4: Business rules validation
	if businessResult, err := s.validateBusinessRules(ctx, request, validationCtx); err != nil {
		return nil, fmt.Errorf("business validation failed: %w", err)
	} else if businessResult != nil {
		result.Errors = append(result.Errors, businessResult.Errors...)
		result.Warnings = append(result.Warnings, businessResult.Warnings...)
		result.RulesApplied += businessResult.RulesApplied
		if !businessResult.IsValid {
			result.IsValid = false
			result.Passed = false
		}
	}

	// Set final validation status
	if result.IsValid {
		result.Passed = true
	}

	// Calculate validation time
	result.ValidationTime = time.Since(startTime)

	// Cache result if successful and caching enabled
	if s.enableCaching && result.Passed {
		if err := s.cacheResult(ctx, request, validationCtx, result); err != nil {
			s.logger.Warn("Failed to cache validation result", "error", err)
		}
	}

	// Log metrics if enabled
	if s.enableMetrics {
		s.logValidationMetrics(result, validationCtx)
	}

	return result, nil
}

// ValidateRegistrationRequest validates user registration requests
func (s *RequestValidationServiceImpl) ValidateRegistrationRequest(ctx context.Context, email, phone, password, role string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
	startTime := time.Now()
	
	result := &domain.ValidationResult{
		ValidationID: fmt.Sprintf("reg_val_%d", time.Now().UnixNano()),
		Timestamp:    startTime,
		Context:      validationCtx,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		FieldResults: make(map[string]domain.FieldValidationResult),
		RulesApplied: 0,
		IsValid:      true,  // Start as valid, set to false if errors found
		Passed:       true,  // Start as passed, set to false if errors found
	}

	// Rate limiting check for registration
	rateLimitKey := fmt.Sprintf("reg_limit:%s", validationCtx.IPAddress)
	rateLimitResult, err := s.rateLimitValidator.CheckRateLimit(ctx, rateLimitKey, 5, 1*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("rate limit check failed: %w", err)
	}
	if !rateLimitResult.Allowed {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "RATE_LIMIT_EXCEEDED",
			Message:   "Registration rate limit exceeded",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryRateLimit,
			Timestamp: time.Now(),
		})
		return result, nil
	}

	// Validate individual fields
	fields := map[string]interface{}{
		"email":    email,
		"phone":    phone,
		"password": password,
		"role":     role,
	}

	// Security validation
	securityResult, err := s.securityValidator.ScanForThreats(ctx, fields, []domain.SecurityConstraint{
		{
			XSSProtection:         true,
			SQLInjectionCheck:     true,
			ScriptInjectionCheck:  true,
			ThreatScanEnabled:     true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("security validation failed: %w", err)
	}
	
	result.SecurityResult = securityResult
	if securityResult.ThreatLevel == domain.ThreatHigh || securityResult.ThreatLevel == domain.ThreatCritical {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "SECURITY_THREAT",
			Field:     "registration",
			Message:   "Security threat detected in registration data",
			Severity:  domain.SeverityError,
			Category:  domain.CategorySecurity,
			Timestamp: time.Now(),
		})
	}

	// Business rules validation
	businessResult, err := s.businessValidator.ValidateRegistrationRules(ctx, email, phone, password, role)
	if err != nil {
		return nil, fmt.Errorf("business validation failed: %w", err)
	}
	
	if businessResult != nil {
		result.Errors = append(result.Errors, businessResult.Errors...)
		result.Warnings = append(result.Warnings, businessResult.Warnings...)
		result.RulesApplied += businessResult.RulesApplied
		if !businessResult.IsValid {
			result.IsValid = false
			result.Passed = false
		}
	}

	// Set final status
	if len(result.Errors) == 0 {
		result.IsValid = true
		result.Passed = true
	}

	result.ValidationTime = time.Since(startTime)
	return result, nil
}

// ValidateLoginRequest validates user login requests
func (s *RequestValidationServiceImpl) ValidateLoginRequest(ctx context.Context, email, password string, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
	startTime := time.Now()
	
	result := &domain.ValidationResult{
		ValidationID: fmt.Sprintf("login_val_%d", time.Now().UnixNano()),
		Timestamp:    startTime,
		Context:      validationCtx,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		FieldResults: make(map[string]domain.FieldValidationResult),
		RulesApplied: 0,
		IsValid:      true,  // Start as valid, set to false if errors found
		Passed:       true,  // Start as passed, set to false if errors found
	}

	// Rate limiting for login attempts
	rateLimitKey := fmt.Sprintf("login_limit:%s", validationCtx.IPAddress)
	rateLimitResult, err := s.rateLimitValidator.CheckRateLimit(ctx, rateLimitKey, 10, 15*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("rate limit check failed: %w", err)
	}
	if !rateLimitResult.Allowed {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "RATE_LIMIT_EXCEEDED",
			Message:   "Login rate limit exceeded",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryRateLimit,
			Timestamp: time.Now(),
		})
		return result, nil
	}

	// Check for brute force attempts
	bruteForceKey := fmt.Sprintf("brute_force:%s", email)
	isBlocked, blockDuration, err := s.rateLimitValidator.IsBlocked(ctx, bruteForceKey, "login")
	if err != nil {
		return nil, fmt.Errorf("brute force check failed: %w", err)
	}
	if isBlocked {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "BRUTE_FORCE_DETECTED",
			Field:     "email",
			Message:   fmt.Sprintf("Account temporarily blocked due to brute force attempts. Try again in %v", blockDuration),
			Severity:  domain.SeverityError,
			Category:  domain.CategoryRateLimit,
			Timestamp: time.Now(),
		})
		return result, nil
	}

	// Security validation
	fields := map[string]interface{}{
		"email":    email,
		"password": password,
	}

	securityResult, err := s.securityValidator.ScanForThreats(ctx, fields, []domain.SecurityConstraint{
		{
			XSSProtection:         true,
			SQLInjectionCheck:     true,
			ScriptInjectionCheck:  true,
			ThreatScanEnabled:     true,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("security validation failed: %w", err)
	}
	
	result.SecurityResult = securityResult
	if securityResult.ThreatLevel == domain.ThreatHigh || securityResult.ThreatLevel == domain.ThreatCritical {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "SECURITY_THREAT",
			Field:     "login",
			Message:   "Security threat detected in login credentials",
			Severity:  domain.SeverityError,
			Category:  domain.CategorySecurity,
			Timestamp: time.Now(),
		})
	}

	// Business rules validation
	businessResult, err := s.businessValidator.ValidateLoginRules(ctx, email, password, nil)
	if err != nil {
		return nil, fmt.Errorf("business validation failed: %w", err)
	}
	
	if businessResult != nil {
		result.Errors = append(result.Errors, businessResult.Errors...)
		result.Warnings = append(result.Warnings, businessResult.Warnings...)
		result.RulesApplied += businessResult.RulesApplied
		if !businessResult.IsValid {
			result.IsValid = false
			result.Passed = false
		}
	}

	// Set final status
	if len(result.Errors) == 0 {
		result.IsValid = true
		result.Passed = true
	}

	result.ValidationTime = time.Since(startTime)
	return result, nil
}

// ValidateOTPRequest validates OTP verification requests
func (s *RequestValidationServiceImpl) ValidateOTPRequest(ctx context.Context, phone, code string, userID uint, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
	startTime := time.Now()
	
	result := &domain.ValidationResult{
		ValidationID: fmt.Sprintf("otp_val_%d", time.Now().UnixNano()),
		Timestamp:    startTime,
		Context:      validationCtx,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		FieldResults: make(map[string]domain.FieldValidationResult),
		RulesApplied: 0,
		IsValid:      true,  // Start as valid, set to false if errors found
		Passed:       true,  // Start as passed, set to false if errors found
	}

	// Rate limiting for OTP attempts
	rateLimitKey := fmt.Sprintf("otp_limit:%s", phone)
	rateLimitResult, err := s.rateLimitValidator.CheckRateLimit(ctx, rateLimitKey, 5, 5*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("rate limit check failed: %w", err)
	}
	if !rateLimitResult.Allowed {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "RATE_LIMIT_EXCEEDED",
			Message:   "OTP verification rate limit exceeded",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryRateLimit,
			Timestamp: time.Now(),
		})
		return result, nil
	}

	// Business rules validation
	businessResult, err := s.businessValidator.ValidateOTPRules(ctx, phone, code, userID)
	if err != nil {
		return nil, fmt.Errorf("business validation failed: %w", err)
	}
	
	if businessResult != nil {
		result.Errors = append(result.Errors, businessResult.Errors...)
		result.Warnings = append(result.Warnings, businessResult.Warnings...)
		result.RulesApplied += businessResult.RulesApplied
		if !businessResult.IsValid {
			result.IsValid = false
			result.Passed = false
		}
	}

	// Set final status
	if len(result.Errors) == 0 {
		result.IsValid = true
		result.Passed = true
	}

	result.ValidationTime = time.Since(startTime)
	return result, nil
}

// ValidateFields validates individual fields against constraints
func (s *RequestValidationServiceImpl) ValidateFields(ctx context.Context, fields map[string]interface{}, rules []domain.ValidationRule) (*domain.ValidationResult, error) {
	startTime := time.Now()
	
	result := &domain.ValidationResult{
		ValidationID: fmt.Sprintf("field_val_%d", time.Now().UnixNano()),
		Timestamp:    startTime,
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		FieldResults: make(map[string]domain.FieldValidationResult),
		RulesApplied: 0,
	}

	for fieldName, value := range fields {
		fieldResult := domain.FieldValidationResult{
			FieldName:     fieldName,
			IsValid:       true,
			OriginalValue: value,
			Errors:        []domain.ValidationError{},
			Warnings:      []domain.ValidationError{},
			AppliedRules:  []string{},
		}

		// Find applicable rules for this field
		for _, rule := range rules {
			if rule.FieldName == fieldName && rule.IsActive {
				fieldResult.AppliedRules = append(fieldResult.AppliedRules, rule.ID)
				
				// Apply field constraints
				if rule.Constraint != nil {
					if err := s.validateFieldConstraint(fieldName, value, rule.Constraint, &fieldResult); err != nil {
						return nil, fmt.Errorf("field constraint validation failed: %w", err)
					}
				}
				
				result.RulesApplied++
			}
		}

		// Update overall result based on field validation
		if !fieldResult.IsValid {
			result.IsValid = false
			result.Passed = false
			result.Errors = append(result.Errors, fieldResult.Errors...)
		}
		result.Warnings = append(result.Warnings, fieldResult.Warnings...)
		result.FieldResults[fieldName] = fieldResult
	}

	result.ValidationTime = time.Since(startTime)
	return result, nil
}

// ValidateField validates a single field against constraints
func (s *RequestValidationServiceImpl) ValidateField(ctx context.Context, fieldName string, value interface{}, constraints *domain.FieldConstraint) (*domain.FieldValidationResult, error) {
	result := &domain.FieldValidationResult{
		FieldName:     fieldName,
		IsValid:       true,
		OriginalValue: value,
		Errors:        []domain.ValidationError{},
		Warnings:      []domain.ValidationError{},
		AppliedRules:  []string{},
	}

	if err := s.validateFieldConstraint(fieldName, value, constraints, result); err != nil {
		return nil, fmt.Errorf("field constraint validation failed: %w", err)
	}

	return result, nil
}

// ValidateBatch validates multiple requests in parallel for performance
func (s *RequestValidationServiceImpl) ValidateBatch(ctx context.Context, requests []interface{}, validationCtx *domain.ValidationContext) ([]domain.ValidationResult, error) {
	results := make([]domain.ValidationResult, len(requests))
	
	// TODO: Implement parallel validation for performance
	// For now, validate sequentially
	for i, request := range requests {
		result, err := s.ValidateRequest(ctx, request, validationCtx)
		if err != nil {
			return nil, fmt.Errorf("batch validation failed for request %d: %w", i, err)
		}
		results[i] = *result
	}

	return results, nil
}

// Helper methods

func (s *RequestValidationServiceImpl) validateRateLimit(ctx context.Context, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
	result := &domain.ValidationResult{
		IsValid:  true,
		Passed:   true,
		Errors:   []domain.ValidationError{},
		Warnings: []domain.ValidationError{},
	}

	// Check general rate limit based on IP
	rateLimitKey := fmt.Sprintf("general_limit:%s", validationCtx.IPAddress)
	rateLimitResult, err := s.rateLimitValidator.CheckRateLimit(ctx, rateLimitKey, 100, 1*time.Hour)
	if err != nil {
		return nil, fmt.Errorf("rate limit check failed: %w", err)
	}

	if !rateLimitResult.Allowed {
		result.IsValid = false
		result.Passed = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "RATE_LIMIT_EXCEEDED",
			Message:   "Rate limit exceeded for IP address",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryRateLimit,
			Timestamp: time.Now(),
		})
	}

	return result, nil
}

func (s *RequestValidationServiceImpl) validateSecurity(ctx context.Context, request interface{}, validationCtx *domain.ValidationContext) (*domain.SecurityValidationResult, error) {
	// Convert request to map for security scanning
	fields := make(map[string]interface{})
	
	// TODO: Implement proper reflection-based field extraction
	// For now, handle specific request types
	
	securityConstraints := []domain.SecurityConstraint{
		{
			XSSProtection:         true,
			SQLInjectionCheck:     true,
			ScriptInjectionCheck:  true,
			ThreatScanEnabled:     true,
		},
	}

	return s.securityValidator.ScanForThreats(ctx, fields, securityConstraints)
}

func (s *RequestValidationServiceImpl) validateFields(ctx context.Context, request interface{}) (*domain.ValidationResult, error) {
	result := &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		FieldResults: make(map[string]domain.FieldValidationResult),
		RulesApplied: 0,
	}

	// Extract fields from request
	fields, ok := request.(map[string]interface{})
	if !ok {
		// If not a map, try to handle common request types
		return result, nil // For now, just pass through non-map requests
	}

	// Validate each field with built-in rules
	for fieldName, value := range fields {
		fieldResult := domain.FieldValidationResult{
			FieldName: fieldName,
			IsValid:   true,
			Errors:    []domain.ValidationError{},
			Warnings:  []domain.ValidationError{},
		}

		// Apply common validation rules based on field name
		switch fieldName {
		case "email":
			if err := s.validateEmailField(fieldName, value, &fieldResult); err != nil {
				return nil, err
			}
		case "password":
			if err := s.validatePasswordField(fieldName, value, &fieldResult); err != nil {
				return nil, err
			}
		case "phone":
			if err := s.validatePhoneField(fieldName, value, &fieldResult); err != nil {
				return nil, err
			}
		}

		// Update overall result if field validation failed
		if !fieldResult.IsValid {
			result.IsValid = false
			result.Passed = false
			result.Errors = append(result.Errors, fieldResult.Errors...)
		}
		result.Warnings = append(result.Warnings, fieldResult.Warnings...)
		result.FieldResults[fieldName] = fieldResult
		result.RulesApplied++
	}

	return result, nil
}

func (s *RequestValidationServiceImpl) validateBusinessRules(ctx context.Context, request interface{}, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
	// Initialize result
	result := &domain.ValidationResult{
		IsValid:      true,
		Passed:       true,
		Errors:       []domain.ValidationError{},
		Warnings:     []domain.ValidationError{},
		RulesApplied: 0,
	}
	
	// Define business constraints based on validation context
	var constraints []domain.BusinessConstraint
	
	// Add default business constraints based on endpoint
	if validationCtx != nil {
		switch validationCtx.Endpoint {
		case "auth/register":
			constraints = append(constraints, domain.BusinessConstraint{
				DomainRules:    []string{"unique_email", "valid_phone", "password_policy"},
				WorkflowState:  "registration",
				QuotaCheck:     true,
			})
		case "auth/login":
			constraints = append(constraints, domain.BusinessConstraint{
				DomainRules:    []string{"account_active", "password_attempts"},
				WorkflowState:  "authentication",
				QuotaCheck:     true,
			})
		default:
			// For security tests and other endpoints, check for business logic exploits
			constraints = append(constraints, domain.BusinessConstraint{
				DomainRules:    []string{"validate_amounts", "validate_user_existence", "validate_permissions"},
				WorkflowState:  "security_validation",
				QuotaCheck:     true,
			})
		}
	}
	
	// Call business validation service if we have constraints
	if len(constraints) > 0 {
		businessResult, err := s.businessValidator.ValidateBusinessRules(ctx, request, constraints)
		if err != nil {
			return nil, fmt.Errorf("business validation service failed: %w", err)
		}
		
		if businessResult != nil {
			result.IsValid = businessResult.IsValid
			result.Passed = businessResult.Passed
			result.Errors = businessResult.Errors
			result.Warnings = businessResult.Warnings
			result.RulesApplied = businessResult.RulesApplied
		}
	}
	
	return result, nil
}

func (s *RequestValidationServiceImpl) validateFieldConstraint(fieldName string, value interface{}, constraints *domain.FieldConstraint, result *domain.FieldValidationResult) error {
	strValue := fmt.Sprintf("%v", value)

	// Required field check - constraints don't have Required field, so we'll skip this for now
	if value == nil || strValue == "" {
		result.IsValid = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "FIELD_REQUIRED",
			Field:     fieldName,
			Message:   fmt.Sprintf("Field %s is required", fieldName),
			Severity:  domain.SeverityError,
			Category:  domain.CategoryField,
			Timestamp: time.Now(),
		})
		return nil
	}

	// String length validation
	if constraints.MinLength != nil && len(strValue) < *constraints.MinLength {
		result.IsValid = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "FIELD_TOO_SHORT",
			Field:     fieldName,
			Message:   fmt.Sprintf("Field %s must be at least %d characters long", fieldName, *constraints.MinLength),
			Severity:  domain.SeverityError,
			Category:  domain.CategoryField,
			Value:     value,
			Expected:  *constraints.MinLength,
			Timestamp: time.Now(),
		})
	}

	if constraints.MaxLength != nil && len(strValue) > *constraints.MaxLength {
		result.IsValid = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "FIELD_TOO_LONG",
			Field:     fieldName,
			Message:   fmt.Sprintf("Field %s must be at most %d characters long", fieldName, *constraints.MaxLength),
			Severity:  domain.SeverityError,
			Category:  domain.CategoryField,
			Value:     value,
			Expected:  *constraints.MaxLength,
			Timestamp: time.Now(),
		})
	}

	// Pattern validation
	if constraints.Pattern != "" {
		if constraints.RegexCompiled == nil {
			compiled, err := regexp.Compile(constraints.Pattern)
			if err != nil {
				return fmt.Errorf("invalid regex pattern for field %s: %w", fieldName, err)
			}
			constraints.RegexCompiled = compiled
		}

		if !constraints.RegexCompiled.MatchString(strValue) {
			result.IsValid = false
			result.Errors = append(result.Errors, domain.ValidationError{
				Code:      "FIELD_FORMAT_INVALID",
				Field:     fieldName,
				Message:   fmt.Sprintf("Field %s does not match required pattern", fieldName),
				Severity:  domain.SeverityError,
				Category:  domain.CategoryField,
				Value:     value,
				Expected:  constraints.Pattern,
				Timestamp: time.Now(),
			})
		}
	}

	// Allowed values validation
	if len(constraints.AllowedValues) > 0 {
		allowed := false
		for _, allowedValue := range constraints.AllowedValues {
			if strValue == allowedValue {
				allowed = true
				break
			}
		}
		if !allowed {
			result.IsValid = false
			result.Errors = append(result.Errors, domain.ValidationError{
				Code:      "FIELD_VALUE_NOT_ALLOWED",
				Field:     fieldName,
				Message:   fmt.Sprintf("Field %s contains invalid value", fieldName),
				Severity:  domain.SeverityError,
				Category:  domain.CategoryField,
				Value:     value,
				Expected:  constraints.AllowedValues,
				Timestamp: time.Now(),
			})
		}
	}

	// Forbidden values validation
	if len(constraints.ForbiddenValues) > 0 {
		for _, forbiddenValue := range constraints.ForbiddenValues {
			if strValue == forbiddenValue {
				result.IsValid = false
				result.Errors = append(result.Errors, domain.ValidationError{
					Code:      "FIELD_VALUE_FORBIDDEN",
					Field:     fieldName,
					Message:   fmt.Sprintf("Field %s contains forbidden value", fieldName),
					Severity:  domain.SeverityError,
					Category:  domain.CategoryField,
					Value:     value,
					Timestamp: time.Now(),
				})
				break
			}
		}
	}

	return nil
}

func (s *RequestValidationServiceImpl) getCachedResult(ctx context.Context, request interface{}, validationCtx *domain.ValidationContext) (*domain.ValidationResult, error) {
	if s.redisClient == nil {
		return nil, fmt.Errorf("redis client not available")
	}

	// Generate cache key based on request and context
	_ = fmt.Sprintf("validation_cache:%s:%s", validationCtx.Endpoint, validationCtx.Method)
	
	// TODO: Implement proper cache key generation and result deserialization
	return nil, fmt.Errorf("cache miss")
}

func (s *RequestValidationServiceImpl) cacheResult(ctx context.Context, request interface{}, validationCtx *domain.ValidationContext, result *domain.ValidationResult) error {
	if s.redisClient == nil {
		return fmt.Errorf("redis client not available")
	}

	// Generate cache key
	cacheKey := fmt.Sprintf("validation_cache:%s:%s", validationCtx.Endpoint, validationCtx.Method)
	
	// TODO: Implement proper result serialization and caching
	return s.redisClient.Set(ctx, cacheKey, "cached", s.cacheTimeout).Err()
}

func (s *RequestValidationServiceImpl) logValidationMetrics(result *domain.ValidationResult, validationCtx *domain.ValidationContext) {
	s.logger.Info("Validation completed",
		"validation_id", result.ValidationID,
		"endpoint", validationCtx.Endpoint,
		"method", validationCtx.Method,
		"is_valid", result.IsValid,
		"passed", result.Passed,
		"validation_time_ms", result.ValidationTime.Milliseconds(),
		"rules_applied", result.RulesApplied,
		"error_count", len(result.Errors),
		"warning_count", len(result.Warnings),
		"threat_level", func() string {
			if result.SecurityResult != nil {
				return string(result.SecurityResult.ThreatLevel)
			}
			return "none"
		}(),
	)
}

// validateEmailField validates email field format and requirements
func (s *RequestValidationServiceImpl) validateEmailField(fieldName string, value interface{}, result *domain.FieldValidationResult) error {
	str, ok := value.(string)
	if !ok {
		result.IsValid = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "INVALID_TYPE",
			Message:   "Email must be a string",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryField,
			Field:     fieldName,
			Timestamp: time.Now(),
		})
		return nil
	}

	// Email format validation
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !emailRegex.MatchString(str) {
		result.IsValid = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "INVALID_EMAIL_FORMAT",
			Message:   "Invalid email format",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryField,
			Field:     fieldName,
			Timestamp: time.Now(),
		})
	}

	// Length validation
	if len(str) > 254 {
		result.IsValid = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "EMAIL_TOO_LONG",
			Message:   "Email address too long (max 254 characters)",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryField,
			Field:     fieldName,
			Timestamp: time.Now(),
		})
	}

	return nil
}

// validatePasswordField validates password field strength and requirements
func (s *RequestValidationServiceImpl) validatePasswordField(fieldName string, value interface{}, result *domain.FieldValidationResult) error {
	str, ok := value.(string)
	if !ok {
		result.IsValid = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "INVALID_TYPE",
			Message:   "Password must be a string",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryField,
			Field:     fieldName,
			Timestamp: time.Now(),
		})
		return nil
	}

	// Length validation
	if len(str) < 8 {
		result.IsValid = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "PASSWORD_TOO_SHORT",
			Message:   "Password must be at least 8 characters long",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryField,
			Field:     fieldName,
			Timestamp: time.Now(),
		})
	}

	if len(str) > 128 {
		result.IsValid = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "PASSWORD_TOO_LONG",
			Message:   "Password must be less than 128 characters",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryField,
			Field:     fieldName,
			Timestamp: time.Now(),
		})
	}

	// Strength validation (warnings for common weak patterns)
	if str == "password" || str == "123456" || str == "admin" {
		result.Warnings = append(result.Warnings, domain.ValidationError{
			Code:      "WEAK_PASSWORD",
			Message:   "Password is commonly used and weak",
			Severity:  domain.SeverityWarning,
			Category:  domain.CategorySecurity,
			Field:     fieldName,
			Timestamp: time.Now(),
		})
	}

	return nil
}

// validatePhoneField validates phone number format
func (s *RequestValidationServiceImpl) validatePhoneField(fieldName string, value interface{}, result *domain.FieldValidationResult) error {
	str, ok := value.(string)
	if !ok {
		result.IsValid = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "INVALID_TYPE",
			Message:   "Phone number must be a string",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryField,
			Field:     fieldName,
			Timestamp: time.Now(),
		})
		return nil
	}

	// Phone format validation (basic international format)
	phoneRegex := regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	if !phoneRegex.MatchString(str) {
		result.IsValid = false
		result.Errors = append(result.Errors, domain.ValidationError{
			Code:      "INVALID_PHONE_FORMAT",
			Message:   "Invalid phone number format",
			Severity:  domain.SeverityError,
			Category:  domain.CategoryField,
			Field:     fieldName,
			Timestamp: time.Now(),
		})
	}

	return nil
}

// Compile-time interface compliance verification
var _ domain.RequestValidationService = (*RequestValidationServiceImpl)(nil)