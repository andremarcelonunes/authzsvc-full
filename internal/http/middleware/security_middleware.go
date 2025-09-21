package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// SecurityMiddleware provides security protection through various validation layers
type SecurityMiddleware struct {
	config SecurityConfig
	logger SecurityLogger
}

// SecurityConfig holds configuration for security middleware
type SecurityConfig struct {
	// Content validation
	AllowedContentTypes    []string
	MaxRequestSize         int64
	RequireContentType     bool
	
	// Security headers
	EnableSecurityHeaders  bool
	CSPPolicy             string
	FrameOptions          string
	ContentTypeOptions    bool
	XSSProtection         bool
	
	// CSRF protection
	EnableCSRF            bool
	CSRFTokenHeader       string
	CSRFCookieName        string
	CSRFSecretKey         string
	
	// Rate limiting
	EnableRateLimit       bool
	RequestsPerMinute     int
	BurstSize            int
	
	// Content filtering
	BlockSuspiciousContent bool
	MaxHeaderSize         int
	MaxQueryParams        int
}

// SecurityLogger interface for security event logging
type SecurityLogger interface {
	LogSecurityEvent(event SecurityEvent)
	LogSecurityViolation(violation SecurityViolation)
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	Type      string    `json:"type"`
	Message   string    `json:"message"`
	ClientIP  string    `json:"client_ip"`
	UserAgent string    `json:"user_agent"`
	Path      string    `json:"path"`
	Method    string    `json:"method"`
	Timestamp time.Time `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// SecurityViolation represents a security policy violation
type SecurityViolation struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	ClientIP    string                 `json:"client_ip"`
	UserAgent   string                 `json:"user_agent"`
	Path        string                 `json:"path"`
	Method      string                 `json:"method"`
	Severity    string                 `json:"severity"`
	Blocked     bool                   `json:"blocked"`
	Details     map[string]interface{} `json:"details,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// NewSecurityMiddleware creates a new security middleware instance
func NewSecurityMiddleware(config SecurityConfig, logger SecurityLogger) *SecurityMiddleware {
	return &SecurityMiddleware{
		config: config,
		logger: logger,
	}
}

// ValidateContentType middleware validates request content type
func (sm *SecurityMiddleware) ValidateContentType() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Skip content type validation for GET, DELETE, HEAD methods
		if c.Request.Method == "GET" || c.Request.Method == "DELETE" || c.Request.Method == "HEAD" {
			c.Next()
			return
		}
		
		contentType := c.GetHeader("Content-Type")
		
		// Check if content type is required
		if sm.config.RequireContentType && contentType == "" {
			sm.handleSecurityViolation(c, SecurityViolation{
				Type:        "MISSING_CONTENT_TYPE",
				Description: "Content-Type header is required",
				Severity:    "medium",
				Blocked:     true,
			})
			return
		}
		
		// Validate against allowed content types
		if contentType != "" && len(sm.config.AllowedContentTypes) > 0 {
			allowed := false
			for _, allowedType := range sm.config.AllowedContentTypes {
				if strings.HasPrefix(contentType, allowedType) {
					allowed = true
					break
				}
			}
			
			if !allowed {
				sm.handleSecurityViolation(c, SecurityViolation{
					Type:        "INVALID_CONTENT_TYPE",
					Description: fmt.Sprintf("Content type '%s' is not allowed", contentType),
					Severity:    "medium",
					Blocked:     true,
					Details:     map[string]interface{}{"content_type": contentType},
				})
				return
			}
		}
		
		c.Next()
	})
}

// LimitRequestSize middleware limits the size of incoming requests
func (sm *SecurityMiddleware) LimitRequestSize() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		if c.Request.ContentLength > sm.config.MaxRequestSize {
			sm.handleSecurityViolation(c, SecurityViolation{
				Type:        "REQUEST_TOO_LARGE",
				Description: fmt.Sprintf("Request size %d bytes exceeds limit of %d bytes", c.Request.ContentLength, sm.config.MaxRequestSize),
				Severity:    "medium",
				Blocked:     true,
				Details:     map[string]interface{}{
					"content_length": c.Request.ContentLength,
					"max_size":      sm.config.MaxRequestSize,
				},
			})
			return
		}
		
		c.Next()
	})
}

// ValidateCharacterEncoding middleware validates request character encoding
func (sm *SecurityMiddleware) ValidateCharacterEncoding() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Check for suspicious encoding patterns
		userAgent := c.GetHeader("User-Agent")
		if sm.containsSuspiciousEncoding(userAgent) {
			sm.handleSecurityViolation(c, SecurityViolation{
				Type:        "SUSPICIOUS_ENCODING",
				Description: "Suspicious character encoding detected in User-Agent",
				Severity:    "high",
				Blocked:     true,
				Details:     map[string]interface{}{"user_agent": userAgent},
			})
			return
		}
		
		// Validate query parameters for suspicious encoding
		for key, values := range c.Request.URL.Query() {
			for _, value := range values {
				if sm.containsSuspiciousEncoding(value) {
					sm.handleSecurityViolation(c, SecurityViolation{
						Type:        "SUSPICIOUS_ENCODING",
						Description: fmt.Sprintf("Suspicious character encoding detected in query parameter '%s'", key),
						Severity:    "high",
						Blocked:     true,
						Details:     map[string]interface{}{"parameter": key, "value": value},
					})
					return
				}
			}
		}
		
		c.Next()
	})
}

// AddSecurityHeaders middleware adds security headers to responses
func (sm *SecurityMiddleware) AddSecurityHeaders() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		if sm.config.EnableSecurityHeaders {
			// Content Security Policy
			if sm.config.CSPPolicy != "" {
				c.Header("Content-Security-Policy", sm.config.CSPPolicy)
			}
			
			// X-Frame-Options
			if sm.config.FrameOptions != "" {
				c.Header("X-Frame-Options", sm.config.FrameOptions)
			} else {
				c.Header("X-Frame-Options", "DENY")
			}
			
			// X-Content-Type-Options
			if sm.config.ContentTypeOptions {
				c.Header("X-Content-Type-Options", "nosniff")
			}
			
			// X-XSS-Protection
			if sm.config.XSSProtection {
				c.Header("X-XSS-Protection", "1; mode=block")
			}
			
			// Strict-Transport-Security (HTTPS only)
			if c.Request.TLS != nil {
				c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			
			// Referrer Policy
			c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
			
			// Permissions Policy
			c.Header("Permissions-Policy", "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()")
		}
		
		c.Next()
	})
}

// ValidateHeaders middleware validates request headers for security threats
func (sm *SecurityMiddleware) ValidateHeaders() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		// Check header count
		if len(c.Request.Header) > sm.config.MaxQueryParams {
			sm.handleSecurityViolation(c, SecurityViolation{
				Type:        "TOO_MANY_HEADERS",
				Description: fmt.Sprintf("Request contains %d headers, exceeding limit of %d", len(c.Request.Header), sm.config.MaxQueryParams),
				Severity:    "medium",
				Blocked:     true,
			})
			return
		}
		
		// Check header sizes and content
		for name, values := range c.Request.Header {
			for _, value := range values {
				// Check header size
				if len(value) > sm.config.MaxHeaderSize {
					sm.handleSecurityViolation(c, SecurityViolation{
						Type:        "HEADER_TOO_LARGE",
						Description: fmt.Sprintf("Header '%s' size exceeds limit", name),
						Severity:    "medium",
						Blocked:     true,
						Details:     map[string]interface{}{"header": name, "size": len(value)},
					})
					return
				}
				
				// Check for suspicious content in headers
				if sm.config.BlockSuspiciousContent && sm.containsSuspiciousContent(value) {
					sm.handleSecurityViolation(c, SecurityViolation{
						Type:        "SUSPICIOUS_HEADER_CONTENT",
						Description: fmt.Sprintf("Suspicious content detected in header '%s'", name),
						Severity:    "high",
						Blocked:     true,
						Details:     map[string]interface{}{"header": name},
					})
					return
				}
			}
		}
		
		c.Next()
	})
}

// ValidateQueryParams middleware validates URL query parameters
func (sm *SecurityMiddleware) ValidateQueryParams() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {
		query := c.Request.URL.Query()
		
		// Check parameter count
		if len(query) > sm.config.MaxQueryParams {
			sm.handleSecurityViolation(c, SecurityViolation{
				Type:        "TOO_MANY_QUERY_PARAMS",
				Description: fmt.Sprintf("Request contains %d query parameters, exceeding limit of %d", len(query), sm.config.MaxQueryParams),
				Severity:    "medium",
				Blocked:     true,
			})
			return
		}
		
		// Validate each parameter
		for key, values := range query {
			for _, value := range values {
				// Check for suspicious content
				if sm.config.BlockSuspiciousContent && sm.containsSuspiciousContent(value) {
					sm.handleSecurityViolation(c, SecurityViolation{
						Type:        "SUSPICIOUS_QUERY_PARAM",
						Description: fmt.Sprintf("Suspicious content detected in query parameter '%s'", key),
						Severity:    "high",
						Blocked:     true,
						Details:     map[string]interface{}{"parameter": key},
					})
					return
				}
			}
		}
		
		c.Next()
	})
}

// handleSecurityViolation handles security violations
func (sm *SecurityMiddleware) handleSecurityViolation(c *gin.Context, violation SecurityViolation) {
	// Enrich violation with request context
	violation.ClientIP = c.ClientIP()
	violation.UserAgent = c.GetHeader("User-Agent")
	violation.Path = c.Request.URL.Path
	violation.Method = c.Request.Method
	violation.Timestamp = time.Now()
	
	// Log the violation
	if sm.logger != nil {
		sm.logger.LogSecurityViolation(violation)
	}
	
	// Determine response status code based on severity
	statusCode := http.StatusBadRequest
	switch violation.Severity {
	case "high", "critical":
		statusCode = http.StatusForbidden
	case "medium":
		statusCode = http.StatusBadRequest
	default:
		statusCode = http.StatusBadRequest
	}
	
	// Send error response
	c.JSON(statusCode, gin.H{
		"status":    "error",
		"code":      violation.Type,
		"message":   "Security policy violation",
		"timestamp": violation.Timestamp.Format(time.RFC3339),
	})
	c.Abort()
}

// Utility functions for security validation

func (sm *SecurityMiddleware) containsSuspiciousEncoding(input string) bool {
	// Check for multiple URL encoding layers
	if strings.Contains(input, "%25") {
		return true
	}
	
	// Check for Unicode encoding attacks
	suspiciousPatterns := []string{
		"\\u", "\\x", "%u", "&#x", "&#",
		"\ufeff", "\u200b", "\u200c", "\u200d",
	}
	
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(strings.ToLower(input), pattern) {
			return true
		}
	}
	
	return false
}

func (sm *SecurityMiddleware) containsSuspiciousContent(input string) bool {
	// Check for common attack patterns
	suspiciousPatterns := []string{
		"<script", "javascript:", "data:text/html",
		"eval(", "alert(", "confirm(", "prompt(",
		"union select", "drop table", "delete from",
		"../", ".\\", "file://", "ftp://",
		"<?php", "<%", "${", "{{",
	}
	
	lowerInput := strings.ToLower(input)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(lowerInput, pattern) {
			return true
		}
	}
	
	return false
}

// DefaultSecurityConfig returns default security configuration
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		AllowedContentTypes: []string{
			"application/json",
			"application/x-www-form-urlencoded",
			"multipart/form-data",
			"text/plain",
		},
		MaxRequestSize:         1024 * 1024, // 1MB
		RequireContentType:     true,
		EnableSecurityHeaders:  true,
		CSPPolicy:             "default-src 'self'",
		FrameOptions:          "DENY",
		ContentTypeOptions:    true,
		XSSProtection:         true,
		EnableCSRF:            true,
		CSRFTokenHeader:       "X-CSRF-Token",
		CSRFCookieName:        "csrf-token",
		EnableRateLimit:       true,
		RequestsPerMinute:     60,
		BurstSize:            10,
		BlockSuspiciousContent: true,
		MaxHeaderSize:         8192,  // 8KB
		MaxQueryParams:        50,
	}
}