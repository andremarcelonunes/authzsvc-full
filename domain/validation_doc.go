// Package domain contains the validation system implementation for CB-182
// Comprehensive Input Validation following Clean Architecture + Hexagonal Pattern
//
// The validation system provides multiple layers of input validation:
//
// 1. Field Validation: Individual field constraints (type, length, format)
// 2. Cross-Field Validation: Multi-field relationships and dependencies  
// 3. Security Validation: XSS, SQL injection, and threat detection
// 4. Business Rule Validation: Domain-specific constraints and workflows
// 5. Rate Limiting: Brute force protection and request throttling
//
// Architecture Overview:
//
//	┌─────────────────────────────────────────────────────────────┐
//	│                    Domain Layer (Core)                      │
//	│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
//	│  │ Validation      │  │ Validation      │  │ Security     │ │
//	│  │ Entities        │  │ Interfaces      │  │ Violations   │ │
//	│  │                 │  │                 │  │              │ │
//	│  │ • Rules         │  │ • Validators    │  │ • Threats    │ │
//	│  │ • Constraints   │  │ • Repositories  │  │ • Actions    │ │
//	│  │ • Results       │  │ • Handlers      │  │ • Auditing   │ │
//	│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
//	└─────────────────────────────────────────────────────────────┘
//	                                │
//	                                ▼
//	┌─────────────────────────────────────────────────────────────┐
//	│              Application Services Layer                      │
//	│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
//	│  │ Request         │  │ Security        │  │ Business     │ │
//	│  │ Validator       │  │ Validator       │  │ Validator    │ │
//	│  │ Service         │  │ Service         │  │ Service      │ │
//	│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
//	└─────────────────────────────────────────────────────────────┘
//	                                │
//	                                ▼
//	┌─────────────────────────────────────────────────────────────┐
//	│               Infrastructure Layer                           │
//	│  ┌─────────────────┐  ┌─────────────────┐  ┌──────────────┐ │
//	│  │ GORM            │  │ Redis           │  │ HTTP         │ │
//	│  │ Repositories    │  │ Cache           │  │ Handlers     │ │
//	│  │                 │  │                 │  │              │ │
//	│  │ • Rules DB      │  │ • Rate Limits   │  │ • Middleware │ │
//	│  │ • Violations    │  │ • Results Cache │  │ • Responses  │ │
//	│  │ • Audit Logs    │  │ • Block Lists   │  │ • Validation │ │
//	│  └─────────────────┘  └─────────────────┘  └──────────────┘ │
//	└─────────────────────────────────────────────────────────────┘
//
// Core Components:
//
// ValidationContext: Provides comprehensive context for validation operations
// including user information, request metadata, session data, and security context.
//
// ValidationRule: Defines validation constraints with support for field constraints,
// cross-field validation, security rules, and business constraints.
//
// ValidationResult: Contains comprehensive validation outcomes including errors,
// warnings, security analysis, and performance metrics.
//
// Security Features:
//
// • XSS (Cross-Site Scripting) detection and prevention
// • SQL injection pattern detection  
// • Script injection blocking
// • Malicious pattern scanning
// • Content sanitization and encoding validation
// • Threat level classification and response actions
//
// Rate Limiting:
//
// • Fixed window rate limiting
// • Sliding window rate limiting  
// • Token bucket algorithm support
// • Brute force attack detection
// • IP and user-based blocking
// • Graceful degradation under load
//
// Business Rules:
//
// • Domain-specific validation constraints
// • Workflow state validation
// • Resource quota and limit enforcement
// • Time window restrictions
// • Recurrence rule validation
// • Custom validation logic support
//
// Error Handling:
//
// The validation system provides structured error responses with:
// • Severity levels (info, warning, error, critical)
// • Detailed field-level error information
// • Localization support for error messages
// • Security violation detailed reporting
// • Standardized API error responses
//
// Performance Considerations:
//
// • Validation rule caching for improved performance
// • Batch validation support for multiple requests
// • Configurable validation timeouts
// • Database connection pooling for rule storage
// • Redis caching for rate limiting and results
//
// Usage Examples:
//
// Basic field validation:
//	validator := NewRequestValidator(...)
//	result, err := validator.ValidateField(ctx, "email", userEmail, emailConstraints)
//
// Security validation:
//	secValidator := NewSecurityValidator(...)
//	result, err := secValidator.ScanForThreats(ctx, userInput, securityRules)
//
// Rate limiting:
//	rateLimiter := NewRateLimitValidator(...)
//	result, err := rateLimiter.CheckRateLimit(ctx, userKey, maxRequests, timeWindow)
//
// Business rule validation:
//	bizValidator := NewBusinessRuleValidator(...)
//	result, err := bizValidator.ValidateBusinessRules(ctx, order, businessConstraints)
//
// Integration with Existing Services:
//
// The validation system integrates seamlessly with existing authentication
// and authorization services, providing additional security layers without
// disrupting current functionality.
//
// SOLID Principles Applied:
//
// • Single Responsibility: Each validator handles specific validation concerns
// • Open/Closed: New validation rules can be added without modifying existing code
// • Liskov Substitution: All validator implementations are interchangeable
// • Interface Segregation: Focused interfaces for specific validation needs
// • Dependency Inversion: Depends on abstractions, not concrete implementations
//
// Thread Safety:
//
// All validation operations are designed to be thread-safe and can handle
// concurrent requests without data races or inconsistencies.
//
package domain