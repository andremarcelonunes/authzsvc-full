package domain

import (
	"fmt"
	"regexp"
	"time"
)

// ValidationContext provides comprehensive context for validation operations
// Includes user information, request metadata, and security context
type ValidationContext struct {
	// User context
	UserID       *uint  `json:"user_id,omitempty"`
	Role         string `json:"role,omitempty"`
	IsAnonymous  bool   `json:"is_anonymous"`
	
	// Request context
	RequestID    string            `json:"request_id"`
	Endpoint     string            `json:"endpoint"`
	Method       string            `json:"method"`
	Headers      map[string]string `json:"headers,omitempty"`
	IPAddress    string            `json:"ip_address"`
	UserAgent    string            `json:"user_agent,omitempty"`
	
	// Session context
	SessionID    string    `json:"session_id,omitempty"`
	SessionStart time.Time `json:"session_start,omitempty"`
	
	// Security context
	RateLimit    *RateLimitContext `json:"rate_limit,omitempty"`
	Timestamp    time.Time         `json:"timestamp"`
}

// RateLimitContext holds rate limiting information
type RateLimitContext struct {
	Key           string        `json:"key"`
	WindowSize    time.Duration `json:"window_size"`
	MaxRequests   int           `json:"max_requests"`
	CurrentCount  int           `json:"current_count"`
	ResetTime     time.Time     `json:"reset_time"`
	IsBlocked     bool          `json:"is_blocked"`
}

// ValidationRule defines validation constraints for a specific field or operation
type ValidationRule struct {
	ID          string                 `json:"id" gorm:"primaryKey"`
	Name        string                 `json:"name" gorm:"not null;index"`
	Description string                 `json:"description"`
	
	// Rule classification
	Category    ValidationCategory     `json:"category" gorm:"not null;index"`
	Severity    ValidationSeverity     `json:"severity" gorm:"not null"`
	
	// Field constraints
	FieldName   string                 `json:"field_name,omitempty"`
	Required    bool                   `json:"required"`
	Constraint  *FieldConstraint       `json:"constraint,omitempty" gorm:"embedded;embeddedPrefix:constraint_"`
	
	// Cross-field validation
	CrossField  *CrossFieldConstraint  `json:"cross_field,omitempty" gorm:"embedded;embeddedPrefix:cross_field_"`
	
	// Security rules
	SecurityRule *SecurityConstraint   `json:"security_rule,omitempty" gorm:"embedded;embeddedPrefix:security_"`
	
	// Business rules
	BusinessRule *BusinessConstraint   `json:"business_rule,omitempty" gorm:"embedded;embeddedPrefix:business_"`
	
	// Rule metadata
	IsActive    bool                   `json:"is_active" gorm:"default:true"`
	Priority    int                    `json:"priority" gorm:"default:100"`
	Tags        []string               `json:"tags" gorm:"type:text[]"`
	Parameters  map[string]interface{} `json:"parameters" gorm:"type:jsonb"`
	
	// Audit fields
	CreatedAt   time.Time              `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   time.Time              `json:"updated_at" gorm:"autoUpdateTime"`
	CreatedBy   string                 `json:"created_by,omitempty"`
	UpdatedBy   string                 `json:"updated_by,omitempty"`
}

// ValidationCategory defines the type of validation rule
type ValidationCategory string

const (
	CategoryField      ValidationCategory = "field"       // Individual field validation
	CategoryCrossField ValidationCategory = "cross_field" // Multi-field validation
	CategorySecurity   ValidationCategory = "security"    // Security validation
	CategoryBusiness   ValidationCategory = "business"    // Business rule validation
	CategoryRateLimit  ValidationCategory = "rate_limit"  // Rate limiting validation
)

// ValidationSeverity defines the importance level of validation violations
type ValidationSeverity string

const (
	SeverityInfo     ValidationSeverity = "info"     // Informational, non-blocking
	SeverityWarning  ValidationSeverity = "warning"  // Warning, may continue
	SeverityError    ValidationSeverity = "error"    // Error, blocks request
	SeverityCritical ValidationSeverity = "critical" // Critical security violation
)

// FieldConstraint defines validation constraints for individual fields
type FieldConstraint struct {
	// Data type constraints
	DataType     string      `json:"data_type"`
	Format       string      `json:"format,omitempty"`
	
	// String constraints
	MinLength    *int        `json:"min_length,omitempty"`
	MaxLength    *int        `json:"max_length,omitempty"`
	Pattern      string      `json:"pattern,omitempty"`
	RegexCompiled *regexp.Regexp `json:"-" gorm:"-"`
	
	// Numeric constraints
	MinValue     *float64    `json:"min_value,omitempty"`
	MaxValue     *float64    `json:"max_value,omitempty"`
	
	// Collection constraints
	AllowedValues []string   `json:"allowed_values,omitempty" gorm:"type:text[]"`
	ForbiddenValues []string `json:"forbidden_values,omitempty" gorm:"type:text[]"`
	
	// Content constraints
	AllowHTML    bool        `json:"allow_html"`
	AllowScripts bool        `json:"allow_scripts"`
	SanitizeHTML bool        `json:"sanitize_html"`
	
	// Custom validation
	CustomValidator string   `json:"custom_validator,omitempty"`
}

// CrossFieldConstraint defines validation rules that span multiple fields
type CrossFieldConstraint struct {
	// Field relationships
	DependentFields []string           `json:"dependent_fields" gorm:"type:text[]"`
	ConditionalRules map[string]string `json:"conditional_rules" gorm:"type:jsonb"`
	
	// Comparison operations
	CompareOperation string            `json:"compare_operation,omitempty"`
	CompareField     string            `json:"compare_field,omitempty"`
	
	// Date/time relationships
	DateConstraint   *DateConstraint   `json:"date_constraint,omitempty" gorm:"embedded;embeddedPrefix:date_"`
	
	// Custom cross-field logic
	ValidationLogic  string            `json:"validation_logic,omitempty"`
}

// DateConstraint defines date/time validation rules
type DateConstraint struct {
	MinDate       *time.Time `json:"min_date,omitempty"`
	MaxDate       *time.Time `json:"max_date,omitempty"`
	FutureOnly    bool       `json:"future_only"`
	PastOnly      bool       `json:"past_only"`
	BusinessDays  bool       `json:"business_days_only"`
	ExcludeWeekends bool     `json:"exclude_weekends"`
}

// SecurityConstraint defines security-specific validation rules
type SecurityConstraint struct {
	// Input sanitization
	XSSProtection     bool     `json:"xss_protection"`
	SQLInjectionCheck bool     `json:"sql_injection_check"`
	ScriptInjectionCheck bool  `json:"script_injection_check"`
	
	// Content filtering
	BlockedPatterns   []string `json:"blocked_patterns" gorm:"type:text[]"`
	AllowedPatterns   []string `json:"allowed_patterns" gorm:"type:text[]"`
	
	// Encoding validation
	RequireEncoding   string   `json:"require_encoding,omitempty"`
	MaxEncodingLayers int      `json:"max_encoding_layers"`
	
	// Threat detection
	ThreatScanEnabled bool     `json:"threat_scan_enabled"`
	VirusScanEnabled  bool     `json:"virus_scan_enabled"`
}

// BusinessConstraint defines business-specific validation rules
type BusinessConstraint struct {
	// Domain validation
	DomainRules      []string           `json:"domain_rules" gorm:"type:text[]"`
	WorkflowState    string             `json:"workflow_state,omitempty"`
	
	// Resource validation
	ResourceLimits   map[string]int     `json:"resource_limits" gorm:"type:jsonb"`
	QuotaCheck       bool               `json:"quota_check"`
	
	// Temporal constraints
	TimeWindows      []TimeWindow       `json:"time_windows" gorm:"type:jsonb"`
	RecurrenceRules  string             `json:"recurrence_rules,omitempty"`
}

// TimeWindow defines allowed time periods for operations
type TimeWindow struct {
	StartTime time.Time `json:"start_time"`
	EndTime   time.Time `json:"end_time"`
	Timezone  string    `json:"timezone"`
	Recurring bool      `json:"recurring"`
}

// ValidationResult represents the outcome of validation operations
type ValidationResult struct {
	// Overall validation status
	IsValid     bool               `json:"is_valid"`
	Passed      bool               `json:"passed"`
	
	// Validation errors and warnings
	Errors      []ValidationError  `json:"errors,omitempty"`
	Warnings    []ValidationError  `json:"warnings,omitempty"`
	
	// Field-specific results
	FieldResults map[string]FieldValidationResult `json:"field_results,omitempty"`
	
	// Security analysis
	SecurityResult *SecurityValidationResult `json:"security_result,omitempty"`
	
	// Performance metrics
	ValidationTime time.Duration    `json:"validation_time"`
	RulesApplied   int              `json:"rules_applied"`
	
	// Metadata
	ValidationID   string           `json:"validation_id"`
	Timestamp      time.Time        `json:"timestamp"`
	Context        *ValidationContext `json:"context,omitempty"`
}

// FieldValidationResult contains validation results for a specific field
type FieldValidationResult struct {
	FieldName    string            `json:"field_name"`
	IsValid      bool              `json:"is_valid"`
	OriginalValue interface{}      `json:"original_value,omitempty"`
	SanitizedValue interface{}     `json:"sanitized_value,omitempty"`
	Errors       []ValidationError `json:"errors,omitempty"`
	Warnings     []ValidationError `json:"warnings,omitempty"`
	AppliedRules []string          `json:"applied_rules,omitempty"`
}

// SecurityValidationResult contains security-specific validation results
type SecurityValidationResult struct {
	ThreatLevel    ThreatLevel       `json:"threat_level"`
	ThreatTypes    []ThreatType      `json:"threat_types,omitempty"`
	Violations     []SecurityViolation `json:"violations,omitempty"`
	SanitizedInput map[string]interface{} `json:"sanitized_input,omitempty"`
	BlockedContent []string          `json:"blocked_content,omitempty"`
	ScanResults    map[string]interface{} `json:"scan_results,omitempty"`
}

// ThreatLevel defines the severity of security threats
type ThreatLevel string

const (
	ThreatNone     ThreatLevel = "none"
	ThreatLow      ThreatLevel = "low"
	ThreatMedium   ThreatLevel = "medium"
	ThreatHigh     ThreatLevel = "high"
	ThreatCritical ThreatLevel = "critical"
)

// ThreatType categorizes different types of security threats
type ThreatType string

const (
	ThreatXSS           ThreatType = "xss"
	ThreatSQLInjection  ThreatType = "sql_injection"
	ThreatScriptInjection ThreatType = "script_injection"
	ThreatPathTraversal ThreatType = "path_traversal"
	ThreatMalware       ThreatType = "malware"
	ThreatPhishing      ThreatType = "phishing"
	ThreatBruteForce    ThreatType = "brute_force"
	ThreatDOS           ThreatType = "denial_of_service"
)

// SecurityViolation represents a specific security rule violation
type SecurityViolation struct {
	ID           string                 `json:"id" gorm:"primaryKey"`
	Type         ThreatType             `json:"type" gorm:"not null;index"`
	Severity     ValidationSeverity     `json:"severity" gorm:"not null"`
	Description  string                 `json:"description" gorm:"not null"`
	
	// Violation context
	FieldName    string                 `json:"field_name,omitempty"`
	Pattern      string                 `json:"pattern,omitempty"`
	Value        string                 `json:"value,omitempty"`
	Context      map[string]interface{} `json:"context" gorm:"type:jsonb"`
	
	// Risk assessment
	RiskScore    float64                `json:"risk_score"`
	Confidence   float64                `json:"confidence"`
	
	// Response actions
	Action       ViolationAction        `json:"action" gorm:"not null"`
	Blocked      bool                   `json:"blocked"`
	Sanitized    bool                   `json:"sanitized"`
	
	// Audit information
	UserID       *uint                  `json:"user_id,omitempty" gorm:"index"`
	IPAddress    string                 `json:"ip_address" gorm:"index"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	RequestID    string                 `json:"request_id" gorm:"index"`
	Timestamp    time.Time              `json:"timestamp" gorm:"autoCreateTime;index"`
	
	// Metadata
	Metadata     map[string]interface{} `json:"metadata" gorm:"type:jsonb"`
}

// ViolationAction defines how to respond to security violations
type ViolationAction string

const (
	ActionLog       ViolationAction = "log"        // Log violation only
	ActionWarn      ViolationAction = "warn"       // Log and warn user
	ActionSanitize  ViolationAction = "sanitize"   // Clean the input
	ActionBlock     ViolationAction = "block"      // Block the request
	ActionAlert     ViolationAction = "alert"      // Send security alert
	ActionBan       ViolationAction = "ban"        // Ban the user/IP
)

// ValidationError represents a structured validation error
type ValidationError struct {
	Code        string                 `json:"code"`
	Field       string                 `json:"field,omitempty"`
	Message     string                 `json:"message"`
	Severity    ValidationSeverity     `json:"severity"`
	Category    ValidationCategory     `json:"category"`
	
	// Error context
	Value       interface{}            `json:"value,omitempty"`
	Expected    interface{}            `json:"expected,omitempty"`
	Constraint  string                 `json:"constraint,omitempty"`
	
	// Additional information
	Suggestions []string               `json:"suggestions,omitempty"`
	HelpURL     string                 `json:"help_url,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	
	// Audit information
	Timestamp   time.Time              `json:"timestamp"`
	RuleID      string                 `json:"rule_id,omitempty"`
}

// TableName returns the table name for ValidationRule GORM model
func (ValidationRule) TableName() string {
	return "validation_rules"
}

// TableName returns the table name for SecurityViolation GORM model  
func (SecurityViolation) TableName() string {
	return "security_violations"
}

// Error implements the error interface for ValidationError
func (ve ValidationError) Error() string {
	if ve.Field != "" {
		return fmt.Sprintf("%s: %s (field: %s)", ve.Code, ve.Message, ve.Field)
	}
	return fmt.Sprintf("%s: %s", ve.Code, ve.Message)
}