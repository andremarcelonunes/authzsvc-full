package services

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/you/authzsvc/domain"
)

// SecurityValidationServiceImpl implements domain.SecurityValidationService
type SecurityValidationServiceImpl struct {
	violationRepo domain.SecurityViolationRepository
	logger        *slog.Logger
	
	// Security patterns for threat detection
	xssPatterns           []*regexp.Regexp
	sqlInjectionPatterns  []*regexp.Regexp
	scriptPatterns        []*regexp.Regexp
	pathTraversalPatterns []*regexp.Regexp
	
	// Configuration
	enableRealTimeScanning bool
	maxInputSize          int
	sanitizationLevel     string
}

// SecurityValidationConfig holds configuration for security validation
type SecurityValidationConfig struct {
	EnableRealTimeScanning bool
	MaxInputSize          int
	SanitizationLevel     string // "strict", "moderate", "lenient"
}

// NewSecurityValidationService creates a new security validation service
func NewSecurityValidationService(
	violationRepo domain.SecurityViolationRepository,
	config SecurityValidationConfig,
) domain.SecurityValidationService {
	if config.MaxInputSize == 0 {
		config.MaxInputSize = 1024 * 1024 // 1MB default
	}
	if config.SanitizationLevel == "" {
		config.SanitizationLevel = "moderate"
	}

	service := &SecurityValidationServiceImpl{
		violationRepo:         violationRepo,
		logger:               slog.Default(),
		enableRealTimeScanning: config.EnableRealTimeScanning,
		maxInputSize:         config.MaxInputSize,
		sanitizationLevel:    config.SanitizationLevel,
	}

	// Initialize security patterns
	service.initializeSecurityPatterns()

	return service
}

// ScanForThreats performs comprehensive threat scanning on input data
func (s *SecurityValidationServiceImpl) ScanForThreats(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (*domain.SecurityValidationResult, error) {
	startTime := time.Now()
	
	result := &domain.SecurityValidationResult{
		ThreatLevel:    domain.ThreatNone,
		ThreatTypes:    []domain.ThreatType{},
		Violations:     []domain.SecurityViolation{},
		SanitizedInput: make(map[string]interface{}),
		BlockedContent: []string{},
		ScanResults:    make(map[string]interface{}),
	}

	// Copy input for sanitization
	for key, value := range input {
		result.SanitizedInput[key] = value
	}

	// Process each rule
	for _, rule := range rules {
		if err := s.processSecurityRule(ctx, input, rule, result); err != nil {
			return nil, fmt.Errorf("error processing security rule: %w", err)
		}
	}

	// Scan each input field
	for fieldName, value := range input {
		fieldStr := fmt.Sprintf("%v", value)
		
		// Check input size limits
		if len(fieldStr) > s.maxInputSize {
			violation := s.createViolation(
				domain.ThreatDOS,
				domain.SeverityError,
				"Input size exceeds maximum allowed length",
				fieldName,
				fieldStr[:100]+"...", // Truncate for logging
				ctx,
			)
			result.Violations = append(result.Violations, *violation)
			result.ThreatLevel = s.escalateThreatLevel(result.ThreatLevel, domain.ThreatHigh)
			result.ThreatTypes = append(result.ThreatTypes, domain.ThreatDOS)
			continue
		}

		// XSS Detection
		if xssResult, err := s.DetectXSS(ctx, fieldStr); err != nil {
			return nil, fmt.Errorf("XSS detection failed for field %s: %w", fieldName, err)
		} else if xssResult.ThreatLevel != domain.ThreatNone {
			result.ThreatLevel = s.escalateThreatLevel(result.ThreatLevel, xssResult.ThreatLevel)
			result.ThreatTypes = s.mergeThreatTypes(result.ThreatTypes, xssResult.ThreatTypes)
			result.Violations = append(result.Violations, xssResult.Violations...)
		}

		// SQL Injection Detection
		if sqlResult, err := s.DetectSQLInjection(ctx, fieldStr); err != nil {
			return nil, fmt.Errorf("SQL injection detection failed for field %s: %w", fieldName, err)
		} else if sqlResult.ThreatLevel != domain.ThreatNone {
			result.ThreatLevel = s.escalateThreatLevel(result.ThreatLevel, sqlResult.ThreatLevel)
			result.ThreatTypes = s.mergeThreatTypes(result.ThreatTypes, sqlResult.ThreatTypes)
			result.Violations = append(result.Violations, sqlResult.Violations...)
		}

		// Script Injection Detection
		if scriptResult, err := s.DetectScriptInjection(ctx, fieldStr); err != nil {
			return nil, fmt.Errorf("script injection detection failed for field %s: %w", fieldName, err)
		} else if scriptResult.ThreatLevel != domain.ThreatNone {
			result.ThreatLevel = s.escalateThreatLevel(result.ThreatLevel, scriptResult.ThreatLevel)
			result.ThreatTypes = s.mergeThreatTypes(result.ThreatTypes, scriptResult.ThreatTypes)
			result.Violations = append(result.Violations, scriptResult.Violations...)
		}

		// Path Traversal Detection
		if s.detectPathTraversal(fieldStr) {
			violation := s.createViolation(
				domain.ThreatPathTraversal,
				domain.SeverityError,
				"Path traversal attempt detected",
				fieldName,
				fieldStr,
				ctx,
			)
			result.Violations = append(result.Violations, *violation)
			result.ThreatLevel = s.escalateThreatLevel(result.ThreatLevel, domain.ThreatMedium)
			result.ThreatTypes = append(result.ThreatTypes, domain.ThreatPathTraversal)
		}
	}

	// Log scan results
	s.logger.Info("Security scan completed",
		"threat_level", result.ThreatLevel,
		"violations_count", len(result.Violations),
		"scan_duration_ms", time.Since(startTime).Milliseconds(),
	)

	// Record violations in repository
	for _, violation := range result.Violations {
		if err := s.RecordViolation(ctx, &violation); err != nil {
			s.logger.Error("Failed to record security violation", "error", err)
		}
	}

	return result, nil
}

// DetectXSS detects cross-site scripting attempts
func (s *SecurityValidationServiceImpl) DetectXSS(ctx context.Context, input string) (*domain.SecurityValidationResult, error) {
	result := &domain.SecurityValidationResult{
		ThreatLevel: domain.ThreatNone,
		ThreatTypes: []domain.ThreatType{},
		Violations:  []domain.SecurityViolation{},
	}

	inputLower := strings.ToLower(input)

	// Check for XSS patterns
	for _, pattern := range s.xssPatterns {
		if pattern.MatchString(inputLower) {
			violation := s.createViolation(
				domain.ThreatXSS,
				domain.SeverityError,
				"Cross-site scripting attempt detected",
				"",
				input,
				ctx,
			)
			
			result.Violations = append(result.Violations, *violation)
			result.ThreatLevel = domain.ThreatHigh
			result.ThreatTypes = append(result.ThreatTypes, domain.ThreatXSS)
			
			s.logger.Warn("XSS attempt detected",
				"pattern", pattern.String(),
				"input_sample", s.truncateInput(input, 100),
			)
			break
		}
	}

	return result, nil
}

// DetectSQLInjection detects SQL injection attempts
func (s *SecurityValidationServiceImpl) DetectSQLInjection(ctx context.Context, input string) (*domain.SecurityValidationResult, error) {
	result := &domain.SecurityValidationResult{
		ThreatLevel: domain.ThreatNone,
		ThreatTypes: []domain.ThreatType{},
		Violations:  []domain.SecurityViolation{},
	}

	inputLower := strings.ToLower(input)

	// Check for SQL injection patterns
	for _, pattern := range s.sqlInjectionPatterns {
		if pattern.MatchString(inputLower) {
			violation := s.createViolation(
				domain.ThreatSQLInjection,
				domain.SeverityError,
				"SQL injection attempt detected",
				"",
				input,
				ctx,
			)
			
			result.Violations = append(result.Violations, *violation)
			result.ThreatLevel = domain.ThreatCritical
			result.ThreatTypes = append(result.ThreatTypes, domain.ThreatSQLInjection)
			
			s.logger.Warn("SQL injection attempt detected",
				"pattern", pattern.String(),
				"input_sample", s.truncateInput(input, 100),
			)
			break
		}
	}

	return result, nil
}

// DetectScriptInjection detects script injection attempts
func (s *SecurityValidationServiceImpl) DetectScriptInjection(ctx context.Context, input string) (*domain.SecurityValidationResult, error) {
	result := &domain.SecurityValidationResult{
		ThreatLevel: domain.ThreatNone,
		ThreatTypes: []domain.ThreatType{},
		Violations:  []domain.SecurityViolation{},
	}

	inputLower := strings.ToLower(input)

	// Check for script injection patterns
	for _, pattern := range s.scriptPatterns {
		if pattern.MatchString(inputLower) {
			violation := s.createViolation(
				domain.ThreatScriptInjection,
				domain.SeverityError,
				"Script injection attempt detected",
				"",
				input,
				ctx,
			)
			
			result.Violations = append(result.Violations, *violation)
			result.ThreatLevel = domain.ThreatHigh
			result.ThreatTypes = append(result.ThreatTypes, domain.ThreatScriptInjection)
			
			s.logger.Warn("Script injection attempt detected",
				"pattern", pattern.String(),
				"input_sample", s.truncateInput(input, 100),
			)
			break
		}
	}

	return result, nil
}

// SanitizeInput sanitizes input data according to security rules
func (s *SecurityValidationServiceImpl) SanitizeInput(ctx context.Context, input map[string]interface{}, rules []domain.SecurityConstraint) (map[string]interface{}, error) {
	sanitized := make(map[string]interface{})

	for key, value := range input {
		strValue := fmt.Sprintf("%v", value)
		
		// Apply sanitization based on level
		switch s.sanitizationLevel {
		case "strict":
			sanitized[key] = s.strictSanitize(strValue)
		case "moderate":
			sanitized[key] = s.moderateSanitize(strValue)
		case "lenient":
			sanitized[key] = s.lenientSanitize(strValue)
		default:
			sanitized[key] = s.moderateSanitize(strValue)
		}
	}

	return sanitized, nil
}

// SanitizeHTML sanitizes HTML content
func (s *SecurityValidationServiceImpl) SanitizeHTML(ctx context.Context, html string) (string, error) {
	// Remove dangerous tags and attributes
	sanitized := html
	
	// Remove script tags
	scriptPattern := regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`)
	sanitized = scriptPattern.ReplaceAllString(sanitized, "")
	
	// Remove style tags
	stylePattern := regexp.MustCompile(`(?i)<style[^>]*>.*?</style>`)
	sanitized = stylePattern.ReplaceAllString(sanitized, "")
	
	// Remove javascript: protocols
	jsPattern := regexp.MustCompile(`(?i)javascript:`)
	sanitized = jsPattern.ReplaceAllString(sanitized, "")
	
	// Remove on* event handlers
	eventPattern := regexp.MustCompile(`(?i)\s+on\w+\s*=\s*[^>]*`)
	sanitized = eventPattern.ReplaceAllString(sanitized, "")

	return sanitized, nil
}

// RecordViolation records a security violation
func (s *SecurityValidationServiceImpl) RecordViolation(ctx context.Context, violation *domain.SecurityViolation) error {
	if s.violationRepo == nil {
		s.logger.Warn("Security violation repository not available, skipping violation recording")
		return nil
	}

	// Set violation ID if not set
	if violation.ID == "" {
		violation.ID = fmt.Sprintf("viol_%d", time.Now().UnixNano())
	}

	return s.violationRepo.RecordViolation(ctx, violation)
}

// GetViolationHistory retrieves violation history for a user
func (s *SecurityValidationServiceImpl) GetViolationHistory(ctx context.Context, userID uint, timeWindow time.Duration) ([]domain.SecurityViolation, error) {
	if s.violationRepo == nil {
		return []domain.SecurityViolation{}, fmt.Errorf("security violation repository not available")
	}

	return s.violationRepo.GetViolationsByUser(ctx, userID, 100, 0)
}

// Helper methods

func (s *SecurityValidationServiceImpl) initializeSecurityPatterns() {
	// XSS patterns
	xssPatterns := []string{
		`<script[^>]*>.*?</script>`,
		`javascript:`,
		`vbscript:`,
		`onload\s*=`,
		`onerror\s*=`,
		`onclick\s*=`,
		`onmouseover\s*=`,
		`<iframe`,
		`<object`,
		`<embed`,
		`<link.*stylesheet`,
		`<meta.*refresh`,
		`eval\s*\(`,
		`expression\s*\(`,
		`document\.cookie`,
		`document\.write`,
		`window\.location`,
	}

	s.xssPatterns = make([]*regexp.Regexp, len(xssPatterns))
	for i, pattern := range xssPatterns {
		s.xssPatterns[i] = regexp.MustCompile(`(?i)` + pattern)
	}

	// SQL injection patterns
	sqlPatterns := []string{
		`union\s+select`,
		`drop\s+table`,
		`delete\s+from`,
		`insert\s+into`,
		`update\s+.*\s+set`,
		`or\s+1\s*=\s*1`,
		`and\s+1\s*=\s*1`,
		`';\s*(drop|delete|insert|update)`,
		`--\s*$`,
		`/\*.*\*/`,
		`concat\s*\(`,
		`char\s*\(`,
		`ascii\s*\(`,
		`substring\s*\(`,
		`waitfor\s+delay`,
		`benchmark\s*\(`,
		`sleep\s*\(`,
		`pg_sleep\s*\(`,
	}

	s.sqlInjectionPatterns = make([]*regexp.Regexp, len(sqlPatterns))
	for i, pattern := range sqlPatterns {
		s.sqlInjectionPatterns[i] = regexp.MustCompile(`(?i)` + pattern)
	}

	// Script injection patterns
	scriptPatterns := []string{
		`<script`,
		`</script>`,
		`javascript:`,
		`vbscript:`,
		`data:text/html`,
		`data:application`,
		`%3Cscript`,
		`%3C/script%3E`,
		`&lt;script`,
		`&lt;/script&gt;`,
	}

	s.scriptPatterns = make([]*regexp.Regexp, len(scriptPatterns))
	for i, pattern := range scriptPatterns {
		s.scriptPatterns[i] = regexp.MustCompile(`(?i)` + pattern)
	}

	// Path traversal patterns
	pathTraversalPatterns := []string{
		`\.\.\/`,
		`\.\.\\`,
		`%2e%2e%2f`,
		`%2e%2e%5c`,
		`..%2f`,
		`..%5c`,
		`%252e%252e%252f`,
		`%c0%ae%c0%ae%c0%af`,
	}

	s.pathTraversalPatterns = make([]*regexp.Regexp, len(pathTraversalPatterns))
	for i, pattern := range pathTraversalPatterns {
		s.pathTraversalPatterns[i] = regexp.MustCompile(`(?i)` + pattern)
	}
}

func (s *SecurityValidationServiceImpl) processSecurityRule(ctx context.Context, input map[string]interface{}, rule domain.SecurityConstraint, result *domain.SecurityValidationResult) error {
	// TODO: Process specific security rules based on constraint configuration
	return nil
}

func (s *SecurityValidationServiceImpl) detectPathTraversal(input string) bool {
	for _, pattern := range s.pathTraversalPatterns {
		if pattern.MatchString(input) {
			return true
		}
	}
	return false
}

func (s *SecurityValidationServiceImpl) createViolation(threatType domain.ThreatType, severity domain.ValidationSeverity, description, fieldName, value string, ctx context.Context) *domain.SecurityViolation {
	violation := &domain.SecurityViolation{
		ID:          fmt.Sprintf("viol_%d", time.Now().UnixNano()),
		Type:        threatType,
		Severity:    severity,
		Description: description,
		FieldName:   fieldName,
		Value:       s.truncateInput(value, 500),
		RiskScore:   s.calculateRiskScore(threatType, severity),
		Confidence:  0.85, // Default confidence
		Action:      s.determineAction(threatType, severity),
		Blocked:     s.shouldBlock(threatType, severity),
		Sanitized:   false,
		Timestamp:   time.Now(),
	}

	// Add metadata
	violation.Metadata = make(map[string]interface{})
	violation.Metadata["detection_method"] = "pattern_matching"
	violation.Metadata["sanitization_level"] = s.sanitizationLevel

	return violation
}

func (s *SecurityValidationServiceImpl) escalateThreatLevel(current, detected domain.ThreatLevel) domain.ThreatLevel {
	levels := map[domain.ThreatLevel]int{
		domain.ThreatNone:     0,
		domain.ThreatLow:      1,
		domain.ThreatMedium:   2,
		domain.ThreatHigh:     3,
		domain.ThreatCritical: 4,
	}

	if levels[detected] > levels[current] {
		return detected
	}
	return current
}

func (s *SecurityValidationServiceImpl) mergeThreatTypes(existing, new []domain.ThreatType) []domain.ThreatType {
	threatMap := make(map[domain.ThreatType]bool)
	
	// Add existing threats
	for _, threat := range existing {
		threatMap[threat] = true
	}
	
	// Add new threats
	for _, threat := range new {
		threatMap[threat] = true
	}
	
	// Convert back to slice
	result := make([]domain.ThreatType, 0, len(threatMap))
	for threat := range threatMap {
		result = append(result, threat)
	}
	
	return result
}

func (s *SecurityValidationServiceImpl) calculateRiskScore(threatType domain.ThreatType, severity domain.ValidationSeverity) float64 {
	baseScore := map[domain.ThreatType]float64{
		domain.ThreatXSS:            0.7,
		domain.ThreatSQLInjection:   0.9,
		domain.ThreatScriptInjection: 0.8,
		domain.ThreatPathTraversal:  0.6,
		domain.ThreatMalware:        0.95,
		domain.ThreatPhishing:       0.7,
		domain.ThreatBruteForce:     0.5,
		domain.ThreatDOS:            0.6,
	}

	severityMultiplier := map[domain.ValidationSeverity]float64{
		domain.SeverityInfo:     0.2,
		domain.SeverityWarning:  0.5,
		domain.SeverityError:    0.8,
		domain.SeverityCritical: 1.0,
	}

	score := baseScore[threatType] * severityMultiplier[severity]
	if score > 1.0 {
		score = 1.0
	}
	return score
}

func (s *SecurityValidationServiceImpl) determineAction(threatType domain.ThreatType, severity domain.ValidationSeverity) domain.ViolationAction {
	if severity == domain.SeverityCritical {
		return domain.ActionBlock
	}
	
	switch threatType {
	case domain.ThreatSQLInjection, domain.ThreatMalware:
		return domain.ActionBlock
	case domain.ThreatXSS, domain.ThreatScriptInjection:
		return domain.ActionSanitize
	case domain.ThreatPathTraversal, domain.ThreatPhishing:
		return domain.ActionWarn
	default:
		return domain.ActionLog
	}
}

func (s *SecurityValidationServiceImpl) shouldBlock(threatType domain.ThreatType, severity domain.ValidationSeverity) bool {
	return s.determineAction(threatType, severity) == domain.ActionBlock
}

func (s *SecurityValidationServiceImpl) truncateInput(input string, maxLength int) string {
	if len(input) <= maxLength {
		return input
	}
	return input[:maxLength] + "..."
}

func (s *SecurityValidationServiceImpl) strictSanitize(input string) string {
	// Very strict sanitization - remove all special characters
	result := regexp.MustCompile(`[^a-zA-Z0-9\s]`).ReplaceAllString(input, "")
	return strings.TrimSpace(result)
}

func (s *SecurityValidationServiceImpl) moderateSanitize(input string) string {
	// Moderate sanitization - remove dangerous patterns but keep basic punctuation
	result := input
	
	// Remove script tags
	result = regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`).ReplaceAllString(result, "")
	
	// Remove javascript: protocols
	result = regexp.MustCompile(`(?i)javascript:`).ReplaceAllString(result, "")
	
	// Remove SQL injection patterns
	result = regexp.MustCompile(`(?i)(union\s+select|drop\s+table|delete\s+from|insert\s+into)`).ReplaceAllString(result, "")
	
	return strings.TrimSpace(result)
}

func (s *SecurityValidationServiceImpl) lenientSanitize(input string) string {
	// Lenient sanitization - only remove the most dangerous patterns
	result := input
	
	// Remove script tags
	result = regexp.MustCompile(`(?i)<script[^>]*>.*?</script>`).ReplaceAllString(result, "")
	
	return strings.TrimSpace(result)
}

// Compile-time interface compliance verification
var _ domain.SecurityValidationService = (*SecurityValidationServiceImpl)(nil)