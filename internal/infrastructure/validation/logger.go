package validation

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/http/middleware"
)

// ValidationLoggerImpl implements ValidationLogger for CB-182
type ValidationLoggerImpl struct {
	logger *slog.Logger
}

// NewValidationLogger creates a new validation logger
func NewValidationLogger() middleware.ValidationLogger {
	return &ValidationLoggerImpl{
		logger: slog.Default(),
	}
}

// LogValidationEvent logs validation events for monitoring and debugging
func (l *ValidationLoggerImpl) LogValidationEvent(ctx context.Context, event middleware.ValidationEvent) {
	// Convert to structured logging
	logFields := []slog.Attr{
		slog.String("request_id", event.RequestID),
		slog.String("endpoint", event.Endpoint),
		slog.String("method", event.Method),
		slog.String("ip_address", event.IPAddress),
		slog.Duration("duration", event.Duration),
		slog.Time("timestamp", event.Timestamp),
	}

	if event.UserID != nil {
		logFields = append(logFields, slog.Uint64("user_id", uint64(*event.UserID)))
	}

	if event.ValidationResult != nil {
		logFields = append(logFields,
			slog.Bool("is_valid", event.ValidationResult.IsValid),
			slog.Bool("passed", event.ValidationResult.Passed),
			slog.Int("error_count", len(event.ValidationResult.Errors)),
			slog.Int("warning_count", len(event.ValidationResult.Warnings)),
			slog.Int("rules_applied", event.ValidationResult.RulesApplied),
		)

		if event.ValidationResult.SecurityResult != nil {
			logFields = append(logFields,
				slog.String("threat_level", string(event.ValidationResult.SecurityResult.ThreatLevel)),
				slog.Int("threat_count", len(event.ValidationResult.SecurityResult.ThreatTypes)),
			)
		}
	}

	l.logger.InfoContext(ctx, "Validation event processed", slog.Any("validation", logFields))
}

// LogSecurityViolation logs security violations for immediate attention
func (l *ValidationLoggerImpl) LogSecurityViolation(ctx context.Context, violation *domain.SecurityViolation) {
	logFields := []slog.Attr{
		slog.String("violation_type", string(violation.Type)),
		slog.String("severity", string(violation.Severity)),
		slog.String("description", violation.Description),
		slog.String("field_name", violation.FieldName),
		slog.String("pattern", violation.Pattern),
		slog.String("action", string(violation.Action)),
		slog.Bool("blocked", violation.Blocked),
		slog.Float64("risk_score", violation.RiskScore),
		slog.Float64("confidence", violation.Confidence),
		slog.Time("timestamp", violation.Timestamp),
	}

	if violation.UserID != nil {
		logFields = append(logFields, slog.Uint64("user_id", uint64(*violation.UserID)))
	}

	// Note: SessionID field doesn't exist in SecurityViolation - would need to be added to domain if needed

	if violation.IPAddress != "" {
		logFields = append(logFields, slog.String("ip_address", violation.IPAddress))
	}

	// Include metadata if present
	if len(violation.Metadata) > 0 {
		if metadataJSON, err := json.Marshal(violation.Metadata); err == nil {
			logFields = append(logFields, slog.String("metadata", string(metadataJSON)))
		}
	}

	l.logger.WarnContext(ctx, "Security violation detected", slog.Any("violation", logFields))
}

// LogValidationError logs validation errors for debugging
func (l *ValidationLoggerImpl) LogValidationError(ctx context.Context, err *domain.ValidationError, requestCtx *domain.ValidationContext) {
	logFields := []slog.Attr{
		slog.String("error_code", err.Code),
		slog.String("error_message", err.Message),
		slog.String("field", err.Field),
		slog.String("constraint", err.Constraint),
		slog.String("severity", string(err.Severity)),
		slog.String("category", string(err.Category)),
		slog.Time("timestamp", err.Timestamp),
	}

	if requestCtx != nil {
		logFields = append(logFields,
			slog.String("request_id", requestCtx.RequestID),
			slog.String("endpoint", requestCtx.Endpoint),
			slog.String("method", requestCtx.Method),
			slog.String("ip_address", requestCtx.IPAddress),
		)

		if requestCtx.UserID != nil {
			logFields = append(logFields, slog.Uint64("user_id", uint64(*requestCtx.UserID)))
		}
	}

	if err.Value != nil {
		if valueJSON, jsonErr := json.Marshal(err.Value); jsonErr == nil {
			logFields = append(logFields, slog.String("value", string(valueJSON)))
		}
	}

	if err.Expected != nil {
		if expectedJSON, jsonErr := json.Marshal(err.Expected); jsonErr == nil {
			logFields = append(logFields, slog.String("expected", string(expectedJSON)))
		}
	}

	if len(err.Metadata) > 0 {
		if metadataJSON, jsonErr := json.Marshal(err.Metadata); jsonErr == nil {
			logFields = append(logFields, slog.String("metadata", string(metadataJSON)))
		}
	}

	// Log level based on severity
	logData := slog.Any("error", logFields)
	switch err.Severity {
	case domain.SeverityCritical:
		l.logger.ErrorContext(ctx, "Critical validation error", logData)
	case domain.SeverityError:
		l.logger.WarnContext(ctx, "Validation error", logData)
	case domain.SeverityWarning:
		l.logger.InfoContext(ctx, "Validation warning", logData)
	default:
		l.logger.DebugContext(ctx, "Validation info", logData)
	}
}