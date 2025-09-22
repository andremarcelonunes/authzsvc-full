package services

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/you/authzsvc/domain"
)

// AuditDataEncryptorImpl implements domain.DataEncryptor for audit data
type AuditDataEncryptorImpl struct {
	encryptionKey []byte
	keyVersion    string
}

// NewAuditDataEncryptor creates a new audit data encryptor
func NewAuditDataEncryptor(encryptionKey string) (domain.DataEncryptor, error) {
	if len(encryptionKey) == 0 {
		return nil, fmt.Errorf("encryption key cannot be empty")
	}

	// Create a 32-byte key from the provided string
	hasher := sha256.New()
	hasher.Write([]byte(encryptionKey))
	key := hasher.Sum(nil)

	return &AuditDataEncryptorImpl{
		encryptionKey: key,
		keyVersion:    "v1", // In production, this would be managed dynamically
	}, nil
}

// Encrypt implements domain.DataEncryptor
func (e *AuditDataEncryptorImpl) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return data, nil
	}

	block, err := aes.NewCipher(e.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt implements domain.DataEncryptor
func (e *AuditDataEncryptorImpl) Decrypt(ctx context.Context, encryptedData []byte) ([]byte, error) {
	if len(encryptedData) == 0 {
		return encryptedData, nil
	}

	block, err := aes.NewCipher(e.encryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptFields implements domain.DataEncryptor
func (e *AuditDataEncryptorImpl) EncryptFields(ctx context.Context, data map[string]interface{}, sensitiveFields []string) (map[string]interface{}, error) {
	if len(data) == 0 || len(sensitiveFields) == 0 {
		return data, nil
	}

	encryptedFields := make(map[string]interface{})
	
	for _, fieldName := range sensitiveFields {
		if value, exists := data[fieldName]; exists && value != nil {
			// Convert value to string for encryption
			valueStr := fmt.Sprintf("%v", value)
			if valueStr != "" {
				encryptedBytes, err := e.Encrypt(ctx, []byte(valueStr))
				if err != nil {
					return nil, fmt.Errorf("failed to encrypt field %s: %w", fieldName, err)
				}
				
				// Store as base64 encoded string
				encryptedFields[fieldName] = base64.StdEncoding.EncodeToString(encryptedBytes)
				
				// Remove original field or mask it
				data[fieldName] = "[ENCRYPTED]"
			}
		}
	}

	return encryptedFields, nil
}

// DecryptFields implements domain.DataEncryptor
func (e *AuditDataEncryptorImpl) DecryptFields(ctx context.Context, data map[string]interface{}, encryptedFields []string) (map[string]interface{}, error) {
	if len(data) == 0 || len(encryptedFields) == 0 {
		return data, nil
	}

	decryptedData := make(map[string]interface{})
	for k, v := range data {
		decryptedData[k] = v
	}

	for _, fieldName := range encryptedFields {
		if encryptedValue, exists := data[fieldName]; exists && encryptedValue != nil {
			encryptedStr, ok := encryptedValue.(string)
			if !ok {
				continue
			}

			// Decode from base64
			encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedStr)
			if err != nil {
				return nil, fmt.Errorf("failed to decode encrypted field %s: %w", fieldName, err)
			}

			// Decrypt
			decryptedBytes, err := e.Decrypt(ctx, encryptedBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt field %s: %w", fieldName, err)
			}

			decryptedData[fieldName] = string(decryptedBytes)
		}
	}

	return decryptedData, nil
}

// RotateKeys implements domain.DataEncryptor
func (e *AuditDataEncryptorImpl) RotateKeys(ctx context.Context) error {
	// In a production system, this would:
	// 1. Generate a new encryption key
	// 2. Update the key version
	// 3. Re-encrypt data with the new key
	// 4. Update the key management system
	
	// For now, we'll just update the version
	e.keyVersion = fmt.Sprintf("v%d", len(e.keyVersion)+1)
	return nil
}

// GetKeyVersion implements domain.DataEncryptor
func (e *AuditDataEncryptorImpl) GetKeyVersion(ctx context.Context) (string, error) {
	return e.keyVersion, nil
}

// AuditIntegrityCheckerImpl implements domain.IntegrityChecker for audit events
type AuditIntegrityCheckerImpl struct{}

// NewAuditIntegrityChecker creates a new audit integrity checker
func NewAuditIntegrityChecker() domain.IntegrityChecker {
	return &AuditIntegrityCheckerImpl{}
}

// CalculateChecksum implements domain.IntegrityChecker
func (c *AuditIntegrityCheckerImpl) CalculateChecksum(data interface{}) (string, error) {
	if event, ok := data.(*domain.ComprehensiveAuditEvent); ok {
		return event.CalculateChecksum(), nil
	}
	
	return "", fmt.Errorf("unsupported data type for checksum calculation: %T", data)
}

// VerifyChecksum implements domain.IntegrityChecker
func (c *AuditIntegrityCheckerImpl) VerifyChecksum(data interface{}, expectedChecksum string) (bool, error) {
	actualChecksum, err := c.CalculateChecksum(data)
	if err != nil {
		return false, err
	}
	
	return actualChecksum == expectedChecksum, nil
}

// VerifyBatchIntegrity implements domain.IntegrityChecker
func (c *AuditIntegrityCheckerImpl) VerifyBatchIntegrity(ctx context.Context, events []*domain.ComprehensiveAuditEvent) ([]bool, error) {
	results := make([]bool, len(events))
	
	for i, event := range events {
		isValid := event.VerifyIntegrity()
		results[i] = isValid
	}
	
	return results, nil
}

// DetectTampering implements domain.IntegrityChecker
func (c *AuditIntegrityCheckerImpl) DetectTampering(ctx context.Context, event *domain.ComprehensiveAuditEvent) (bool, []string, error) {
	var violations []string
	
	// Check if checksum matches
	if !event.VerifyIntegrity() {
		violations = append(violations, "checksum_mismatch")
	}
	
	// Check for suspicious patterns
	if event.CreatedAt.After(event.UpdatedAt) {
		violations = append(violations, "invalid_timestamps")
	}
	
	// Check for suspicious metadata patterns
	if event.Metadata != nil {
		var metadataMap map[string]interface{}
		if err := json.Unmarshal(event.Metadata, &metadataMap); err == nil {
			if val, exists := metadataMap["tampered"]; exists && val == true {
				violations = append(violations, "tampered_flag_set")
			}
		}
	}
	
	// Check correlation ID validity
	if event.CorrelationID.String() == "00000000-0000-0000-0000-000000000000" {
		violations = append(violations, "invalid_correlation_id")
	}
	
	return len(violations) > 0, violations, nil
}

// ScanForIntegrityViolations implements domain.IntegrityChecker
func (c *AuditIntegrityCheckerImpl) ScanForIntegrityViolations(ctx context.Context, criteria *domain.AuditCriteria) ([]*domain.ComprehensiveAuditEvent, error) {
	// This would typically be implemented by the repository with a specialized query
	// For now, we return an empty slice as this is a complex operation that would
	// require database-level integrity checking
	return []*domain.ComprehensiveAuditEvent{}, nil
}

// AuditMetricsImpl implements domain.AuditMetrics for collecting audit metrics
type AuditMetricsImpl struct {
	// In a real implementation, this would use a proper metrics system like Prometheus
	// For now, we'll use simple in-memory counters
	eventCounts       map[string]int64
	securityCounts    map[string]int64
	dataAccessCounts  map[string]int64
	processingTimes   []time.Duration
	writeTimes        []time.Duration
	queryTimes        []time.Duration
}

// NewAuditMetrics creates a new audit metrics collector
func NewAuditMetrics() domain.AuditMetrics {
	return &AuditMetricsImpl{
		eventCounts:      make(map[string]int64),
		securityCounts:   make(map[string]int64),
		dataAccessCounts: make(map[string]int64),
		processingTimes:  make([]time.Duration, 0),
		writeTimes:       make([]time.Duration, 0),
		queryTimes:       make([]time.Duration, 0),
	}
}

// Performance metrics implementation would go here...
// For brevity, I'll include just the interface implementation stubs

func (m *AuditMetricsImpl) RecordEventProcessingTime(ctx context.Context, duration time.Duration) {
	m.processingTimes = append(m.processingTimes, duration)
}

func (m *AuditMetricsImpl) RecordEventWriteLatency(ctx context.Context, latency time.Duration) {
	m.writeTimes = append(m.writeTimes, latency)
}

func (m *AuditMetricsImpl) RecordEventQueryLatency(ctx context.Context, latency time.Duration) {
	m.queryTimes = append(m.queryTimes, latency)
}

func (m *AuditMetricsImpl) IncrementEventCount(ctx context.Context, eventType string) {
	m.eventCounts[eventType]++
}

func (m *AuditMetricsImpl) IncrementSecurityEventCount(ctx context.Context, severity domain.SecuritySeverity) {
	m.securityCounts[string(severity)]++
}

func (m *AuditMetricsImpl) RecordEventBatchSize(ctx context.Context, size int) {
	// Record batch size metrics
}

func (m *AuditMetricsImpl) RecordDataAccessCount(ctx context.Context, dataType string, operation domain.DataOperation) {
	key := fmt.Sprintf("%s_%s", dataType, operation)
	m.dataAccessCounts[key]++
}

func (m *AuditMetricsImpl) RecordConsentEvent(ctx context.Context, consentType string) {
	key := fmt.Sprintf("consent_%s", consentType)
	m.eventCounts[key]++
}

func (m *AuditMetricsImpl) RecordSystemHealth(ctx context.Context, component string, healthy bool) {
	status := "unhealthy"
	if healthy {
		status = "healthy"
	}
	key := fmt.Sprintf("health_%s_%s", component, status)
	m.eventCounts[key]++
}

func (m *AuditMetricsImpl) RecordErrorRate(ctx context.Context, errorType string, rate float64) {
	key := fmt.Sprintf("error_%s", errorType)
	m.eventCounts[key] = int64(rate * 100) // Store as percentage
}

func (m *AuditMetricsImpl) GetMetrics(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error) {
	return map[string]interface{}{
		"event_counts":       m.eventCounts,
		"security_counts":    m.securityCounts,
		"data_access_counts": m.dataAccessCounts,
		"avg_processing_time": m.calculateAverage(m.processingTimes),
		"avg_write_time":     m.calculateAverage(m.writeTimes),
		"avg_query_time":     m.calculateAverage(m.queryTimes),
		"time_range":         timeRange.String(),
	}, nil
}

func (m *AuditMetricsImpl) GetComplianceReport(ctx context.Context, timeRange time.Duration) (map[string]interface{}, error) {
	return map[string]interface{}{
		"data_access_events": m.dataAccessCounts,
		"consent_events":     m.filterConsentEvents(),
		"time_range":         timeRange.String(),
	}, nil
}

// Helper methods

func (m *AuditMetricsImpl) calculateAverage(durations []time.Duration) time.Duration {
	if len(durations) == 0 {
		return 0
	}
	
	var total time.Duration
	for _, d := range durations {
		total += d
	}
	
	return total / time.Duration(len(durations))
}

func (m *AuditMetricsImpl) filterConsentEvents() map[string]int64 {
	consentEvents := make(map[string]int64)
	for key, count := range m.eventCounts {
		if strings.HasPrefix(key, "consent_") {
			consentEvents[key] = count
		}
	}
	return consentEvents
}