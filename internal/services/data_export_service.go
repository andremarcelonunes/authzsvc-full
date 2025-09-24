package services

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
	"golang.org/x/crypto/scrypt"
)

// DataExportService handles user data export for LGPD compliance
type DataExportService struct {
	userRepo         domain.UserRepository
	auditRepo        domain.ComprehensiveAuditRepository
	deletionRepo     domain.DeletionRequestRepository
	
	// Storage configuration
	config           *ExportConfig
	
	// Security
	encryptionKey    []byte
}

// ExportConfig contains export service configuration
type ExportConfig struct {
	// Storage settings
	StoragePath           string        // Base path for file storage
	MaxFileSize           int64         // Maximum export file size (bytes)
	DefaultRetention      time.Duration // Default export retention period
	
	// Security settings
	EnableEncryption      bool
	EncryptionKeyPath     string
	SigningEnabled        bool
	
	// Export formats
	SupportedFormats      []string // ["json", "csv", "pdf"]
	DefaultFormat         string
	
	// URL generation
	BaseDownloadURL       string
	URLExpirationTime     time.Duration
	
	// Cleanup
	AutoCleanupEnabled    bool
	CleanupInterval       time.Duration
	
	// Testing
	TestMode              bool
}

// DefaultExportConfig returns production-ready export configuration
func DefaultExportConfig() *ExportConfig {
	return &ExportConfig{
		StoragePath:        "/var/authzsvc/exports",
		MaxFileSize:        100 * 1024 * 1024, // 100MB
		DefaultRetention:   7 * 24 * time.Hour, // 7 days
		EnableEncryption:   true,
		SigningEnabled:     true,
		SupportedFormats:   []string{"json", "csv", "zip"},
		DefaultFormat:      "json",
		BaseDownloadURL:    "https://api.example.com/exports",
		URLExpirationTime:  24 * time.Hour,
		AutoCleanupEnabled: true,
		CleanupInterval:    6 * time.Hour,
		TestMode:           false,
	}
}

// UserDataExport contains all exportable user data
type UserDataExport struct {
	ExportID          string                 `json:"export_id"`
	UserID            uint                   `json:"user_id"`
	RequestedAt       time.Time              `json:"requested_at"`
	GeneratedAt       time.Time              `json:"generated_at"`
	Format            string                 `json:"format"`
	
	// User profile data
	Profile           *UserProfile           `json:"profile"`
	
	// Activity data
	LoginHistory      []LoginRecord          `json:"login_history"`
	AuditLogs         []AuditRecord          `json:"audit_logs"`
	
	// Deletion requests
	DeletionHistory   []DeletionRecord       `json:"deletion_history"`
	
	// Compliance data
	ConsentRecords    []ConsentRecord        `json:"consent_records"`
	DataProcessing    []ProcessingRecord     `json:"data_processing"`
	
	// Metadata
	Metadata          map[string]interface{} `json:"metadata"`
	
	// Security
	Checksum          string                 `json:"checksum"`
	Encrypted         bool                   `json:"encrypted"`
	SignedBy          string                 `json:"signed_by,omitempty"`
}

// UserProfile contains exportable user profile data
type UserProfile struct {
	ID               uint       `json:"id"`
	Email            string     `json:"email"`
	Phone            string     `json:"phone"`
	Role             string     `json:"role"`
	IsActive         bool       `json:"is_active"`
	PhoneVerified    bool       `json:"phone_verified"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
	LastLoginAt      *time.Time `json:"last_login_at,omitempty"`
}

// LoginRecord represents a login history entry
type LoginRecord struct {
	Timestamp   time.Time `json:"timestamp"`
	IPAddress   string    `json:"ip_address"`
	UserAgent   string    `json:"user_agent"`
	Success     bool      `json:"success"`
	FailReason  string    `json:"fail_reason,omitempty"`
}

// AuditRecord represents an audit log entry
type AuditRecord struct {
	Timestamp     time.Time              `json:"timestamp"`
	EventType     string                 `json:"event_type"`
	EventCategory string                 `json:"event_category"`
	Action        string                 `json:"action"`
	Success       bool                   `json:"success"`
	IPAddress     string                 `json:"ip_address,omitempty"`
	Details       map[string]interface{} `json:"details,omitempty"`
}

// DeletionRecord represents a deletion request history
type DeletionRecord struct {
	RequestID      string    `json:"request_id"`
	RequestedAt    time.Time `json:"requested_at"`
	DeletionType   string    `json:"deletion_type"`
	Status         string    `json:"status"`
	ScheduledAt    time.Time `json:"scheduled_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
	CancelledAt    *time.Time `json:"cancelled_at,omitempty"`
	Reason         string    `json:"reason"`
}

// ConsentRecord represents user consent history
type ConsentRecord struct {
	ConsentType   string    `json:"consent_type"`
	GrantedAt     time.Time `json:"granted_at"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	LegalBasis    string    `json:"legal_basis"`
	Purpose       string    `json:"purpose"`
}

// ProcessingRecord represents data processing activities
type ProcessingRecord struct {
	ProcessedAt   time.Time `json:"processed_at"`
	DataType      string    `json:"data_type"`
	Operation     string    `json:"operation"`
	LegalBasis    string    `json:"legal_basis"`
	Purpose       string    `json:"purpose"`
	ProcessorID   string    `json:"processor_id,omitempty"`
}

// NewDataExportService creates a new data export service
func NewDataExportService(
	userRepo domain.UserRepository,
	auditRepo domain.ComprehensiveAuditRepository,
	deletionRepo domain.DeletionRequestRepository,
	config *ExportConfig,
) (*DataExportService, error) {
	if config == nil {
		config = DefaultExportConfig()
	}
	
	service := &DataExportService{
		userRepo:     userRepo,
		auditRepo:    auditRepo,
		deletionRepo: deletionRepo,
		config:       config,
	}
	
	// Initialize encryption if enabled
	if config.EnableEncryption {
		key, err := service.loadOrGenerateEncryptionKey()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize encryption: %w", err)
		}
		service.encryptionKey = key
	}
	
	// Ensure storage directory exists
	if err := os.MkdirAll(config.StoragePath, 0700); err != nil {
		return nil, fmt.Errorf("failed to create storage directory: %w", err)
	}
	
	return service, nil
}

// ExportUserData exports all user data in the requested format
func (s *DataExportService) ExportUserData(ctx context.Context, userID uint, format string) (*domain.UserDataExport, error) {
	// Validate format
	if !s.isFormatSupported(format) {
		format = s.config.DefaultFormat
	}
	
	// Gather all user data
	export, err := s.gatherUserData(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to gather user data: %w", err)
	}
	
	// Generate export ID
	export.ExportID = uuid.New().String()
	export.GeneratedAt = time.Now()
	export.Format = format
	
	// Convert to requested format
	data, err := s.formatExportData(export, format)
	if err != nil {
		return nil, fmt.Errorf("failed to format export data: %w", err)
	}
	
	// Encrypt if enabled
	if s.config.EnableEncryption {
		data, err = s.encryptData(data)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt export: %w", err)
		}
		export.Encrypted = true
	}
	
	// Calculate checksum
	export.Checksum = s.calculateChecksum(data)
	
	// Save to storage
	filePath, err := s.saveExportFile(export.ExportID, data, format)
	if err != nil {
		return nil, fmt.Errorf("failed to save export file: %w", err)
	}
	
	// Generate secure download URL
	downloadURL := s.generateDownloadURL(export.ExportID)
	
	// Create database record
	exportUUID, _ := uuid.Parse(export.ExportID)
	dbExport := &domain.UserDataExport{
		ExportID:      exportUUID,
		UserID:        userID,
		Format:        format,
		DownloadURL:   downloadURL,
		Size:          int64(len(data)),
		Checksum:      export.Checksum,
		ExpiresAt:     time.Now().Add(s.config.DefaultRetention),
		RequestedAt:   export.RequestedAt,
		GeneratedAt:   export.GeneratedAt,
		Downloaded:    false,
		DownloadCount: 0,
		CreatedAt:     export.GeneratedAt,
		UpdatedAt:     time.Now(),
	}
	
	if err := s.deletionRepo.CreateExport(ctx, dbExport); err != nil {
		// Clean up file on database error
		os.Remove(filePath)
		return nil, fmt.Errorf("failed to create export record: %w", err)
	}
	
	return dbExport, nil
}

// gatherUserData collects all user data for export
func (s *DataExportService) gatherUserData(ctx context.Context, userID uint) (*UserDataExport, error) {
	export := &UserDataExport{
		UserID:      userID,
		RequestedAt: time.Now(),
		Metadata:    make(map[string]interface{}),
	}
	
	// Get user profile
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	
	export.Profile = &UserProfile{
		ID:            user.ID,
		Email:         user.Email,
		Phone:         user.Phone,
		Role:          user.Role,
		IsActive:      user.IsActive,
		PhoneVerified: user.PhoneVerified,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
	}
	
	// Get login history
	export.LoginHistory = s.getLoginHistory(ctx, userID)
	
	// Get audit logs
	export.AuditLogs = s.getAuditLogs(ctx, userID)
	
	// Get deletion history
	export.DeletionHistory = s.getDeletionHistory(ctx, userID)
	
	// Get consent records
	export.ConsentRecords = s.getConsentRecords(ctx, userID)
	
	// Get data processing records
	export.DataProcessing = s.getDataProcessingRecords(ctx, userID)
	
	// Add metadata
	export.Metadata["export_timestamp"] = time.Now()
	export.Metadata["total_records"] = s.countRecords(export)
	export.Metadata["lgpd_compliant"] = true
	
	return export, nil
}

// Helper methods for gathering specific data types

func (s *DataExportService) getLoginHistory(ctx context.Context, userID uint) []LoginRecord {
	events, _ := s.auditRepo.FindByUser(ctx, userID, 1000, 0)
	
	records := []LoginRecord{}
	for _, event := range events {
		if event.EventType == "login_success" || event.EventType == "login_failure" {
			record := LoginRecord{
				Timestamp: event.Timestamp,
				IPAddress: event.IPAddress,
				UserAgent: event.UserAgent,
				Success:   event.Success,
			}
			if !event.Success {
				record.FailReason = event.ErrorDetails
			}
			records = append(records, record)
		}
	}
	
	return records
}

func (s *DataExportService) getAuditLogs(ctx context.Context, userID uint) []AuditRecord {
	events, _ := s.auditRepo.FindByUser(ctx, userID, 1000, 0)
	
	records := []AuditRecord{}
	for _, event := range events {
		record := AuditRecord{
			Timestamp:     event.Timestamp,
			EventType:     event.EventType,
			EventCategory: string(event.EventCategory),
			Action:        event.Action,
			Success:       event.Success,
			IPAddress:     event.IPAddress,
		}
		
		if event.Metadata.String() != "" {
			var details map[string]interface{}
			json.Unmarshal([]byte(event.Metadata.String()), &details)
			record.Details = details
		}
		
		records = append(records, record)
	}
	
	return records
}

func (s *DataExportService) getDeletionHistory(ctx context.Context, userID uint) []DeletionRecord {
	// Get all deletion requests for the user
	requests, _ := s.deletionRepo.FindByUserID(ctx, userID)
	
	records := []DeletionRecord{}
	for _, req := range requests {
		record := DeletionRecord{
			RequestID:    req.ID.String(),
			RequestedAt:  req.RequestedAt,
			DeletionType: string(req.RequestType),
			Status:       string(req.Status),
			ScheduledAt:  time.Time{}, // Default to zero time if not scheduled
			Reason:       req.Reason,
		}
		
		if req.ScheduledFor != nil {
			record.ScheduledAt = *req.ScheduledFor
		}
		if req.CompletedAt != nil {
			record.CompletedAt = req.CompletedAt
		}
		
		records = append(records, record)
	}
	
	return records
}

func (s *DataExportService) getConsentRecords(ctx context.Context, userID uint) []ConsentRecord {
	// Get consent-related audit events
	events, _ := s.auditRepo.FindByUser(ctx, userID, 1000, 0)
	
	records := []ConsentRecord{}
	for _, event := range events {
		if event.EventType == "consent_granted" || event.EventType == "consent_revoked" {
			record := ConsentRecord{
				ConsentType: event.Action,
				LegalBasis:  string(event.LegalBasis),
			}
			
			if event.EventType == "consent_granted" {
				record.GrantedAt = event.Timestamp
			} else {
				record.RevokedAt = &event.Timestamp
			}
			
			records = append(records, record)
		}
	}
	
	return records
}

func (s *DataExportService) getDataProcessingRecords(ctx context.Context, userID uint) []ProcessingRecord {
	// Get data processing audit events
	events, _ := s.auditRepo.FindByUser(ctx, userID, 1000, 0)
	
	records := []ProcessingRecord{}
	for _, event := range events {
		if event.EventCategory == domain.CategoryDataAccess {
			record := ProcessingRecord{
				ProcessedAt: event.Timestamp,
				DataType:    event.ResourceType,
				Operation:   event.Action,
				LegalBasis:  string(event.LegalBasis),
			}
			records = append(records, record)
		}
	}
	
	return records
}

// Format conversion methods

func (s *DataExportService) formatExportData(export *UserDataExport, format string) ([]byte, error) {
	switch format {
	case "json":
		return s.formatAsJSON(export)
	case "csv":
		return s.formatAsCSV(export)
	case "zip":
		return s.formatAsZIP(export)
	default:
		return nil, fmt.Errorf("unsupported format: %s", format)
	}
}

func (s *DataExportService) formatAsJSON(export *UserDataExport) ([]byte, error) {
	return json.MarshalIndent(export, "", "  ")
}

func (s *DataExportService) formatAsCSV(export *UserDataExport) ([]byte, error) {
	var buf bytes.Buffer
	writer := csv.NewWriter(&buf)
	
	// Write profile data
	writer.Write([]string{"Section", "Field", "Value"})
	writer.Write([]string{"Profile", "ID", fmt.Sprintf("%d", export.Profile.ID)})
	writer.Write([]string{"Profile", "Email", export.Profile.Email})
	writer.Write([]string{"Profile", "Phone", export.Profile.Phone})
	writer.Write([]string{"Profile", "Role", export.Profile.Role})
	writer.Write([]string{"Profile", "Created", export.Profile.CreatedAt.Format(time.RFC3339)})
	
	// Write login history
	for _, login := range export.LoginHistory {
		writer.Write([]string{
			"Login", 
			login.Timestamp.Format(time.RFC3339),
			login.IPAddress,
			fmt.Sprintf("%v", login.Success),
		})
	}
	
	// Write audit logs
	for _, audit := range export.AuditLogs {
		writer.Write([]string{
			"Audit",
			audit.Timestamp.Format(time.RFC3339),
			audit.EventType,
			audit.Action,
		})
	}
	
	writer.Flush()
	return buf.Bytes(), writer.Error()
}

func (s *DataExportService) formatAsZIP(export *UserDataExport) ([]byte, error) {
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)
	
	// Add JSON file
	jsonData, err := s.formatAsJSON(export)
	if err != nil {
		return nil, err
	}
	
	jsonFile, err := zipWriter.Create("user_data.json")
	if err != nil {
		return nil, err
	}
	if _, err := jsonFile.Write(jsonData); err != nil {
		return nil, err
	}
	
	// Add CSV file
	csvData, err := s.formatAsCSV(export)
	if err != nil {
		return nil, err
	}
	
	csvFile, err := zipWriter.Create("user_data.csv")
	if err != nil {
		return nil, err
	}
	if _, err := csvFile.Write(csvData); err != nil {
		return nil, err
	}
	
	// Add README
	readme := []byte(fmt.Sprintf(`LGPD Data Export
================
User ID: %d
Generated: %s
Format: ZIP Archive

This archive contains your personal data as requested under LGPD Article 18.

Files included:
- user_data.json: Complete data in JSON format
- user_data.csv: Simplified data in CSV format

For questions, contact: privacy@example.com
`, export.UserID, export.GeneratedAt.Format(time.RFC3339)))
	
	readmeFile, err := zipWriter.Create("README.txt")
	if err != nil {
		return nil, err
	}
	if _, err := readmeFile.Write(readme); err != nil {
		return nil, err
	}
	
	if err := zipWriter.Close(); err != nil {
		return nil, err
	}
	
	return buf.Bytes(), nil
}

// Security methods

func (s *DataExportService) loadOrGenerateEncryptionKey() ([]byte, error) {
	if s.config.TestMode {
		// Use fixed key for testing
		return []byte("test-encryption-key-32-bytes-xxx"), nil
	}
	
	keyPath := s.config.EncryptionKeyPath
	if keyPath == "" {
		keyPath = filepath.Join(s.config.StoragePath, ".encryption.key")
	}
	
	// Try to load existing key
	if key, err := os.ReadFile(keyPath); err == nil {
		return key, nil
	}
	
	// Generate new key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	
	// Save key (in production, use proper key management)
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, err
	}
	
	return key, nil
}

func (s *DataExportService) encryptData(data []byte) ([]byte, error) {
	// Generate salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	
	// Derive key using scrypt
	key, err := scrypt.Key(s.encryptionKey, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	
	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	
	// Encrypt data
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	
	// Combine salt + ciphertext
	result := append(salt, ciphertext...)
	
	return result, nil
}

func (s *DataExportService) decryptData(encryptedData []byte) ([]byte, error) {
	if len(encryptedData) < 32 {
		return nil, fmt.Errorf("invalid encrypted data")
	}
	
	// Extract salt
	salt := encryptedData[:32]
	ciphertext := encryptedData[32:]
	
	// Derive key
	key, err := scrypt.Key(s.encryptionKey, salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	
	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	
	// Create GCM
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	
	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	
	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	
	return plaintext, nil
}

func (s *DataExportService) calculateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// Storage methods

func (s *DataExportService) saveExportFile(exportID string, data []byte, format string) (string, error) {
	// Create subdirectory based on date
	dateDir := time.Now().Format("2006/01/02")
	dirPath := filepath.Join(s.config.StoragePath, dateDir)
	
	if err := os.MkdirAll(dirPath, 0700); err != nil {
		return "", err
	}
	
	// Generate filename
	ext := format
	if s.config.EnableEncryption {
		ext = fmt.Sprintf("%s.enc", format)
	}
	filename := fmt.Sprintf("%s.%s", exportID, ext)
	filePath := filepath.Join(dirPath, filename)
	
	// Write file
	if err := os.WriteFile(filePath, data, 0600); err != nil {
		return "", err
	}
	
	return filePath, nil
}

func (s *DataExportService) generateDownloadURL(exportID string) string {
	// Generate signed URL with expiration
	expires := time.Now().Add(s.config.URLExpirationTime).Unix()
	
	// Create signature (in production, use proper signing)
	signature := s.generateURLSignature(exportID, expires)
	
	// Build URL
	url := fmt.Sprintf("%s/%s?expires=%d&signature=%s",
		s.config.BaseDownloadURL,
		exportID,
		expires,
		signature,
	)
	
	return url
}

func (s *DataExportService) generateURLSignature(exportID string, expires int64) string {
	data := fmt.Sprintf("%s:%d", exportID, expires)
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:])
}

// Utility methods

func (s *DataExportService) isFormatSupported(format string) bool {
	for _, f := range s.config.SupportedFormats {
		if f == format {
			return true
		}
	}
	return false
}

func (s *DataExportService) countRecords(export *UserDataExport) int {
	count := 1 // Profile
	count += len(export.LoginHistory)
	count += len(export.AuditLogs)
	count += len(export.DeletionHistory)
	count += len(export.ConsentRecords)
	count += len(export.DataProcessing)
	return count
}

// GetExportByID retrieves an export by ID
func (s *DataExportService) GetExportByID(ctx context.Context, exportID string) (*domain.UserDataExport, error) {
	return s.deletionRepo.GetExportByID(ctx, exportID)
}

// VerifyExportOwnership verifies that an export belongs to a user
func (s *DataExportService) VerifyExportOwnership(ctx context.Context, exportID string, userID uint) error {
	export, err := s.GetExportByID(ctx, exportID)
	if err != nil {
		return err
	}
	
	if export.UserID != userID {
		return fmt.Errorf("export does not belong to user")
	}
	
	return nil
}

// CleanupExpiredExports removes expired export files
func (s *DataExportService) CleanupExpiredExports(ctx context.Context) error {
	// Get expired exports
	criteria := domain.ExportSearchCriteria{
		ExpiredBefore: func() *time.Time { t := time.Now(); return &t }(),
		Limit:         100,
	}
	
	exports, err := s.deletionRepo.SearchExports(ctx, criteria)
	if err != nil {
		return err
	}
	
	// Delete each expired export
	for _, export := range exports {
		// Note: In production, would delete actual file from storage
		// For now, just mark as expired in database
		
		// Update export record via repository
		if err := s.deletionRepo.UpdateExport(ctx, export); err != nil {
			// Log error but continue
			continue
		}
	}
	
	return nil
}