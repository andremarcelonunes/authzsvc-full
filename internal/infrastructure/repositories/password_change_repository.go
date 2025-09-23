package repositories

import (
	"context"
	"time"

	"github.com/you/authzsvc/domain"
	"gorm.io/gorm"
)

// DBPasswordChangeRequest represents the database model for password change requests
type DBPasswordChangeRequest struct {
	ID          string     `gorm:"type:uuid;primaryKey" json:"id"`
	UserID      uint       `gorm:"not null;index" json:"user_id"`
	RequestedAt time.Time  `gorm:"not null;index" json:"requested_at"`
	ExpiresAt   time.Time  `gorm:"not null;index" json:"expires_at"`
	OTPCode     string     `gorm:"type:text" json:"otp_code,omitempty"`
	OTPAttempts int64      `gorm:"default:0" json:"otp_attempts"`
	Status      string     `gorm:"type:varchar(50);not null;index" json:"status"`
	CompletedAt *time.Time `gorm:"index" json:"completed_at,omitempty"`
	IPAddress   string     `gorm:"type:text" json:"ip_address,omitempty"`
	UserAgent   string     `gorm:"type:text" json:"user_agent,omitempty"`
	RequestID   string     `gorm:"type:text" json:"request_id,omitempty"`
	Nonce       string     `gorm:"type:text;not null" json:"nonce"`
	CreatedAt   time.Time  `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time  `gorm:"autoUpdateTime" json:"updated_at"`
}

// TableName specifies the table name for GORM
func (DBPasswordChangeRequest) TableName() string {
	return "auth.password_change_requests"
}

// PasswordChangeRepository handles password change request data operations
type PasswordChangeRepository struct {
	db *gorm.DB
}

// NewPasswordChangeRepository creates a new password change repository
func NewPasswordChangeRepository(db *gorm.DB) *PasswordChangeRepository {
	return &PasswordChangeRepository{db: db}
}

// ForgotPasswordRepository handles forgot password request data operations
// Note: Uses the same password_change_requests table as password changes
type ForgotPasswordRepository struct {
	db *gorm.DB
}

// NewForgotPasswordRepository creates a new forgot password repository
func NewForgotPasswordRepository(db *gorm.DB) *ForgotPasswordRepository {
	return &ForgotPasswordRepository{db: db}
}

// Create creates a new forgot password request (uses same table as password changes)
func (r *ForgotPasswordRepository) Create(ctx context.Context, request *domain.ForgotPasswordRequest) error {
	// Convert forgot password request to password change request for unified storage
	var userID uint
	if request.UserID != nil {
		userID = *request.UserID
	}
	
	pcRequest := &domain.PasswordChangeRequest{
		ID:          request.ID,
		UserID:      userID,
		Status:      request.Status,
		RequestedAt: request.RequestedAt,
		ExpiresAt:   request.ExpiresAt,
		OTPCode:     request.OTPCode,
		Nonce:       request.Nonce,
		IPAddress:   request.IPAddress,
		UserAgent:   request.UserAgent,
	}
	
	dbRequest := r.toDBModel(pcRequest)
	return r.db.WithContext(ctx).Create(dbRequest).Error
}

// GetByID retrieves a forgot password request by ID
func (r *ForgotPasswordRepository) GetByID(ctx context.Context, id string) (*domain.ForgotPasswordRequest, error) {
	var dbRequest DBPasswordChangeRequest
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&dbRequest).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, domain.ErrForgotPasswordNotFound
		}
		return nil, err
	}
	return r.toForgotPasswordDomainModel(&dbRequest), nil
}

// Update updates a forgot password request
func (r *ForgotPasswordRepository) Update(ctx context.Context, request *domain.ForgotPasswordRequest) error {
	// Convert forgot password request to password change request for unified storage
	var userID uint
	if request.UserID != nil {
		userID = *request.UserID
	}
	
	pcRequest := &domain.PasswordChangeRequest{
		ID:                 request.ID,
		UserID:             userID,
		Status:             request.Status,
		RequestedAt:        request.RequestedAt,
		ExpiresAt:          request.ExpiresAt,
		CompletedAt:        request.CompletedAt,
		OTPCode:            request.OTPCode,
		OTPAttempts:        request.OTPAttempts,
		OTPGeneratedAt:     request.OTPGeneratedAt,
		OTPExpiresAt:       request.OTPExpiresAt,
		Nonce:              request.Nonce,
		IPAddress:          request.IPAddress,
		UserAgent:          request.UserAgent,
		FailureReason:      request.FailureReason,
		SessionInvalidated: false, // ForgotPasswordRequest doesn't have this field
	}
	
	dbRequest := r.toDBModel(pcRequest)
	return r.db.WithContext(ctx).Save(dbRequest).Error
}

// UpdateStatus updates the status of a forgot password request
func (r *ForgotPasswordRepository) UpdateStatus(ctx context.Context, id string, status string, reason string) error {
	updates := map[string]interface{}{
		"status":     status,
		"updated_at": time.Now(),
	}
	if status == "completed" {
		now := time.Now()
		updates["completed_at"] = &now
	}
	return r.db.WithContext(ctx).Model(&DBPasswordChangeRequest{}).Where("id = ?", id).Updates(updates).Error
}

// CountRecentByIP counts recent forgot password requests for rate limiting by IP
func (r *ForgotPasswordRepository) CountRecentByIP(ctx context.Context, ipAddress string, since time.Time) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&DBPasswordChangeRequest{}).
		Where("ip_address = ? AND requested_at > ?", ipAddress, since).
		Count(&count).Error
	return count, err
}

// UpdateOTPAttempts updates the OTP attempts count for a forgot password request
func (r *ForgotPasswordRepository) UpdateOTPAttempts(ctx context.Context, id string, attempts int) error {
	return r.db.WithContext(ctx).
		Model(&DBPasswordChangeRequest{}).
		Where("id = ?", id).
		Update("otp_attempts", attempts).Error
}

// toDBModel converts domain password change model to database model (for forgot password repo)
func (r *ForgotPasswordRepository) toDBModel(request *domain.PasswordChangeRequest) *DBPasswordChangeRequest {
	return &DBPasswordChangeRequest{
		ID:          request.ID,
		UserID:      request.UserID,
		RequestedAt: request.RequestedAt,
		ExpiresAt:   request.ExpiresAt,
		OTPCode:     request.OTPCode,
		OTPAttempts: int64(request.OTPAttempts),
		Status:      request.Status,
		CompletedAt: request.CompletedAt,
		IPAddress:   request.IPAddress,
		UserAgent:   request.UserAgent,
		RequestID:   request.ID, // Use ID as RequestID for compatibility
		Nonce:       request.Nonce,
	}
}

// toForgotPasswordDomainModel converts database model to forgot password domain model
func (r *ForgotPasswordRepository) toForgotPasswordDomainModel(dbRequest *DBPasswordChangeRequest) *domain.ForgotPasswordRequest {
	var userID *uint
	if dbRequest.UserID != 0 {
		userID = &dbRequest.UserID
	}
	
	return &domain.ForgotPasswordRequest{
		ID:          dbRequest.ID,
		UserID:      userID,
		Status:      dbRequest.Status,
		RequestedAt: dbRequest.RequestedAt,
		ExpiresAt:   dbRequest.ExpiresAt,
		CompletedAt: dbRequest.CompletedAt,
		OTPCode:     dbRequest.OTPCode,
		OTPAttempts: int(dbRequest.OTPAttempts),
		Nonce:       dbRequest.Nonce,
		IPAddress:   dbRequest.IPAddress,
		UserAgent:   dbRequest.UserAgent,
	}
}

// Create creates a new password change request
func (r *PasswordChangeRepository) Create(ctx context.Context, request *domain.PasswordChangeRequest) error {
	dbRequest := r.toDBModel(request)
	return r.db.WithContext(ctx).Create(dbRequest).Error
}

// GetByID retrieves a password change request by ID
func (r *PasswordChangeRepository) GetByID(ctx context.Context, id string) (*domain.PasswordChangeRequest, error) {
	var dbRequest DBPasswordChangeRequest
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&dbRequest).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, domain.ErrPasswordChangeNotFound
		}
		return nil, err
	}
	return r.toDomainModel(&dbRequest), nil
}

// GetByUserID retrieves password change requests for a user
func (r *PasswordChangeRepository) GetByUserID(ctx context.Context, userID uint, limit int) ([]*domain.PasswordChangeRequest, error) {
	var dbRequests []DBPasswordChangeRequest
	query := r.db.WithContext(ctx).Where("user_id = ?", userID).Order("requested_at DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	err := query.Find(&dbRequests).Error
	if err != nil {
		return nil, err
	}

	requests := make([]*domain.PasswordChangeRequest, len(dbRequests))
	for i, dbRequest := range dbRequests {
		requests[i] = r.toDomainModel(&dbRequest)
	}
	return requests, nil
}

// GetActiveByUserID retrieves active password change requests for a user
func (r *PasswordChangeRepository) GetActiveByUserID(ctx context.Context, userID uint) (*domain.PasswordChangeRequest, error) {
	var dbRequest DBPasswordChangeRequest
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND status = ? AND expires_at > ?", userID, "initiated", time.Now()).
		First(&dbRequest).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil // No active request found
		}
		return nil, err
	}
	return r.toDomainModel(&dbRequest), nil
}

// Update updates a password change request
func (r *PasswordChangeRepository) Update(ctx context.Context, request *domain.PasswordChangeRequest) error {
	dbRequest := r.toDBModel(request)
	return r.db.WithContext(ctx).Save(dbRequest).Error
}

// UpdateStatus updates the status of a password change request
func (r *PasswordChangeRepository) UpdateStatus(ctx context.Context, id string, status string, reason string) error {
	updates := map[string]interface{}{
		"status":     status,
		"updated_at": time.Now(),
	}
	if status == "completed" {
		now := time.Now()
		updates["completed_at"] = &now
	}
	return r.db.WithContext(ctx).Model(&DBPasswordChangeRequest{}).Where("id = ?", id).Updates(updates).Error
}

// UpdateOTPAttempts updates the OTP attempts count
func (r *PasswordChangeRepository) UpdateOTPAttempts(ctx context.Context, id string, attempts int) error {
	return r.db.WithContext(ctx).
		Model(&DBPasswordChangeRequest{}).
		Where("id = ?", id).
		Update("otp_attempts", attempts).Error
}

// DeleteExpired deletes expired password change requests
func (r *PasswordChangeRepository) DeleteExpired(ctx context.Context) error {
	return r.db.WithContext(ctx).
		Where("expires_at < ? AND status IN (?)", time.Now(), []string{"initiated", "failed"}).
		Delete(&DBPasswordChangeRequest{}).Error
}

// CountActiveByUserID counts active password change requests for a user
func (r *PasswordChangeRepository) CountActiveByUserID(ctx context.Context, userID uint) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&DBPasswordChangeRequest{}).
		Where("user_id = ? AND status = ? AND expires_at > ?", userID, "initiated", time.Now()).
		Count(&count).Error
	return count, err
}

// CountRecentByUserID counts recent password change requests for rate limiting
func (r *PasswordChangeRepository) CountRecentByUserID(ctx context.Context, userID uint, since time.Time) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&DBPasswordChangeRequest{}).
		Where("user_id = ? AND requested_at > ?", userID, since).
		Count(&count).Error
	return count, err
}

// toDBModel converts domain model to database model
func (r *PasswordChangeRepository) toDBModel(request *domain.PasswordChangeRequest) *DBPasswordChangeRequest {
	return &DBPasswordChangeRequest{
		ID:          request.ID,
		UserID:      request.UserID,
		RequestedAt: request.RequestedAt,
		ExpiresAt:   request.ExpiresAt,
		OTPCode:     request.OTPCode,
		OTPAttempts: int64(request.OTPAttempts),
		Status:      request.Status,
		CompletedAt: request.CompletedAt,
		IPAddress:   request.IPAddress,
		UserAgent:   request.UserAgent,
		RequestID:   request.ID, // Use ID as RequestID for compatibility
		Nonce:       request.Nonce,
	}
}

// toDomainModel converts database model to domain model
func (r *PasswordChangeRepository) toDomainModel(dbRequest *DBPasswordChangeRequest) *domain.PasswordChangeRequest {
	return &domain.PasswordChangeRequest{
		ID:          dbRequest.ID,
		UserID:      dbRequest.UserID,
		Status:      dbRequest.Status,
		RequestedAt: dbRequest.RequestedAt,
		ExpiresAt:   dbRequest.ExpiresAt,
		CompletedAt: dbRequest.CompletedAt,
		OTPCode:     dbRequest.OTPCode,
		OTPAttempts: int(dbRequest.OTPAttempts),
		Nonce:       dbRequest.Nonce,
		IPAddress:   dbRequest.IPAddress,
		UserAgent:   dbRequest.UserAgent,
	}
}