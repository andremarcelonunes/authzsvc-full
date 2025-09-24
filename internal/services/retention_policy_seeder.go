package services

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/you/authzsvc/domain"
	"gorm.io/gorm"
)

// RetentionPolicySeeder handles initialization of default data retention policies
type RetentionPolicySeeder struct {
	db *gorm.DB
}

// NewRetentionPolicySeeder creates a new retention policy seeder
func NewRetentionPolicySeeder(db *gorm.DB) *RetentionPolicySeeder {
	return &RetentionPolicySeeder{
		db: db,
	}
}

// SeedDefaultRetentionPolicies creates the default LGPD-compliant retention policies
func (s *RetentionPolicySeeder) SeedDefaultRetentionPolicies(ctx context.Context) error {
	// Check if policies already exist
	var count int64
	if err := s.db.WithContext(ctx).Model(&domain.DataRetentionPolicy{}).Count(&count).Error; err != nil {
		return fmt.Errorf("failed to check existing policies: %w", err)
	}
	
	// If policies already exist, skip seeding
	if count > 0 {
		return nil
	}
	
	// Default retention policies based on LGPD Compliance Service logic
	defaultPolicies := []domain.DataRetentionPolicy{
		{
			ID:              uuid.New(),
			DataType:        "audit_logs",
			RetentionPeriod: 5 * 365 * 24 * time.Hour, // 5 years
			LegalBasis:      "LGPD Article 16 - Legal obligation for audit trails",
			Mandatory:       true,
			Description:     "Audit logs must be retained for legal compliance and security monitoring",
			AppliesTo:       domain.StringList{"all_users"},
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		},
		{
			ID:              uuid.New(),
			DataType:        "financial_records",
			RetentionPeriod: 5 * 365 * 24 * time.Hour, // 5 years  
			LegalBasis:      "Brazilian Federal Revenue Service regulations",
			Mandatory:       true,
			Description:     "Financial transaction records must be retained for tax compliance",
			AppliesTo:       domain.StringList{"users_with_financial_activity"},
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		},
		{
			ID:              uuid.New(),
			DataType:        "tax_records",
			RetentionPeriod: 5 * 365 * 24 * time.Hour, // 5 years
			LegalBasis:      "Brazilian Tax Code - Legal obligation",
			Mandatory:       true,
			Description:     "Tax-related data must be retained per Brazilian tax law",
			AppliesTo:       domain.StringList{"users_with_tax_data"},
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		},
		{
			ID:              uuid.New(),
			DataType:        "administrative_actions",
			RetentionPeriod: 5 * 365 * 24 * time.Hour, // 5 years
			LegalBasis:      "Internal governance and accountability requirements",
			Mandatory:       true,
			Description:     "Administrative actions must be retained for governance and audit purposes",
			AppliesTo:       domain.StringList{"admin", "attendant"},
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		},
		{
			ID:              uuid.New(),
			DataType:        "regional_compliance_brazil",
			RetentionPeriod: 5 * 365 * 24 * time.Hour, // 5 years
			LegalBasis:      "Data protection laws in region: Brazil",
			Mandatory:       true,
			Description:     "Regional compliance requirements for Brazil",
			AppliesTo:       domain.StringList{"users_in_brazil"},
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		},
		{
			ID:              uuid.New(),
			DataType:        "user_personal_data",
			RetentionPeriod: 90 * 24 * time.Hour, // 90 days after deletion request
			LegalBasis:      "LGPD Article 18 - Right to deletion with grace period",
			Mandatory:       false,
			Description:     "Personal user data retention after deletion request",
			AppliesTo:       domain.StringList{"all_users"},
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		},
		{
			ID:              uuid.New(),
			DataType:        "session_logs",
			RetentionPeriod: 1 * 365 * 24 * time.Hour, // 1 year
			LegalBasis:      "Security monitoring and incident response",
			Mandatory:       true,
			Description:     "User session logs for security and fraud prevention",
			AppliesTo:       domain.StringList{"all_users"},
			CreatedAt:       time.Now(),
			UpdatedAt:       time.Now(),
		},
	}
	
	// Insert all policies in a transaction
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		for _, policy := range defaultPolicies {
			if err := tx.Create(&policy).Error; err != nil {
				return fmt.Errorf("failed to create retention policy %s: %w", policy.DataType, err)
			}
		}
		return nil
	})
}