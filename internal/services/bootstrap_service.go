package services

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/you/authzsvc/domain"
)

// BootstrapAccount holds the credentials configured for a startup account.
type BootstrapAccount struct {
	Email    string
	Phone    string
	Password string
}

func (a BootstrapAccount) isEmpty() bool {
	return a.Email == "" && a.Phone == "" && a.Password == ""
}

// missingFields lists the names (never the values) of the unset fields.
func (a BootstrapAccount) missingFields() []string {
	var missing []string
	if a.Email == "" {
		missing = append(missing, "email")
	}
	if a.Phone == "" {
		missing = append(missing, "phone")
	}
	if a.Password == "" {
		missing = append(missing, "password")
	}
	return missing
}

// systemEventLogger is the part of the audit service the bootstrap needs.
type systemEventLogger interface {
	LogSystemEvent(ctx context.Context, eventType string, description string, metadata map[string]interface{}) error
}

// BootstrapService creates the root administrator and the optional service administrator
// at startup. It is idempotent and never aborts startup: problems are logged (without
// passwords or full phone numbers) and the caller continues.
type BootstrapService struct {
	userRepo    domain.UserRepository
	passwordSvc domain.PasswordService
	validator   domain.BusinessValidationService
	audit       systemEventLogger
	logger      *log.Logger
}

// NewBootstrapService builds the bootstrap service. audit and logger may be nil.
func NewBootstrapService(
	userRepo domain.UserRepository,
	passwordSvc domain.PasswordService,
	validator domain.BusinessValidationService,
	audit systemEventLogger,
	logger *log.Logger,
) *BootstrapService {
	if logger == nil {
		logger = log.Default()
	}
	return &BootstrapService{userRepo: userRepo, passwordSvc: passwordSvc, validator: validator, audit: audit, logger: logger}
}

// Run executes the bootstrap for both accounts. Errors are logged by the individual steps.
func (s *BootstrapService) Run(ctx context.Context, root, serviceAdmin BootstrapAccount) {
	_, _ = s.EnsureRootAdmin(ctx, root)
	_, _ = s.EnsureServiceAdmin(ctx, serviceAdmin)
}

// EnsureRootAdmin creates the root user when none exists. It reports whether an account was created.
func (s *BootstrapService) EnsureRootAdmin(ctx context.Context, acct BootstrapAccount) (bool, error) {
	exists, err := s.userRepo.ExistsByRole(ctx, domain.RoleRoot)
	if err != nil {
		s.logger.Printf("bootstrap: ERROR could not check for an existing root administrator: %v", err)
		return false, err
	}
	if exists {
		s.logger.Printf("bootstrap: root administrator already exists, nothing to do")
		return false, nil
	}
	if acct.isEmpty() {
		s.logger.Printf("bootstrap: WARNING no root administrator configured")
		return false, nil
	}
	return s.create(ctx, "root administrator", domain.RoleRoot, acct)
}

// EnsureServiceAdmin creates the dedicated admin account when no user has its email.
// An empty configuration is silently ignored (the account is optional).
func (s *BootstrapService) EnsureServiceAdmin(ctx context.Context, acct BootstrapAccount) (bool, error) {
	if acct.isEmpty() {
		return false, nil
	}
	if acct.Email != "" {
		existing, err := s.userRepo.FindByEmail(ctx, acct.Email)
		switch {
		case err == nil && existing != nil:
			if existing.Role != domain.RoleAdmin {
				s.logger.Printf("bootstrap: WARNING service administrator email is already used by a user with role %q; not modified", existing.Role)
			} else {
				s.logger.Printf("bootstrap: service administrator already exists, nothing to do")
			}
			return false, nil
		case err != nil && !errors.Is(err, domain.ErrUserNotFound):
			s.logger.Printf("bootstrap: ERROR could not look up the service administrator: %v", err)
			return false, err
		}
	}
	return s.create(ctx, "service administrator", domain.RoleAdmin, acct)
}

func (s *BootstrapService) create(ctx context.Context, label, role string, acct BootstrapAccount) (bool, error) {
	if missing := acct.missingFields(); len(missing) > 0 {
		err := fmt.Errorf("incomplete configuration, missing: %s", strings.Join(missing, ", "))
		s.logger.Printf("bootstrap: ERROR %s not created: %v", label, err)
		return false, err
	}

	result, err := s.validator.ValidateRegistrationRules(ctx, acct.Email, acct.Phone, acct.Password, role)
	if err != nil {
		s.logger.Printf("bootstrap: ERROR %s not created: validation failed: %v", label, err)
		return false, err
	}
	if result != nil && !result.Passed {
		// Only error codes and field names are logged, never values.
		problems := make([]string, 0, len(result.Errors))
		for _, e := range result.Errors {
			problems = append(problems, fmt.Sprintf("%s (%s)", e.Code, e.Field))
		}
		s.logger.Printf("bootstrap: ERROR %s not created: invalid configuration: %s", label, strings.Join(problems, ", "))
		return false, fmt.Errorf("invalid %s configuration: %s", label, strings.Join(problems, ", "))
	}

	hash, err := s.passwordSvc.Hash(acct.Password)
	if err != nil {
		s.logger.Printf("bootstrap: ERROR %s not created: could not hash password", label)
		return false, fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now()
	user := &domain.User{
		Email:         acct.Email,
		Phone:         acct.Phone,
		PasswordHash:  hash,
		Role:          role,
		IsActive:      true,
		PhoneVerified: true, // bootstrap accounts skip OTP verification
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := s.userRepo.Create(ctx, user); err != nil {
		s.logger.Printf("bootstrap: ERROR %s not created: %v", label, err)
		return false, err
	}

	s.logger.Printf("bootstrap: %s created (user_id=%d, role=%s)", label, user.ID, role)
	if s.audit != nil {
		_ = s.audit.LogSystemEvent(ctx, "bootstrap_account_created",
			fmt.Sprintf("Bootstrap %s created", label),
			map[string]interface{}{
				"user_id": user.ID,
				"role":    role,
			})
	}
	return true, nil
}
