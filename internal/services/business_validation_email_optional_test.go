package services

import (
	"context"
	"testing"

	"github.com/you/authzsvc/domain"
	"github.com/you/authzsvc/internal/mocks"
)

func registrationErrorCodes(res *domain.ValidationResult) map[string]bool {
	codes := map[string]bool{}
	for _, e := range res.Errors {
		codes[e.Code] = true
	}
	return codes
}

func TestValidateRegistrationRules_EmailOptionalSwitch(t *testing.T) {
	const phone, pass = "+5511999990001", "Passw0rd!"
	tests := []struct {
		name     string
		optional bool
		email    string
		wantOK   bool
		wantCode string
	}{
		{"required: empty email rejected", false, "", false, "EMAIL_FORMAT_INVALID"},
		{"required: valid email accepted", false, "a@example.com", true, ""},
		{"optional: empty email accepted", true, "", true, ""},
		{"optional: valid email accepted", true, "a@example.com", true, ""},
		{"optional: an email that is sent is still validated", true, "not-an-email", false, "EMAIL_FORMAT_INVALID"},
		{"optional: blocked domain still rejected", true, "x@tempmail.com", false, "EMAIL_DOMAIN_BLOCKED"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewBusinessValidationService(mocks.NewMockUserRepository(), BusinessValidationConfig{
				EmailValidation: EmailValidationConfig{
					BlockedDomains: []string{"tempmail.com"},
					MaxLength:      254,
					Optional:       tc.optional,
				},
			})
			res, err := svc.ValidateRegistrationRules(context.Background(), tc.email, phone, pass, domain.RoleUser)
			if err != nil {
				t.Fatal(err)
			}
			if res.Passed != tc.wantOK {
				t.Fatalf("passed=%v, want %v (errors: %v)", res.Passed, tc.wantOK, registrationErrorCodes(res))
			}
			if tc.wantCode != "" && !registrationErrorCodes(res)[tc.wantCode] {
				t.Errorf("expected %s, got %v", tc.wantCode, registrationErrorCodes(res))
			}
		})
	}
}

// With the e-mail optional, an absent e-mail must not trigger any e-mail lookup, and the optional
// flag survives the "default email config" fallback of the constructor.
func TestValidateRegistrationRules_AbsentEmailIsNeverLookedUp(t *testing.T) {
	repo := mocks.NewMockUserRepository()
	emailLookups := 0
	repo.FindByEmailFunc = func(ctx context.Context, email string) (*domain.User, error) {
		emailLookups++
		return &domain.User{ID: 1}, nil // would report a duplicate if it were asked
	}
	svc := NewBusinessValidationService(repo, BusinessValidationConfig{EmailValidation: EmailValidationConfig{Optional: true}}) // MaxLength 0 -> defaults
	res, err := svc.ValidateRegistrationRules(context.Background(), "", "+5511999990001", "Passw0rd!", domain.RoleUser)
	if err != nil || !res.Passed {
		t.Fatalf("passed=%v err=%v errors=%v", res != nil && res.Passed, err, res)
	}
	if emailLookups != 0 {
		t.Errorf("no e-mail lookup expected, got %d", emailLookups)
	}
}

func TestValidateRegistrationRules_DuplicatePhoneStillRejectedWithoutEmail(t *testing.T) {
	repo := mocks.NewMockUserRepository()
	repo.FindByPhoneFunc = func(ctx context.Context, phone string) (*domain.User, error) { return &domain.User{ID: 1}, nil }
	svc := NewBusinessValidationService(repo, BusinessValidationConfig{EmailValidation: EmailValidationConfig{Optional: true, MaxLength: 254}})
	res, _ := svc.ValidateRegistrationRules(context.Background(), "", "+5511999990001", "Passw0rd!", domain.RoleUser)
	if res.Passed || !registrationErrorCodes(res)["PHONE_ALREADY_EXISTS"] {
		t.Errorf("duplicate phone must be rejected: %v", registrationErrorCodes(res))
	}
}
