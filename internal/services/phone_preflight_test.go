package services

import (
	"context"
	"errors"
	"testing"

	"github.com/you/authzsvc/domain"
)

func TestRegistration_PhonePreflightRefusesBeforeAnyUserIsCreated(t *testing.T) {
	svc := &AuthServiceImpl{phoneVerification: domain.StrictPhoneVerification()} // nil userRepo: touching it would panic
	WithPhoneCodePreflight(func(p string) error { return domain.ValidateMobilePhone(p) })(svc)
	_, err := svc.createUserAccount(context.Background(), "/auth/register", nil, "", "+551133334444", "x", "user")
	var verr *domain.RegistrationValidationError
	if !errors.As(err, &verr) || verr.Code != "PHONE_FORMAT_INVALID" || verr.Field != "phone" || verr.Message != "Use um número de celular" {
		t.Fatalf("got %v", err)
	}
}
