package domain

import (
	"context"
	"errors"
	"strings"
)

var (
	// ErrPhoneNotMobile: a +55 number that is not a mobile (11 digits after +55, the first after the
	// area code being 9). Refused before anything is sent.
	ErrPhoneNotMobile = errors.New("phone number is not a mobile")
	// ErrSMSInvalidPhone: the code provider refused the number as invalid (Twilio Verify 60200).
	ErrSMSInvalidPhone = errors.New("phone number refused by the code provider")
)

// PhoneNotMobileMessage is the client-facing message for ErrPhoneNotMobile.
const PhoneNotMobileMessage = "Use um número de celular"

// ValidateMobilePhone refuses a Brazilian (+55) number that is not a mobile: it needs 11 digits after
// +55 and the third digit (the first after the area code) must be 9. Numbers of other countries pass.
func ValidateMobilePhone(phone string) error {
	national, ok := strings.CutPrefix(phone, "+55")
	if !ok {
		return nil
	}
	if len(national) != 11 || national[2] != '9' {
		return ErrPhoneNotMobile
	}
	for _, r := range national {
		if r < '0' || r > '9' {
			return ErrPhoneNotMobile
		}
	}
	return nil
}

// PhoneCodeVerifier is the port of a provider that generates, sends and checks the code itself
// (Twilio Verify). With it the application stores no code.
//
// StartVerification returns *SMSLimitError when the provider limits sends, ErrSMSInvalidPhone for a
// number it refuses. CheckVerification reports whether the code was approved; a wrong code is
// (false, nil); ErrOTPMaxAttempts and ErrOTPExpired mirror the provider's own states.
type PhoneCodeVerifier interface {
	StartVerification(ctx context.Context, phone string) error
	CheckVerification(ctx context.Context, phone, code string) (bool, error)
}
