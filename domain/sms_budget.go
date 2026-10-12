package domain

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// SMSLimits bounds the SMS the installation may send. Every value is mandatory (a zero cap would
// refuse everything); MinIntervalPerPhone may be 0 (no minimum interval).
type SMSLimits struct {
	MaxPerPhonePerDay     int           // per destination phone, all purposes together, in a 24h window from its first SMS
	MaxPerPhonePer30Days  int           // same, 30-day window
	MinIntervalPerPhone   time.Duration // minimum time between two SMS to the same phone
	MaxPerIPPerDay        int           // per caller address, 24h window
	GlobalDailyCap        int           // whole installation, per UTC calendar day
	GlobalMonthlyCap      int           // whole installation, per UTC calendar month
}

// DefaultSMSLimits are the deliberately strict service defaults.
func DefaultSMSLimits() SMSLimits {
	return SMSLimits{
		MaxPerPhonePerDay:    2,
		MaxPerPhonePer30Days: 5,
		MinIntervalPerPhone:  2 * time.Minute,
		MaxPerIPPerDay:       5,
		GlobalDailyCap:       100,
		GlobalMonthlyCap:     1000,
	}
}

// SMSTarget identifies one SMS about to be sent: the destination phone and the caller address.
type SMSTarget struct {
	Phone string
	IP    string
}

// SMSUsage is what the admin usage route returns: SMS accepted by the provider, and the caps.
type SMSUsage struct {
	Today      int64 `json:"today"`
	Month      int64 `json:"month"`
	DailyCap   int   `json:"daily_cap"`
	MonthlyCap int   `json:"monthly_cap"`
}

// SMSBudget decides whether one more SMS may be sent. Reserve atomically checks every limit and
// consumes one unit of each; it fails closed.
type SMSBudget interface {
	Reserve(ctx context.Context, target SMSTarget) error
	// Release gives a reservation back (only when nothing reached the provider).
	Release(ctx context.Context, target SMSTarget) error
	// RecordSent counts an SMS the provider accepted.
	RecordSent(ctx context.Context) error
	Usage(ctx context.Context) (SMSUsage, error)
}

// SMSLimitKind says which limit refused an SMS.
type SMSLimitKind string

const (
	SMSLimitPhoneInterval SMSLimitKind = "phone_interval"
	SMSLimitPhoneDay      SMSLimitKind = "phone_day"
	SMSLimitPhoneMonth    SMSLimitKind = "phone_30_days"
	SMSLimitIPDay         SMSLimitKind = "ip_day"
)

// SMSLimitError is returned when a per-phone or per-caller limit refuses an SMS. RetryAfter is when
// the limit lets the next one through.
type SMSLimitError struct {
	Kind       SMSLimitKind
	RetryAfter time.Duration
}

func (e *SMSLimitError) Error() string { return "sms limit reached: " + string(e.Kind) }

var (
	// ErrSMSUnavailable: the installation-wide cap is reached or the budget store failed (fail closed).
	ErrSMSUnavailable = errors.New("sms sending unavailable")
	// ErrSMSNotSent marks a provider failure that happened before any network call; the budget
	// reservation is given back.
	ErrSMSNotSent = errors.New("sms not sent")
	// ErrPhoneAlreadyVerified: a verification code is never sent to a verified phone.
	ErrPhoneAlreadyVerified = errors.New("phone already verified")
)

// OTPPurpose is why a code is sent; it selects the SMS text. The default is verification.
type OTPPurpose string

const (
	OTPPurposeVerification   OTPPurpose = "verification"
	OTPPurposePasswordReset  OTPPurpose = "password_reset"
	OTPPurposePasswordChange OTPPurpose = "password_change"
)

// WithOTPPurpose / OTPPurposeFrom carry the purpose down to OTPService.Generate.
func WithOTPPurpose(ctx context.Context, p OTPPurpose) context.Context {
	return context.WithValue(ctx, otpPurposeKey{}, p)
}

func OTPPurposeFrom(ctx context.Context) OTPPurpose {
	if p, ok := ctx.Value(otpPurposeKey{}).(OTPPurpose); ok && p != "" {
		return p
	}
	return OTPPurposeVerification
}

type otpPurposeKey struct{}

// WithClientIP / ClientIPFrom carry the caller address. They use the same "client_ip" key the
// registration and login paths already read.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, "client_ip", ip)
}

func ClientIPFrom(ctx context.Context) string {
	ip, _ := ctx.Value("client_ip").(string)
	return ip
}

// DefaultSMSBrand is the product name that opens every code SMS.
const DefaultSMSBrand = "TocomVC"

// MaxSMSBrandLength keeps the sender name short, so the text stays one segment.
const MaxSMSBrandLength = 11

// gsm7Basic is the GSM 03.38 basic alphabet (line breaks excluded). A text made only of these
// characters is sent as a GSM-7 segment (160 characters); any other character forces UCS-2 (70).
const gsm7Basic = "@£$¥èéùìòÇØøÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"

// IsGSM7 reports whether every character of s is in the GSM-7 basic alphabet.
func IsGSM7(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune(gsm7Basic, r) {
			return false
		}
	}
	return true
}

// ValidateSMSBrand checks SMS_BRAND: not empty, at most 11 characters, GSM-7 characters only.
func ValidateSMSBrand(brand string) error {
	switch {
	case strings.TrimSpace(brand) == "":
		return errors.New("must not be empty")
	case utf8.RuneCountInString(brand) > MaxSMSBrandLength:
		return fmt.Errorf("must have at most %d characters", MaxSMSBrandLength)
	case !IsGSM7(brand):
		return errors.New("must use only GSM-7 characters (no accents like á ã õ ê ô í ó ú, which make the SMS UCS-2)")
	}
	return nil
}

// MinSMSTestPrefixDigits keeps a typo such as "+55" from silencing SMS for a whole country.
const MinSMSTestPrefixDigits = 8

// ParseSMSTestPhonePrefixes parses SMS_TEST_PHONE_PREFIXES: a comma-separated list of E.164 prefixes,
// each "+" followed by at least 8 digits. Empty means no test numbers. An invalid entry is an error.
func ParseSMSTestPhonePrefixes(raw string) ([]string, error) {
	var prefixes []string
	seen := map[string]bool{}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		digits := strings.TrimPrefix(entry, "+")
		valid := strings.HasPrefix(entry, "+") && len(digits) >= MinSMSTestPrefixDigits
		for _, r := range digits {
			if r < '0' || r > '9' {
				valid = false
			}
		}
		if !valid {
			return nil, fmt.Errorf("invalid test phone prefix %q: expected \"+\" followed by at least %d digits", entry, MinSMSTestPrefixDigits)
		}
		if !seen[entry] {
			seen[entry] = true
			prefixes = append(prefixes, entry)
		}
	}
	return prefixes, nil
}
