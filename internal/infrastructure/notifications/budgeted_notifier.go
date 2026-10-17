package notifications

import (
	"context"
	"errors"
	"log"
	"strings"

	"github.com/you/authzsvc/domain"
)

// BudgetedNotifier is the single choke point for SMS: it reserves budget right before the provider is
// called, so no path that sends through it can bypass the caps. The mock provider (no credentials)
// reports Live() == false and never consumes budget.
type BudgetedNotifier struct {
	inner        domain.NotificationService
	budget       domain.SMSBudget
	testPrefixes []string
	logMessages  bool
	verifier     domain.PhoneCodeVerifier
}

// NotifierOption configures a BudgetedNotifier.
type NotifierOption func(*BudgetedNotifier)

// WithTestPhonePrefixes makes numbers that start with one of prefixes (E.164, SMS_TEST_PHONE_PREFIXES)
// follow the mock path: never handed to the provider, never consuming budget. The message is logged,
// code included, only when logMessages is true (OTP_LOG_CODES). No prefixes means the feature is off.
func WithTestPhonePrefixes(prefixes []string, logMessages bool) NotifierOption {
	return func(b *BudgetedNotifier) {
		b.testPrefixes = prefixes
		b.logMessages = logMessages
	}
}

// WithPhoneCodeVerifier makes codes go through a provider that generates and checks them itself
// (Twilio Verify). Test numbers still follow the mock path; the budget applies to every start.
func WithPhoneCodeVerifier(v domain.PhoneCodeVerifier) NotifierOption {
	return func(b *BudgetedNotifier) { b.verifier = v }
}

// NewBudgetedNotifier wraps inner with budget.
func NewBudgetedNotifier(inner domain.NotificationService, budget domain.SMSBudget, opts ...NotifierOption) *BudgetedNotifier {
	b := &BudgetedNotifier{inner: inner, budget: budget}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

func (b *BudgetedNotifier) isTestNumber(phone string) bool {
	for _, prefix := range b.testPrefixes {
		if strings.HasPrefix(phone, prefix) {
			return true
		}
	}
	return false
}

// SendSMS sends without caller context: phone and installation caps apply, the caller address is unknown.
func (b *BudgetedNotifier) SendSMS(to, message string) error {
	return b.SendSMSContext(context.Background(), to, message)
}

// SendEmail is not budgeted.
func (b *BudgetedNotifier) SendEmail(to, subject, body string) error {
	return b.inner.SendEmail(to, subject, body)
}

// SendSMSContext reserves budget (fail closed), calls the provider and accounts for the outcome.
// A reservation stays consumed when the provider fails, unless the failure happened before any
// network call (domain.ErrSMSNotSent).
func (b *BudgetedNotifier) SendSMSContext(ctx context.Context, to, message string) error {
	if b.isTestNumber(to) {
		logMockSMS(to, message, b.logMessages)
		return nil
	}
	if live, ok := b.inner.(interface{ Live() bool }); ok && !live.Live() {
		return b.inner.SendSMS(to, message)
	}
	target := domain.SMSTarget{Phone: to, IP: domain.ClientIPFrom(ctx)}
	if err := b.budget.Reserve(ctx, target); err != nil {
		return err
	}
	if err := b.inner.SendSMS(to, message); err != nil {
		if errors.Is(err, domain.ErrSMSNotSent) {
			if relErr := b.budget.Release(ctx, target); relErr != nil {
				log.Printf("Warning: failed to release SMS reservation: %v", relErr)
			}
		}
		return err
	}
	if err := b.budget.RecordSent(ctx); err != nil {
		log.Printf("Warning: failed to record a sent SMS: %v", err)
	}
	return nil
}

// IsTestNumber reports whether phone has one of the SMS test prefixes.
func (b *BudgetedNotifier) IsTestNumber(phone string) bool { return b.isTestNumber(phone) }

// UsesProviderVerification is true when codes for phone are generated and checked by the provider:
// a verifier is configured and the number is not a test number.
func (b *BudgetedNotifier) UsesProviderVerification(phone string) bool {
	return b.verifier != nil && !b.isTestNumber(phone)
}

// CheckPhone refuses, before anything is sent, a +55 number that is not a mobile. Test numbers and a
// notifier that would not really send (mock path) are not checked.
func (b *BudgetedNotifier) CheckPhone(phone string) error {
	if b.isTestNumber(phone) {
		return nil
	}
	live := b.verifier != nil
	if l, ok := b.inner.(interface{ Live() bool }); ok && l.Live() {
		live = true
	}
	if !live {
		return nil
	}
	return domain.ValidateMobilePhone(phone)
}

// StartVerification reserves budget (fail closed) and asks the provider to send a code. It has the
// same accounting as SendSMSContext.
func (b *BudgetedNotifier) StartVerification(ctx context.Context, phone string) error {
	if b.verifier == nil || b.isTestNumber(phone) {
		return domain.ErrSMSUnavailable
	}
	target := domain.SMSTarget{Phone: phone, IP: domain.ClientIPFrom(ctx)}
	if err := b.budget.Reserve(ctx, target); err != nil {
		return err
	}
	if err := b.verifier.StartVerification(ctx, phone); err != nil {
		if errors.Is(err, domain.ErrSMSNotSent) {
			if relErr := b.budget.Release(ctx, target); relErr != nil {
				log.Printf("Warning: failed to release SMS reservation: %v", relErr)
			}
		}
		return err
	}
	if err := b.budget.RecordSent(ctx); err != nil {
		log.Printf("Warning: failed to record a sent SMS: %v", err)
	}
	return nil
}

// CheckVerification asks the provider whether code is right. Checking costs no budget.
func (b *BudgetedNotifier) CheckVerification(ctx context.Context, phone, code string) (bool, error) {
	if b.verifier == nil {
		return false, domain.ErrSMSUnavailable
	}
	return b.verifier.CheckVerification(ctx, phone, code)
}

var _ domain.NotificationService = (*BudgetedNotifier)(nil)
