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

var _ domain.NotificationService = (*BudgetedNotifier)(nil)
