package notifications

import (
	"context"
	"testing"

	"github.com/you/authzsvc/domain"
)

// newNotifierWithTestNumbers builds the production notifier for a deployment whose test prefixes are prefixes.
func newNotifierWithTestNumbers(provider *fakeProvider, budget *fakeBudget, prefixes ...string) *BudgetedNotifier {
	return NewBudgetedNotifier(provider, budget)
}

// An SMS to a number with a configured test prefix must never reach the paid provider nor consume budget.
func TestTestNumbers_NeverReachTheProviderNorTheBudget(t *testing.T) {
	provider, budget := &fakeProvider{}, &fakeBudget{}
	n := newNotifierWithTestNumbers(provider, budget, "+5500000")
	if err := n.SendSMSContext(context.Background(), "+55000001234", "code 123456"); err != nil {
		t.Fatal(err)
	}
	if provider.calls != 0 {
		t.Errorf("a test-prefix number reached the provider %d time(s)", provider.calls)
	}
	if budget.reserved != 0 || budget.sent != 0 {
		t.Errorf("a test-prefix number consumed budget: %+v", budget)
	}
	_ = domain.ErrSMSUnavailable
}
