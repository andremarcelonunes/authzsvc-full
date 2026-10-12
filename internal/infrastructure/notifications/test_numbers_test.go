package notifications

import (
	"context"
	"strings"
	"testing"
)

// newNotifierWithTestNumbers builds the production notifier for a deployment whose test prefixes are prefixes.
func newNotifierWithTestNumbers(provider *fakeProvider, budget *fakeBudget, prefixes ...string) *BudgetedNotifier {
	return NewBudgetedNotifier(provider, budget, WithTestPhonePrefixes(prefixes, false))
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
}

func TestTestNumbers_PrefixMatchAndNonMatch(t *testing.T) {
	provider, budget := &fakeProvider{}, &fakeBudget{}
	n := newNotifierWithTestNumbers(provider, budget, "+5500000", "+15550001")
	for phone, test := range map[string]bool{
		"+5500000123":  true,  // first prefix
		"+15550001999": true,  // second prefix
		"+5511999990000": false, // a real number
		"+550000":      false, // shorter than the prefix
		"5500000123":   false, // no plus sign
		"+5500001000":  false, // differs inside the prefix
	} {
		before := provider.calls
		if err := n.SendSMSContext(context.Background(), phone, "x"); err != nil {
			t.Fatal(err)
		}
		reached := provider.calls > before
		if reached == test {
			t.Errorf("%s: test number=%v but reached provider=%v", phone, test, reached)
		}
	}
	if budget.reserved != 4 {
		t.Errorf("only the 4 real numbers consume budget, got %d", budget.reserved)
	}
}

func TestTestNumbers_DefaultIsOff(t *testing.T) {
	provider, budget := &fakeProvider{}, &fakeBudget{}
	n := NewBudgetedNotifier(provider, budget)
	_ = n.SendSMSContext(context.Background(), "+55000001234", "x")
	if provider.calls != 1 || budget.reserved != 1 {
		t.Errorf("with no prefixes every number is a normal one: %+v %+v", provider, budget)
	}
	n = NewBudgetedNotifier(provider, budget, WithTestPhonePrefixes(nil, false))
	_ = n.SendSMSContext(context.Background(), "+55000001234", "x")
	if provider.calls != 2 {
		t.Error("an empty list must not match anything (the empty prefix matches every string)")
	}
}

func TestTestNumbers_CodeIsLoggedOnlyWithTheSwitch(t *testing.T) {
	for logIt, wantCode := range map[bool]bool{false: false, true: true} {
		n := NewBudgetedNotifier(&fakeProvider{}, &fakeBudget{}, WithTestPhonePrefixes([]string{"+5500000"}, logIt))
		out := captureLog(t, func() { _ = n.SendSMSContext(context.Background(), "+55000001234", "codigo 123456") })
		if strings.Contains(out, "123456") != wantCode {
			t.Errorf("OTP_LOG_CODES=%v: log %q", logIt, out)
		}
		if !logIt && strings.Contains(out, "+55000001234") {
			t.Errorf("the full phone must not be logged without the switch: %q", out)
		}
	}
}
