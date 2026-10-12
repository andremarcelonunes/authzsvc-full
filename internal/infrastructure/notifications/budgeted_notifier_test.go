package notifications

import (
	"context"
	"errors"
	"testing"

	"github.com/you/authzsvc/domain"
)

type fakeBudget struct {
	reserveErr error
	reserved   int
	released   int
	sent       int
	last       domain.SMSTarget
}

func (f *fakeBudget) Reserve(ctx context.Context, t domain.SMSTarget) error {
	f.last = t
	if f.reserveErr != nil {
		return f.reserveErr
	}
	f.reserved++
	return nil
}
func (f *fakeBudget) Release(ctx context.Context, t domain.SMSTarget) error { f.released++; return nil }
func (f *fakeBudget) RecordSent(ctx context.Context) error                  { f.sent++; return nil }
func (f *fakeBudget) Usage(ctx context.Context) (domain.SMSUsage, error)    { return domain.SMSUsage{}, nil }

type fakeProvider struct {
	live  *bool
	err   error
	calls int
}

func (p *fakeProvider) SendSMS(to, message string) error   { p.calls++; return p.err }
func (p *fakeProvider) SendEmail(to, s, b string) error    { return nil }
func (p *fakeProvider) Live() bool                         { return p.live == nil || *p.live }

func TestBudgetedNotifier_RefusalNeverReachesTheProvider(t *testing.T) {
	budget, provider := &fakeBudget{reserveErr: domain.ErrSMSUnavailable}, &fakeProvider{}
	err := NewBudgetedNotifier(provider, budget).SendSMS("+5511999990000", "x")
	if !errors.Is(err, domain.ErrSMSUnavailable) || provider.calls != 0 {
		t.Errorf("a refused reservation must stop before the provider: err=%v calls=%d", err, provider.calls)
	}
}

func TestBudgetedNotifier_SuccessIsRecordedAndCarriesTheCallerAddress(t *testing.T) {
	budget, provider := &fakeBudget{}, &fakeProvider{}
	err := NewBudgetedNotifier(provider, budget).SendSMSContext(domain.WithClientIP(context.Background(), "203.0.113.9"), "+5511999990000", "x")
	if err != nil || budget.reserved != 1 || budget.sent != 1 || provider.calls != 1 {
		t.Fatalf("unexpected: err=%v budget=%+v provider=%+v", err, budget, provider)
	}
	if budget.last.IP != "203.0.113.9" || budget.last.Phone != "+5511999990000" {
		t.Errorf("the target must carry phone and address: %+v", budget.last)
	}
}

func TestBudgetedNotifier_ProviderFailureKeepsTheReservation(t *testing.T) {
	budget, provider := &fakeBudget{}, &fakeProvider{err: errors.New("twilio 500")}
	if err := NewBudgetedNotifier(provider, budget).SendSMS("+5511999990000", "x"); err == nil {
		t.Fatal("the provider error must be returned")
	}
	if budget.released != 0 || budget.sent != 0 {
		t.Errorf("a failure after the call keeps the reservation and is not a sent SMS: %+v", budget)
	}
}

func TestBudgetedNotifier_FailureBeforeAnyNetworkCallReleases(t *testing.T) {
	budget, provider := &fakeBudget{}, &fakeProvider{err: domain.ErrSMSNotSent}
	_ = NewBudgetedNotifier(provider, budget).SendSMS("+5511999990000", "x")
	if budget.released != 1 {
		t.Errorf("a pre-network failure must give the reservation back: %+v", budget)
	}
}

func TestBudgetedNotifier_MockProviderConsumesNoBudget(t *testing.T) {
	budget := &fakeBudget{}
	// The real Twilio service without credentials is the mock path.
	err := NewBudgetedNotifier(NewTwilioService("", "", ""), budget).SendSMS("+5511999990000", "x")
	if err != nil || budget.reserved != 0 || budget.sent != 0 {
		t.Errorf("the mock provider must not touch the budget: err=%v %+v", err, budget)
	}
	off := false
	budget = &fakeBudget{}
	_ = NewBudgetedNotifier(&fakeProvider{live: &off}, budget).SendSMS("+5511999990000", "x")
	if budget.reserved != 0 {
		t.Error("a provider reporting Live()==false must not touch the budget")
	}
}

func TestTwilioEmptyDestinationFailsBeforeTheNetwork(t *testing.T) {
	svc := NewTwilioService("sid", "token", "+15005550006")
	if err := svc.SendSMS("", "x"); !errors.Is(err, domain.ErrSMSNotSent) {
		t.Errorf("an empty destination must fail with ErrSMSNotSent, got %v", err)
	}
}
