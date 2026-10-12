package smsbudget

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/you/authzsvc/domain"
)

func newBudget(t *testing.T, mutate func(*domain.SMSLimits)) (*RedisBudget, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	limits := domain.SMSLimits{MaxPerPhonePerDay: 100, MaxPerPhonePer30Days: 100, MinIntervalPerPhone: 0, MaxPerIPPerDay: 100, GlobalDailyCap: 1000, GlobalMonthlyCap: 10000}
	if mutate != nil {
		mutate(&limits)
	}
	return NewRedisBudget(rdb, limits, "secret"), mr
}

func limitKind(t *testing.T, err error) domain.SMSLimitKind {
	t.Helper()
	var le *domain.SMSLimitError
	if !errors.As(err, &le) {
		t.Fatalf("expected an SMSLimitError, got %v", err)
	}
	if le.RetryAfter <= 0 {
		t.Errorf("retry-after must be positive, got %v", le.RetryAfter)
	}
	return le.Kind
}

var ctx = context.Background()

func TestPerPhoneDailyCap(t *testing.T) {
	b, mr := newBudget(t, func(l *domain.SMSLimits) { l.MaxPerPhonePerDay = 2 })
	target := domain.SMSTarget{Phone: "+5511999990000", IP: "1.1.1.1"}
	for i := 0; i < 2; i++ {
		if err := b.Reserve(ctx, target); err != nil {
			t.Fatalf("reservation %d: %v", i, err)
		}
	}
	if k := limitKind(t, b.Reserve(ctx, target)); k != domain.SMSLimitPhoneDay {
		t.Errorf("expected phone_day, got %s", k)
	}
	if err := b.Reserve(ctx, domain.SMSTarget{Phone: "+5511888880000", IP: "1.1.1.1"}); err != nil {
		t.Errorf("another phone is not affected: %v", err)
	}
	mr.FastForward(24*time.Hour + time.Second)
	if err := b.Reserve(ctx, target); err != nil {
		t.Errorf("the window must expire after 24h: %v", err)
	}
}

func TestPerPhone30DayCap(t *testing.T) {
	b, mr := newBudget(t, func(l *domain.SMSLimits) { l.MaxPerPhonePer30Days = 3 })
	target := domain.SMSTarget{Phone: "+5511999990000", IP: "1.1.1.1"}
	for i := 0; i < 3; i++ {
		if err := b.Reserve(ctx, target); err != nil {
			t.Fatal(err)
		}
		mr.FastForward(25 * time.Hour) // keep the daily window out of the way, 3 sends within 30 days
	}
	// 75h passed: still inside the 30-day window
	if k := limitKind(t, b.Reserve(ctx, target)); k != domain.SMSLimitPhoneMonth {
		t.Errorf("expected phone_30_days, got %s", k)
	}
	mr.FastForward(30 * 24 * time.Hour)
	if err := b.Reserve(ctx, target); err != nil {
		t.Errorf("the 30-day window must expire: %v", err)
	}
}

func TestMinIntervalPerPhone(t *testing.T) {
	b, mr := newBudget(t, func(l *domain.SMSLimits) { l.MinIntervalPerPhone = 2 * time.Minute })
	target := domain.SMSTarget{Phone: "+5511999990000", IP: "1.1.1.1"}
	if err := b.Reserve(ctx, target); err != nil {
		t.Fatal(err)
	}
	err := b.Reserve(ctx, target)
	if k := limitKind(t, err); k != domain.SMSLimitPhoneInterval {
		t.Errorf("expected phone_interval, got %s", k)
	}
	if ra := err.(*domain.SMSLimitError).RetryAfter; ra > 2*time.Minute || ra < time.Minute {
		t.Errorf("retry-after should be about 2 minutes, got %v", ra)
	}
	mr.FastForward(119 * time.Second)
	if err := b.Reserve(ctx, target); err == nil {
		t.Error("1s before the interval ends the SMS must still be refused")
	}
	mr.FastForward(2 * time.Second)
	if err := b.Reserve(ctx, target); err != nil {
		t.Errorf("after the interval the SMS is allowed: %v", err)
	}
}

func TestRefusedReservationConsumesNothing(t *testing.T) {
	b, _ := newBudget(t, func(l *domain.SMSLimits) { l.MaxPerPhonePerDay = 1; l.MaxPerIPPerDay = 2 })
	a := domain.SMSTarget{Phone: "+5511999990000", IP: "1.1.1.1"}
	if err := b.Reserve(ctx, a); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ { // refused by the phone cap: must not eat the IP budget
		_ = b.Reserve(ctx, a)
	}
	if err := b.Reserve(ctx, domain.SMSTarget{Phone: "+5511888880000", IP: "1.1.1.1"}); err != nil {
		t.Errorf("refused attempts must not consume the address budget: %v", err)
	}
}

func TestPerIPCapAndUnknownBucket(t *testing.T) {
	b, _ := newBudget(t, func(l *domain.SMSLimits) { l.MaxPerIPPerDay = 3 })
	for i := 0; i < 3; i++ {
		if err := b.Reserve(ctx, domain.SMSTarget{Phone: fmt.Sprintf("+55119999000%02d", i), IP: "9.9.9.9"}); err != nil {
			t.Fatal(err)
		}
	}
	if k := limitKind(t, b.Reserve(ctx, domain.SMSTarget{Phone: "+5511999990099", IP: "9.9.9.9"})); k != domain.SMSLimitIPDay {
		t.Errorf("expected ip_day, got %s", k)
	}
	if err := b.Reserve(ctx, domain.SMSTarget{Phone: "+5511999990098", IP: "8.8.8.8"}); err != nil {
		t.Errorf("another address is not affected: %v", err)
	}
	// No address at all: everything shares one bucket, still bounded.
	for i := 0; i < 3; i++ {
		if err := b.Reserve(ctx, domain.SMSTarget{Phone: fmt.Sprintf("+55118888000%02d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	if k := limitKind(t, b.Reserve(ctx, domain.SMSTarget{Phone: "+5511888800099"})); k != domain.SMSLimitIPDay {
		t.Errorf("the unknown-address bucket must be capped too, got %s", k)
	}
}

func TestGlobalCapsAreUnavailableAndLoggedOncePerPeriod(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	b, _ := newBudget(t, func(l *domain.SMSLimits) { l.GlobalDailyCap = 2 })
	for i := 0; i < 2; i++ {
		if err := b.Reserve(ctx, domain.SMSTarget{Phone: fmt.Sprintf("+55119999000%02d", i), IP: "1.1.1.1"}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		err := b.Reserve(ctx, domain.SMSTarget{Phone: "+5511777770000", IP: "2.2.2.2"})
		if !errors.Is(err, domain.ErrSMSUnavailable) {
			t.Fatalf("a global cap must answer ErrSMSUnavailable, got %v", err)
		}
	}
	if n := strings.Count(buf.String(), "SMS budget exhausted"); n != 1 {
		t.Errorf("the exhaustion must be logged once per period, logged %d times: %q", n, buf.String())
	}

	buf.Reset()
	m, _ := newBudget(t, func(l *domain.SMSLimits) { l.GlobalMonthlyCap = 1 })
	_ = m.Reserve(ctx, domain.SMSTarget{Phone: "+5511999990000", IP: "1.1.1.1"})
	if err := m.Reserve(ctx, domain.SMSTarget{Phone: "+5511999990001", IP: "1.1.1.2"}); !errors.Is(err, domain.ErrSMSUnavailable) {
		t.Errorf("monthly cap: %v", err)
	}
	if !strings.Contains(buf.String(), "monthly cap") {
		t.Errorf("monthly exhaustion must be logged: %q", buf.String())
	}
}

func TestGlobalDailyCapResetsNextDay(t *testing.T) {
	b, _ := newBudget(t, func(l *domain.SMSLimits) { l.GlobalDailyCap = 1 })
	clock := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return clock }
	if err := b.Reserve(ctx, domain.SMSTarget{Phone: "+5511999990000", IP: "1"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Reserve(ctx, domain.SMSTarget{Phone: "+5511999990001", IP: "2"}); !errors.Is(err, domain.ErrSMSUnavailable) {
		t.Fatalf("same day must be refused, got %v", err)
	}
	clock = clock.Add(24 * time.Hour)
	if err := b.Reserve(ctx, domain.SMSTarget{Phone: "+5511999990001", IP: "2"}); err != nil {
		t.Errorf("the next UTC day has a fresh cap: %v", err)
	}
}

func TestFailsClosedWhenRedisIsDown(t *testing.T) {
	b, mr := newBudget(t, nil)
	mr.Close()
	if err := b.Reserve(ctx, domain.SMSTarget{Phone: "+5511999990000", IP: "1.1.1.1"}); !errors.Is(err, domain.ErrSMSUnavailable) {
		t.Errorf("a Redis failure must refuse the SMS (ErrSMSUnavailable), got %v", err)
	}
}

func TestReserveIsAtomicUnderConcurrency(t *testing.T) {
	t.Run("one phone", func(t *testing.T) {
		b, _ := newBudget(t, func(l *domain.SMSLimits) { l.MaxPerPhonePerDay = 10 })
		var ok int64
		var wg sync.WaitGroup
		for i := 0; i < 80; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if b.Reserve(ctx, domain.SMSTarget{Phone: "+5511999990000", IP: "1.1.1.1"}) == nil {
					atomic.AddInt64(&ok, 1)
				}
			}()
		}
		wg.Wait()
		if ok != 10 {
			t.Errorf("exactly 10 reservations must succeed, got %d", ok)
		}
	})
	t.Run("installation", func(t *testing.T) {
		b, _ := newBudget(t, func(l *domain.SMSLimits) { l.GlobalDailyCap = 20 })
		var ok int64
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				if b.Reserve(ctx, domain.SMSTarget{Phone: fmt.Sprintf("+55119990%05d", i), IP: fmt.Sprintf("10.0.0.%d", i)}) == nil {
					atomic.AddInt64(&ok, 1)
				}
			}(i)
		}
		wg.Wait()
		if ok != 20 {
			t.Errorf("exactly 20 reservations must succeed, got %d", ok)
		}
	})
	t.Run("interval", func(t *testing.T) {
		b, _ := newBudget(t, func(l *domain.SMSLimits) { l.MinIntervalPerPhone = time.Minute })
		var ok int64
		var wg sync.WaitGroup
		for i := 0; i < 50; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if b.Reserve(ctx, domain.SMSTarget{Phone: "+5511999990000", IP: "1.1.1.1"}) == nil {
					atomic.AddInt64(&ok, 1)
				}
			}()
		}
		wg.Wait()
		if ok != 1 {
			t.Errorf("only one request may win the interval, got %d", ok)
		}
	})
}

func TestReleaseGivesTheReservationBack(t *testing.T) {
	b, _ := newBudget(t, func(l *domain.SMSLimits) { l.MaxPerPhonePerDay = 1; l.MinIntervalPerPhone = time.Hour })
	target := domain.SMSTarget{Phone: "+5511999990000", IP: "1.1.1.1"}
	if err := b.Reserve(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := b.Reserve(ctx, target); err == nil {
		t.Fatal("the second reservation must be refused")
	}
	if err := b.Release(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := b.Reserve(ctx, target); err != nil {
		t.Errorf("after Release the budget and the interval are free again: %v", err)
	}
	// Release never drives counters below zero.
	_ = b.Release(ctx, target)
	_ = b.Release(ctx, target)
	if err := b.Reserve(ctx, target); err != nil {
		t.Errorf("unexpected: %v", err)
	}
	if err := b.Reserve(ctx, target); err == nil {
		t.Error("the cap of 1 must still hold after extra releases")
	}
}

func TestUsageCountsOnlySentAndHoldsNoPhoneNumbers(t *testing.T) {
	b, mr := newBudget(t, func(l *domain.SMSLimits) { l.GlobalDailyCap = 7; l.GlobalMonthlyCap = 70 })
	_ = b.Reserve(ctx, domain.SMSTarget{Phone: "+5511999990000", IP: "203.0.113.9"})
	u, err := b.Usage(ctx)
	if err != nil || u.Today != 0 || u.Month != 0 || u.DailyCap != 7 || u.MonthlyCap != 70 {
		t.Fatalf("a reservation is not a sent SMS: %+v %v", u, err)
	}
	for i := 0; i < 3; i++ {
		if err := b.RecordSent(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if u, _ := b.Usage(ctx); u.Today != 3 || u.Month != 3 {
		t.Errorf("unexpected usage %+v", u)
	}
	for _, key := range mr.Keys() {
		if strings.Contains(key, "5511999990000") || strings.Contains(key, "203.0.113.9") {
			t.Errorf("Redis key %q exposes a phone number or an address", key)
		}
	}
}
