package domain

import (
	"testing"
	"time"
)

func TestSessionPolicy_ZeroValueIsTodaysBehaviour(t *testing.T) {
	var p SessionPolicy
	if p.LoginTTL() != 7*24*time.Hour || p.RefreshTTL() != 24*time.Hour {
		t.Errorf("zero policy must be 7d at login and 24h per refresh, got %v / %v", p.LoginTTL(), p.RefreshTTL())
	}
	now := time.Now()
	if p.Expired(now.Add(-1000*time.Hour), now) {
		t.Error("no cap by default")
	}
	if got := p.CappedTTL(now.Add(-1000*time.Hour), now, 24*time.Hour); got != 24*time.Hour {
		t.Errorf("no cap by default, got %v", got)
	}
}

func TestSessionPolicy_ConfiguredTTLAppliesToLoginAndRefresh(t *testing.T) {
	p := SessionPolicy{TTL: 720 * time.Hour}
	if p.LoginTTL() != 720*time.Hour || p.RefreshTTL() != 720*time.Hour {
		t.Errorf("got %v / %v", p.LoginTTL(), p.RefreshTTL())
	}
}

func TestSessionPolicy_MaxAge(t *testing.T) {
	p := SessionPolicy{TTL: 720 * time.Hour, MaxAge: 100 * time.Hour}
	now := time.Now()
	if p.Expired(now.Add(-99*time.Hour), now) || !p.Expired(now.Add(-100*time.Hour), now) {
		t.Error("expired exactly at CreatedAt+MaxAge")
	}
	if got := p.CappedTTL(now.Add(-90*time.Hour), now, 720*time.Hour); got != 10*time.Hour {
		t.Errorf("TTL must stop at the cap, got %v", got)
	}
	if got := p.CappedTTL(now, now, 24*time.Hour); got != 24*time.Hour {
		t.Errorf("a fresh session keeps the full TTL, got %v", got)
	}
}
