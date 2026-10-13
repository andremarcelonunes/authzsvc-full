package config

import (
	"testing"
	"time"

	"github.com/you/authzsvc/domain"
)

func TestLoadSessionConfig_DefaultsAreTodaysBehaviour(t *testing.T) {
	got, err := loadSessionConfig(SessionFileConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got.TTL != 0 || got.MaxAge != 0 || got.RefreshGrace != 0 {
		t.Errorf("all zero by default (legacy lifetimes, no cap, strict tokens): %+v", got)
	}
}

func TestLoadSessionConfig_FileAndEnv(t *testing.T) {
	got, err := loadSessionConfig(SessionFileConfig{TTL: "720h", MaxAge: "2160h", RefreshGrace: "30s"})
	if err != nil || got.TTL != 720*time.Hour || got.MaxAge != 2160*time.Hour || got.RefreshGrace != 30*time.Second {
		t.Errorf("file values must apply: %+v %v", got, err)
	}
	t.Setenv("SESSION_TTL", "48h")
	t.Setenv("SESSION_MAX_AGE", "0")
	t.Setenv("REFRESH_GRACE", "10s")
	got, err = loadSessionConfig(SessionFileConfig{TTL: "720h", MaxAge: "2160h", RefreshGrace: "30s"})
	if err != nil || got.TTL != 48*time.Hour || got.MaxAge != 0 || got.RefreshGrace != 10*time.Second {
		t.Errorf("env must override file: %+v %v", got, err)
	}
}

func TestLoadSessionConfig_InvalidValues(t *testing.T) {
	for name, file := range map[string]SessionFileConfig{
		"ttl lixo":            {TTL: "abc"},
		"ttl negativo":        {TTL: "-1h"},
		"max age negativo":    {MaxAge: "-1h"},
		"grace negativo":      {RefreshGrace: "-1s"},
		"grace acima do teto": {RefreshGrace: "10m"},
	} {
		if _, err := loadSessionConfig(file); err == nil {
			t.Errorf("%s must be rejected", name)
		}
	}
}

func TestLoadSessionConfig_TTLNeverExceedsTheCap(t *testing.T) {
	got, err := loadSessionConfig(SessionFileConfig{TTL: "720h", MaxAge: "24h"})
	if err != nil || got.TTL != 24*time.Hour {
		t.Errorf("a sliding window longer than the absolute cap is clamped: %+v %v", got, err)
	}
}

func TestEffectiveRefreshTTL_RefreshTokenNeverExpiresBeforeTheSession(t *testing.T) {
	week := 168 * time.Hour
	if got := effectiveRefreshTTL(week, domain.SessionPolicy{}); got != week {
		t.Errorf("default: refresh_ttl unchanged, got %v", got)
	}
	if got := effectiveRefreshTTL(week, domain.SessionPolicy{TTL: 24 * time.Hour}); got != week {
		t.Errorf("shorter session keeps refresh_ttl, got %v", got)
	}
	if got := effectiveRefreshTTL(week, domain.SessionPolicy{TTL: 720 * time.Hour}); got != 720*time.Hour {
		t.Errorf("longer session raises the refresh lifetime to match, got %v", got)
	}
}
