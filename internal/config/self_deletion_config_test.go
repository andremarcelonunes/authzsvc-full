package config

import (
	"testing"
	"time"

	"github.com/you/authzsvc/domain"
)

func TestLoadSelfDeletionConfig_DefaultsKeepTodaysBehaviour(t *testing.T) {
	got, err := loadSelfDeletionConfig(SelfDeletionFileConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Immediate || got.RequirePassword || got.MinAccountAge != 24*time.Hour {
		t.Errorf("defaults must be false/false/24h: %+v", got)
	}
}

func TestLoadSelfDeletionConfig_FileValues(t *testing.T) {
	got, err := loadSelfDeletionConfig(SelfDeletionFileConfig{Immediate: boolPtr(true), RequirePassword: boolPtr(true), MinAccountAge: "0"})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Immediate || !got.RequirePassword || got.MinAccountAge != 0 {
		t.Errorf("file values must apply: %+v", got)
	}
	got, err = loadSelfDeletionConfig(SelfDeletionFileConfig{MinAccountAge: "48h"})
	if err != nil || got.MinAccountAge != 48*time.Hour || got.Immediate {
		t.Errorf("a missing key must keep its default: %+v %v", got, err)
	}
}

func TestLoadSelfDeletionConfig_EnvOverridesFile(t *testing.T) {
	t.Setenv("SELF_DELETION_IMMEDIATE", "false")
	t.Setenv("SELF_DELETION_REQUIRE_PASSWORD", "true")
	t.Setenv("SELF_DELETION_MIN_ACCOUNT_AGE", "0s")
	got, err := loadSelfDeletionConfig(SelfDeletionFileConfig{Immediate: boolPtr(true), RequirePassword: boolPtr(false), MinAccountAge: "24h"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Immediate || !got.RequirePassword || got.MinAccountAge != 0 {
		t.Errorf("env must override file: %+v", got)
	}
}

func TestLoadSelfDeletionConfig_Invalid(t *testing.T) {
	cases := map[string]string{
		"SELF_DELETION_IMMEDIATE":        "maybe",
		"SELF_DELETION_REQUIRE_PASSWORD": "maybe",
		"SELF_DELETION_MIN_ACCOUNT_AGE":  "soon",
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, value)
			if _, err := loadSelfDeletionConfig(SelfDeletionFileConfig{}); err == nil {
				t.Error("expected an error for an unparsable value")
			}
		})
	}
	if _, err := loadSelfDeletionConfig(SelfDeletionFileConfig{MinAccountAge: "-1h"}); err == nil {
		t.Error("a negative age must be rejected")
	}
}

func TestResolveBoolSwitchWithDefault(t *testing.T) {
	const name = "SELF_DELETION_TEST_SWITCH"
	if v, _ := resolveBoolSwitchDefaultFalse(name, nil); v {
		t.Error("default false resolver must return false when unset")
	}
	if v, _ := resolveBoolSwitch(name, nil); !v {
		t.Error("the existing resolver must keep defaulting to true")
	}
	if v, _ := resolveBoolSwitchDefaultFalse(name, boolPtr(true)); !v {
		t.Error("file value must win over the default")
	}
	t.Setenv(name, "true")
	if v, _ := resolveBoolSwitchDefaultFalse(name, boolPtr(false)); !v {
		t.Error("env must win over file")
	}
}

func TestOTPLogCodesSwitchDefaultsToFalse(t *testing.T) {
	if v, err := resolveBoolSwitchDefaultFalse("OTP_LOG_CODES", nil); err != nil || v {
		t.Errorf("OTP_LOG_CODES must default to false: %v %v", v, err)
	}
	t.Setenv("OTP_LOG_CODES", "true")
	if v, _ := resolveBoolSwitchDefaultFalse("OTP_LOG_CODES", nil); !v {
		t.Error("OTP_LOG_CODES=true must switch it on")
	}
}

func TestLoadSMSBudgetConfig(t *testing.T) {
	got, err := loadSMSBudgetConfig(SMSBudgetFileConfig{})
	if err != nil {
		t.Fatal(err)
	}
	want := domain.SMSLimits{MaxPerPhonePerDay: 2, MaxPerPhonePer30Days: 5, MinIntervalPerPhone: 2 * time.Minute, MaxPerIPPerDay: 5, GlobalDailyCap: 100, GlobalMonthlyCap: 1000}
	if got != want {
		t.Errorf("defaults must be the strict ones: %+v", got)
	}

	one, ten := 1, 10
	got, err = loadSMSBudgetConfig(SMSBudgetFileConfig{MaxPerPhonePerDay: &ten, GlobalDailyCap: &one, MinIntervalPerPhone: "30s"})
	if err != nil || got.MaxPerPhonePerDay != 10 || got.GlobalDailyCap != 1 || got.MinIntervalPerPhone != 30*time.Second || got.GlobalMonthlyCap != 1000 {
		t.Errorf("file values must apply over the defaults: %+v %v", got, err)
	}

	t.Setenv("SMS_MAX_PER_PHONE_PER_DAY", "3")
	t.Setenv("SMS_MAX_PER_PHONE_PER_30_DAYS", "7")
	t.Setenv("SMS_MIN_INTERVAL_PER_PHONE", "0")
	t.Setenv("SMS_MAX_PER_IP_PER_DAY", "9")
	t.Setenv("SMS_GLOBAL_DAILY_CAP", "11")
	t.Setenv("SMS_GLOBAL_MONTHLY_CAP", "12")
	got, err = loadSMSBudgetConfig(SMSBudgetFileConfig{MaxPerPhonePerDay: &ten})
	want = domain.SMSLimits{MaxPerPhonePerDay: 3, MaxPerPhonePer30Days: 7, MinIntervalPerPhone: 0, MaxPerIPPerDay: 9, GlobalDailyCap: 11, GlobalMonthlyCap: 12}
	if err != nil || got != want {
		t.Errorf("env must override file: %+v %v", got, err)
	}
}

func TestLoadSMSBudgetConfig_Invalid(t *testing.T) {
	for env, value := range map[string]string{
		"SMS_MAX_PER_PHONE_PER_DAY":  "0",
		"SMS_GLOBAL_DAILY_CAP":       "-1",
		"SMS_GLOBAL_MONTHLY_CAP":     "many",
		"SMS_MIN_INTERVAL_PER_PHONE": "soon",
	} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, value)
			if _, err := loadSMSBudgetConfig(SMSBudgetFileConfig{}); err == nil {
				t.Errorf("%s=%s must be rejected (a zero cap would silently disable SMS)", env, value)
			}
		})
	}
	if _, err := loadSMSBudgetConfig(SMSBudgetFileConfig{MinIntervalPerPhone: "-1m"}); err == nil {
		t.Error("a negative interval must be rejected")
	}
}

func TestLoadClientIPHeader(t *testing.T) {
	if h, err := loadClientIPHeader(""); err != nil || h != "" {
		t.Errorf("the default trusts no header: %q %v", h, err)
	}
	if h, err := loadClientIPHeader(" X-Envoy-External-Address "); err != nil || h != "X-Envoy-External-Address" {
		t.Errorf("file value: %q %v", h, err)
	}
	t.Setenv("CLIENT_IP_HEADER", "X-Real-Peer")
	if h, _ := loadClientIPHeader("X-Envoy-External-Address"); h != "X-Real-Peer" {
		t.Errorf("env must override file, got %q", h)
	}
	t.Setenv("CLIENT_IP_HEADER", "X-Bad Header: 1")
	if _, err := loadClientIPHeader(""); err == nil {
		t.Error("a value that is not a header name must be rejected")
	}
}

func TestValidateSMSBrand(t *testing.T) {
	for _, ok := range []string{domain.DefaultSMSBrand, "A", "WWWWWWWWWWW", "Café"} {
		if err := domain.ValidateSMSBrand(ok); err != nil {
			t.Errorf("%q must be valid: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "   ", "WWWWWWWWWWWW" /* 12 */, "Tocomvê", "São Paulo", "a\nb", "日本"} {
		if err := domain.ValidateSMSBrand(bad); err == nil {
			t.Errorf("%q must be rejected", bad)
		}
	}
}
