package config

import (
	"testing"
	"time"
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
