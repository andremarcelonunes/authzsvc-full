package config

import (
	"testing"
	"time"
)

func intPtr(i int) *int { return &i }

func TestLoadPasswordConfig_DefaultsAreStrict(t *testing.T) {
	got, err := loadPasswordConfig(PasswordFileConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RequireComplexity || got.MinLength != 8 || !got.ResetRequireEmail {
		t.Errorf("defaults must be today's strict behaviour (true, 8, true): %+v", got)
	}
}

func TestLoadPasswordConfig_FileValues(t *testing.T) {
	got, err := loadPasswordConfig(PasswordFileConfig{RequireComplexity: boolPtr(false), MinLength: intPtr(6), ResetRequireEmail: boolPtr(false)})
	if err != nil || got.RequireComplexity || got.MinLength != 6 || got.ResetRequireEmail {
		t.Errorf("file values must apply: %+v %v", got, err)
	}
	got, err = loadPasswordConfig(PasswordFileConfig{MinLength: intPtr(10)})
	if err != nil || !got.RequireComplexity || got.MinLength != 10 || !got.ResetRequireEmail {
		t.Errorf("a missing key must keep its default: %+v %v", got, err)
	}
}

func TestLoadPasswordConfig_EnvOverridesFile(t *testing.T) {
	t.Setenv("PASSWORD_REQUIRE_COMPLEXITY", "true")
	t.Setenv("PASSWORD_MIN_LENGTH", "12")
	t.Setenv("PASSWORD_RESET_REQUIRE_EMAIL", "true")
	got, err := loadPasswordConfig(PasswordFileConfig{RequireComplexity: boolPtr(false), MinLength: intPtr(6), ResetRequireEmail: boolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RequireComplexity || got.MinLength != 12 || !got.ResetRequireEmail {
		t.Errorf("env must override file: %+v", got)
	}
}

func TestLoadPasswordConfig_EnvFalse(t *testing.T) {
	t.Setenv("PASSWORD_REQUIRE_COMPLEXITY", "false")
	t.Setenv("PASSWORD_RESET_REQUIRE_EMAIL", "false")
	t.Setenv("PASSWORD_MIN_LENGTH", "6")
	got, err := loadPasswordConfig(PasswordFileConfig{})
	if err != nil || got.RequireComplexity || got.ResetRequireEmail || got.MinLength != 6 {
		t.Errorf("env false/6 must apply: %+v %v", got, err)
	}
}

func TestLoadPasswordConfig_InvalidValuesFail(t *testing.T) {
	cases := []struct{ name, value string }{
		{"PASSWORD_REQUIRE_COMPLEXITY", "maybe"},
		{"PASSWORD_RESET_REQUIRE_EMAIL", "maybe"},
		{"PASSWORD_MIN_LENGTH", "abc"},
		{"PASSWORD_MIN_LENGTH", "3"},
		{"PASSWORD_MIN_LENGTH", "0"},
		{"PASSWORD_MIN_LENGTH", "-8"},
		{"PASSWORD_MIN_LENGTH", "129"},
	}
	for _, tc := range cases {
		t.Run(tc.name+"="+tc.value, func(t *testing.T) {
			t.Setenv(tc.name, tc.value)
			if _, err := loadPasswordConfig(PasswordFileConfig{}); err == nil {
				t.Error("expected an error")
			}
		})
	}
	if _, err := loadPasswordConfig(PasswordFileConfig{MinLength: intPtr(2)}); err == nil {
		t.Error("an out-of-range file value must fail too")
	}
}

func TestLoadRegistrationConfig_RateLimitDefaultsAreToday(t *testing.T) {
	got, err := loadRegistrationConfig(RegistrationFileConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got.RateLimitPerIP != 2 || got.RateLimitWindow != 30*time.Second {
		t.Errorf("defaults must be 2 per 30s, got %d per %s", got.RateLimitPerIP, got.RateLimitWindow)
	}
}

func TestLoadRegistrationConfig_RateLimitLowAndHigh(t *testing.T) {
	cases := []struct {
		name   string
		limit  string
		window string
		want   int
		wantW  time.Duration
	}{
		{"low", "1", "60s", 1, time.Minute},
		{"high", "500", "1m", 500, time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("REGISTRATION_RATE_LIMIT_PER_IP", tc.limit)
			t.Setenv("REGISTRATION_RATE_LIMIT_WINDOW", tc.window)
			got, err := loadRegistrationConfig(RegistrationFileConfig{})
			if err != nil || got.RateLimitPerIP != tc.want || got.RateLimitWindow != tc.wantW {
				t.Errorf("got %+v %v", got, err)
			}
		})
	}
}

func TestLoadRegistrationConfig_RateLimitFileAndEnvPrecedence(t *testing.T) {
	file := RegistrationFileConfig{RateLimitPerIP: intPtr(50), RateLimitWindow: "10s"}
	got, err := loadRegistrationConfig(file)
	if err != nil || got.RateLimitPerIP != 50 || got.RateLimitWindow != 10*time.Second {
		t.Errorf("file values must apply: %+v %v", got, err)
	}
	t.Setenv("REGISTRATION_RATE_LIMIT_PER_IP", "7")
	t.Setenv("REGISTRATION_RATE_LIMIT_WINDOW", "2m")
	got, err = loadRegistrationConfig(file)
	if err != nil || got.RateLimitPerIP != 7 || got.RateLimitWindow != 2*time.Minute {
		t.Errorf("env must override file: %+v %v", got, err)
	}
}

func TestLoadRegistrationConfig_RateLimitInvalidValuesFail(t *testing.T) {
	cases := []struct{ name, value string }{
		{"REGISTRATION_RATE_LIMIT_PER_IP", "abc"},
		{"REGISTRATION_RATE_LIMIT_PER_IP", "0"},
		{"REGISTRATION_RATE_LIMIT_PER_IP", "-1"},
		{"REGISTRATION_RATE_LIMIT_PER_IP", "100001"},
		{"REGISTRATION_RATE_LIMIT_WINDOW", "soon"},
		{"REGISTRATION_RATE_LIMIT_WINDOW", "0s"},
		{"REGISTRATION_RATE_LIMIT_WINDOW", "-5s"},
		{"REGISTRATION_RATE_LIMIT_WINDOW", "500ms"},
		{"REGISTRATION_RATE_LIMIT_WINDOW", "2h"},
	}
	for _, tc := range cases {
		t.Run(tc.name+"="+tc.value, func(t *testing.T) {
			t.Setenv(tc.name, tc.value)
			if _, err := loadRegistrationConfig(RegistrationFileConfig{}); err == nil {
				t.Error("expected an error")
			}
		})
	}
}
