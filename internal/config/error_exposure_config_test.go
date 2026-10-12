package config

import "testing"

func TestLoadGinMode(t *testing.T) {
	t.Setenv("GIN_MODE", "")
	if m, err := loadGinMode(""); err != nil || m != "release" {
		t.Errorf("the default is release: %q %v", m, err)
	}
	if m, _ := loadGinMode("debug"); m != "debug" {
		t.Errorf("the yaml value is honoured, got %q", m)
	}
	t.Setenv("GIN_MODE", "test")
	if m, _ := loadGinMode("debug"); m != "test" {
		t.Errorf("env overrides file, got %q", m)
	}
	t.Setenv("GIN_MODE", "verbose")
	if _, err := loadGinMode(""); err == nil {
		t.Error("an unknown mode must be rejected")
	}
}

func TestErrorExposureSwitchesDefaultToOff(t *testing.T) {
	for _, name := range []string{"EXPOSE_ERROR_DETAILS", "DB_LOG_SQL"} {
		if v, err := resolveBoolSwitchDefaultFalse(name, nil); err != nil || v {
			t.Errorf("%s must default to false", name)
		}
	}
}
