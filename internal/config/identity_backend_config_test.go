package config

import (
	"testing"
	"time"
)

func TestLoadIdentityBackendConfig_EnvOverridesFile(t *testing.T) {
	fromFile := IdentityBackendFileConfig{URL: "http://file:8000", APIKey: "file-key", Timeout: "5s"}
	t.Setenv("IDENTITY_BACKEND_URL", "http://env:9000")
	t.Setenv("IDENTITY_BACKEND_API_KEY", "env-key")
	t.Setenv("IDENTITY_BACKEND_TIMEOUT", "750ms")

	got, err := loadIdentityBackendConfig(fromFile)
	if err != nil {
		t.Fatal(err)
	}
	if got.URL != "http://env:9000" || got.APIKey != "env-key" || got.Timeout != 750*time.Millisecond {
		t.Errorf("env must override file: %+v", got)
	}
}

func TestLoadIdentityBackendConfig_FileAndDefaults(t *testing.T) {
	got, err := loadIdentityBackendConfig(IdentityBackendFileConfig{URL: "http://file:8000", APIKey: "k", Timeout: "5s"})
	if err != nil || got.URL != "http://file:8000" || got.APIKey != "k" || got.Timeout != 5*time.Second {
		t.Errorf("file values: %+v %v", got, err)
	}
	got, err = loadIdentityBackendConfig(IdentityBackendFileConfig{})
	if err != nil || got.URL != "" || got.Timeout != DefaultIdentityBackendTimeout {
		t.Errorf("defaults: %+v %v", got, err)
	}
}

func TestLoadIdentityBackendConfig_InvalidTimeout(t *testing.T) {
	t.Setenv("IDENTITY_BACKEND_TIMEOUT", "soon")
	if _, err := loadIdentityBackendConfig(IdentityBackendFileConfig{}); err == nil {
		t.Error("expected an error for an invalid timeout")
	}
}
