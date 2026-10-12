package config

import "testing"

func boolPtr(b bool) *bool { return &b }

func TestLoadRegistrationConfig_DefaultsAreStrict(t *testing.T) {
	got, err := loadRegistrationConfig(RegistrationFileConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RequireEmail || !got.RequirePhoneVerification {
		t.Errorf("both switches must default to true: %+v", got)
	}
}

func TestLoadRegistrationConfig_FileValues(t *testing.T) {
	got, err := loadRegistrationConfig(RegistrationFileConfig{RequireEmail: boolPtr(false), RequirePhoneVerification: boolPtr(false)})
	if err != nil || got.RequireEmail || got.RequirePhoneVerification {
		t.Errorf("file values must apply: %+v %v", got, err)
	}
	got, err = loadRegistrationConfig(RegistrationFileConfig{RequireEmail: boolPtr(false)})
	if err != nil || got.RequireEmail || !got.RequirePhoneVerification {
		t.Errorf("a missing key must keep the default true: %+v %v", got, err)
	}
}

func TestLoadRegistrationConfig_EnvOverridesFile(t *testing.T) {
	t.Setenv("REQUIRE_REGISTRATION_EMAIL", "true")
	t.Setenv("REQUIRE_PHONE_VERIFICATION", "false")
	got, err := loadRegistrationConfig(RegistrationFileConfig{RequireEmail: boolPtr(false), RequirePhoneVerification: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	if !got.RequireEmail || got.RequirePhoneVerification {
		t.Errorf("env must override file: %+v", got)
	}
}

func TestLoadRegistrationConfig_InvalidEnv(t *testing.T) {
	for _, name := range []string{"REQUIRE_REGISTRATION_EMAIL", "REQUIRE_PHONE_VERIFICATION"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "maybe")
			if _, err := loadRegistrationConfig(RegistrationFileConfig{}); err == nil {
				t.Error("expected an error for an unparsable value")
			}
		})
	}
}
