package config

import "testing"

func TestLoadBootstrapConfig_EnvOverridesFile(t *testing.T) {
	fromFile := BootstrapConfig{
		RootAdmin:    BootstrapAccount{Email: "file-root@example.com", Phone: "+5511900000001", Password: "FilePass1"},
		ServiceAdmin: BootstrapAccount{Email: "file-svc@example.com"},
	}
	t.Setenv("ROOT_ADMIN_EMAIL", "env-root@example.com")
	t.Setenv("SERVICE_ADMIN_PASSWORD", "EnvSvcPass1")

	got := loadBootstrapConfig(fromFile)
	if got.RootAdmin.Email != "env-root@example.com" {
		t.Errorf("env must override file, got %q", got.RootAdmin.Email)
	}
	if got.RootAdmin.Phone != "+5511900000001" || got.RootAdmin.Password != "FilePass1" {
		t.Errorf("unset env vars must fall back to the file: %+v", got.RootAdmin)
	}
	if got.ServiceAdmin.Email != "file-svc@example.com" || got.ServiceAdmin.Password != "EnvSvcPass1" {
		t.Errorf("unexpected service admin: %+v", got.ServiceAdmin)
	}
}

func TestLoadBootstrapConfig_Absent(t *testing.T) {
	got := loadBootstrapConfig(BootstrapConfig{})
	if got != (BootstrapConfig{}) {
		t.Errorf("expected empty config, got %+v", got)
	}
}
