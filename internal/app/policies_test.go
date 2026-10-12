package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/casbin/casbin/v2"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
)

func newTestEnforcer(t *testing.T) *casbin.Enforcer {
	t.Helper()
	policyFile := filepath.Join(t.TempDir(), "policy.csv")
	if err := os.WriteFile(policyFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := casbin.NewEnforcer("../../casbin/model.conf", fileadapter.NewAdapter(policyFile))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEnsureStandardPolicies_RoleHierarchy(t *testing.T) {
	e := newTestEnforcer(t)
	if err := EnsureStandardPolicies(e); err != nil {
		t.Fatal(err)
	}

	for _, g := range [][2]string{
		{"role_admin", "role_user"},
		{"role_root", "role_admin"},
		{"role_client", "role_user"},
		{"role_contact", "role_user"},
		{"role_attendant", "role_user"},
		{"role_client_contact", "role_client"},
		{"role_client_contact", "role_contact"},
	} {
		if ok, _ := e.HasGroupingPolicy(g[0], g[1]); !ok {
			t.Errorf("missing grouping %v", g)
		}
	}

	allow := []struct{ sub, obj, act string }{
		{"role_root", "/admin/users", "POST"},
		{"role_root", "/admin/policies", "GET"},
		{"role_admin", "/admin/users", "POST"},
		{"role_client", "/auth/me", "GET"},
		{"role_contact", "/auth/me", "GET"},
		{"role_attendant", "/auth/me", "GET"},
		{"role_client_contact", "/auth/me", "GET"},
		// every user-level role may call the profile endpoint (the service decides the transition)
		{"role_user", "/auth/roles", "POST"},
		{"role_client", "/auth/roles", "POST"},
		{"role_contact", "/auth/roles", "POST"},
		{"role_client_contact", "/auth/roles", "POST"},
	}
	for _, c := range allow {
		if ok, err := e.Enforce(c.sub, c.obj, c.act); err != nil || !ok {
			t.Errorf("%s %s %s should be permitted (err=%v)", c.sub, c.obj, c.act, err)
		}
	}
	deny := []struct{ sub, obj, act string }{
		{"role_client", "/admin/users", "POST"},
		{"role_attendant", "/admin/users", "POST"},
		{"role_user", "/admin/users", "POST"},
		{"role_client_contact", "/admin/users", "POST"},
		{"role_user", "/auth/roles", "GET"},
	}
	for _, c := range deny {
		if ok, _ := e.Enforce(c.sub, c.obj, c.act); ok {
			t.Errorf("%s %s %s must be denied", c.sub, c.obj, c.act)
		}
	}
}

func TestEnsureStandardPolicies_Idempotent(t *testing.T) {
	e := newTestEnforcer(t)
	for i := 0; i < 2; i++ {
		if err := EnsureStandardPolicies(e); err != nil {
			t.Fatal(err)
		}
	}
	groupings, _ := e.GetGroupingPolicy()
	if len(groupings) != 7 {
		t.Errorf("expected 7 grouping policies after two runs, got %d: %v", len(groupings), groupings)
	}
}

// client_contact inherits the policies of BOTH role_client and role_contact (not just role_user).
func TestEnsureStandardPolicies_ClientContactInheritsBothRoles(t *testing.T) {
	e := newTestEnforcer(t)
	if err := EnsureStandardPolicies(e); err != nil {
		t.Fatal(err)
	}
	// Policies that exist only for the individual roles
	e.AddPolicy("role_client", "/v1/only-client", "GET", "*")
	e.AddPolicy("role_contact", "/v1/only-contact", "GET", "*")

	for _, path := range []string{"/v1/only-client", "/v1/only-contact"} {
		if ok, err := e.Enforce("role_client_contact", path, "GET"); err != nil || !ok {
			t.Errorf("role_client_contact must inherit %s (err=%v)", path, err)
		}
	}
	if ok, _ := e.Enforce("role_client", "/v1/only-contact", "GET"); ok {
		t.Error("role_client must not get contact-only policies")
	}
	if ok, _ := e.Enforce("role_contact", "/v1/only-client", "GET"); ok {
		t.Error("role_contact must not get client-only policies")
	}
}
