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
	if len(groupings) != 5 {
		t.Errorf("expected 5 grouping policies after two runs, got %d: %v", len(groupings), groupings)
	}
}
