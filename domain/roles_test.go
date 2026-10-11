package domain

import "testing"

func TestIsRoleAllowedForPublicRegistration(t *testing.T) {
	cases := map[string]bool{
		"":            true, // defaults to user
		RoleUser:      true,
		RoleClient:    true,
		RoleContact:   true,
		RoleRoot:      false,
		RoleAdmin:     false,
		RoleAttendant: false,
		"moderator":   false,
		"Admin":       false,
		"unknown":     false,
	}
	for role, want := range cases {
		if got := IsRoleAllowedForPublicRegistration(role); got != want {
			t.Errorf("IsRoleAllowedForPublicRegistration(%q) = %v, want %v", role, got, want)
		}
	}
}

func TestNormalizeRegistrationRole(t *testing.T) {
	if got := NormalizeRegistrationRole(""); got != RoleUser {
		t.Errorf("empty role should default to %q, got %q", RoleUser, got)
	}
	if got := NormalizeRegistrationRole(RoleClient); got != RoleClient {
		t.Errorf("client should be unchanged, got %q", got)
	}
}

func TestIsKnownRole(t *testing.T) {
	for _, r := range AllRoles() {
		if !IsKnownRole(r) {
			t.Errorf("%q should be known", r)
		}
	}
	for _, r := range []string{"", "moderator", "superuser"} {
		if IsKnownRole(r) {
			t.Errorf("%q should not be known", r)
		}
	}
}

// Every creator role x every target role.
func TestCanCreateRole_Matrix(t *testing.T) {
	allowed := map[string]map[string]bool{
		RoleRoot:  {RoleAdmin: true, RoleAttendant: true, RoleClient: true, RoleContact: true, RoleUser: true},
		RoleAdmin: {RoleAttendant: true, RoleClient: true, RoleContact: true, RoleUser: true},
	}
	creators := append(AllRoles(), "moderator", "")
	targets := append(AllRoles(), "moderator", "")
	for _, creator := range creators {
		for _, target := range targets {
			want := allowed[creator][target]
			if got := CanCreateRole(creator, target); got != want {
				t.Errorf("CanCreateRole(%q, %q) = %v, want %v", creator, target, got, want)
			}
		}
	}
}

func TestCreatableRoles_NobodyCreatesRoot(t *testing.T) {
	for _, creator := range AllRoles() {
		for _, r := range CreatableRoles(creator) {
			if r == RoleRoot {
				t.Errorf("%q must not be able to create root", creator)
			}
		}
	}
}
