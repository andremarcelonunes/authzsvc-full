package domain

import (
	"errors"
	"testing"
)

func TestNextRoleOnAddProfile(t *testing.T) {
	tests := []struct {
		current, add, want string
		wantErr            bool
	}{
		{RoleUser, RoleClient, RoleClient, false},
		{RoleUser, RoleContact, RoleContact, false},
		{RoleClient, RoleContact, RoleClientContact, false},
		{RoleContact, RoleClient, RoleClientContact, false},
		// already held: no-op
		{RoleClient, RoleClient, RoleClient, false},
		{RoleContact, RoleContact, RoleContact, false},
		{RoleClientContact, RoleClient, RoleClientContact, false},
		{RoleClientContact, RoleContact, RoleClientContact, false},
		// privileged callers
		{RoleAttendant, RoleClient, "", true},
		{RoleAttendant, RoleContact, "", true},
		{RoleAdmin, RoleClient, "", true},
		{RoleRoot, RoleContact, "", true},
		// unknown / empty callers
		{"", RoleClient, "", true},
		{"moderator", RoleContact, "", true},
		// forbidden targets, whatever the caller
		{RoleUser, RoleAttendant, "", true},
		{RoleUser, RoleAdmin, "", true},
		{RoleUser, RoleRoot, "", true},
		{RoleUser, RoleUser, "", true},
		{RoleUser, RoleClientContact, "", true},
		{RoleClient, RoleAttendant, "", true},
		{RoleClientContact, RoleAdmin, "", true},
		{RoleUser, "", "", true},
		{RoleUser, "moderator", "", true},
	}
	for _, tc := range tests {
		got, err := NextRoleOnAddProfile(tc.current, tc.add)
		if tc.wantErr {
			if !errors.Is(err, ErrRoleTransitionNotAllowed) || got != "" {
				t.Errorf("NextRoleOnAddProfile(%q, %q) = (%q, %v), want ErrRoleTransitionNotAllowed", tc.current, tc.add, got, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("NextRoleOnAddProfile(%q, %q) = (%q, %v), want %q", tc.current, tc.add, got, err, tc.want)
		}
	}
}

func TestClientContactIsNotSelfRegistrable(t *testing.T) {
	if IsRoleAllowedForPublicRegistration(RoleClientContact) {
		t.Error("client_contact must not be allowed in public registration")
	}
	if !CanCreateRole(RoleRoot, RoleClientContact) || !CanCreateRole(RoleAdmin, RoleClientContact) {
		t.Error("root and admin must be able to create client_contact")
	}
	for _, creator := range []string{RoleAttendant, RoleClient, RoleContact, RoleUser, RoleClientContact} {
		if CanCreateRole(creator, RoleClientContact) {
			t.Errorf("%q must not create client_contact", creator)
		}
	}
}
