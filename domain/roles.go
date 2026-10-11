package domain

// User role names. This file is the single source of truth for role names and
// for the two role rule sets: who may be self-registered through the public
// endpoint and which roles each creator role may create.
const (
	RoleRoot      = "root"
	RoleAdmin     = "admin"
	RoleAttendant = "attendant"
	RoleClient    = "client"
	RoleContact   = "contact"
	RoleUser      = "user"
)

// DefaultRegistrationRole is applied when a registration request carries no role.
const DefaultRegistrationRole = RoleUser

// AllRoles lists every role known to the system.
func AllRoles() []string {
	return []string{RoleRoot, RoleAdmin, RoleAttendant, RoleClient, RoleContact, RoleUser}
}

// IsKnownRole reports whether role is one of the defined roles.
func IsKnownRole(role string) bool {
	for _, r := range AllRoles() {
		if r == role {
			return true
		}
	}
	return false
}

// PublicRegistrationRoles lists the roles that may be requested through the
// unauthenticated registration endpoint (unprivileged accounts only).
func PublicRegistrationRoles() []string {
	return []string{RoleUser, RoleClient, RoleContact}
}

// NormalizeRegistrationRole returns the default role for an empty role and the
// input unchanged otherwise.
func NormalizeRegistrationRole(role string) string {
	if role == "" {
		return DefaultRegistrationRole
	}
	return role
}

// IsRoleAllowedForPublicRegistration reports whether role may be self-registered.
// An empty role means the default role and is allowed.
func IsRoleAllowedForPublicRegistration(role string) bool {
	role = NormalizeRegistrationRole(role)
	for _, r := range PublicRegistrationRoles() {
		if r == role {
			return true
		}
	}
	return false
}

// CreatableRoles returns the roles a user with creatorRole may create through
// the privileged creation endpoint. Roles not listed (attendant, client,
// contact, user, unknown) create nobody; root can never be created via the API.
func CreatableRoles(creatorRole string) []string {
	switch creatorRole {
	case RoleRoot:
		return []string{RoleAdmin, RoleAttendant, RoleClient, RoleContact, RoleUser}
	case RoleAdmin:
		return []string{RoleAttendant, RoleClient, RoleContact, RoleUser}
	default:
		return nil
	}
}

// CanCreateRole reports whether a user with creatorRole may create an account
// with targetRole.
func CanCreateRole(creatorRole, targetRole string) bool {
	for _, r := range CreatableRoles(creatorRole) {
		if r == targetRole {
			return true
		}
	}
	return false
}
