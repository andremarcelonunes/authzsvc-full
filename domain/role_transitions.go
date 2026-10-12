package domain

// NextRoleOnAddProfile is the rule for a user adding the other profile to their own account.
// current is the role stored for the user and add is the profile asked for ("client" or "contact").
// It returns the resulting role:
//
//	user                -> client | contact
//	client  + contact   -> client_contact
//	contact + client    -> client_contact
//	a profile already held (client+client, contact+contact, client_contact+either) -> unchanged
//
// Anything else (including any attempt to reach attendant, admin, root or user, and callers whose
// role is attendant, admin or root) fails with ErrRoleTransitionNotAllowed.
func NextRoleOnAddProfile(current, add string) (string, error) {
	if add != RoleClient && add != RoleContact {
		return "", ErrRoleTransitionNotAllowed
	}
	switch current {
	case RoleUser:
		return add, nil
	case RoleClient:
		if add == RoleClient {
			return RoleClient, nil
		}
		return RoleClientContact, nil
	case RoleContact:
		if add == RoleContact {
			return RoleContact, nil
		}
		return RoleClientContact, nil
	case RoleClientContact:
		return RoleClientContact, nil
	default:
		return "", ErrRoleTransitionNotAllowed
	}
}
