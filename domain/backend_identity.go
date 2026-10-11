package domain

import "context"

// BackendIdentityResolver translates this service's user id (the one carried by
// the JWT) into the user id used by the other services behind the gateway.
//
// found=false with a nil error means the user has no backend counterpart.
// Any error means the lookup could not be performed (the caller must fail closed).
type BackendIdentityResolver interface {
	ResolveBackendUserID(ctx context.Context, authzUserID uint) (backendID string, found bool, err error)
}
