package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/you/authzsvc/domain"
)

// AuthMW wraps the token service and session repository for middleware
type AuthMW struct {
	tokenSvc    domain.TokenService
	sessionRepo domain.SessionRepository
}

// NewAuthMW creates new auth middleware wrapper
func NewAuthMW(tokenSvc domain.TokenService, sessionRepo domain.SessionRepository) *AuthMW {
	return &AuthMW{
		tokenSvc:    tokenSvc,
		sessionRepo: sessionRepo,
	}
}

// WithJWT returns the JWT middleware function
func (mw *AuthMW) WithJWT() gin.HandlerFunc {
	return AuthMiddleware(mw.tokenSvc, mw.sessionRepo)
}