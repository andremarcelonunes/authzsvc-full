package auth

import (
	"golang.org/x/crypto/bcrypt"
	"github.com/you/authzsvc/domain"
)

// PasswordServiceImpl implements domain.PasswordService
type PasswordServiceImpl struct {
	cost int
}

// NewPasswordService creates a new password service
func NewPasswordService() domain.PasswordService {
	return &PasswordServiceImpl{
		cost: bcrypt.DefaultCost,
	}
}

// Hash implements domain.PasswordService
func (p *PasswordServiceImpl) Hash(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), p.cost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

// Verify implements domain.PasswordService
func (p *PasswordServiceImpl) Verify(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}