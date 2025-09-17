package auth

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/you/authzsvc/domain"
)

// JWTServiceImpl implements domain.TokenService
type JWTServiceImpl struct {
	secretKey        []byte
	issuer           string
	accessTokenTTL   time.Duration
	refreshTokenTTL  time.Duration
}

// NewJWTService creates a new JWT service
func NewJWTService(secretKey string, issuer string, accessTTL, refreshTTL time.Duration) domain.TokenService {
	return &JWTServiceImpl{
		secretKey:       []byte(secretKey),
		issuer:          issuer,
		accessTokenTTL:  accessTTL,
		refreshTokenTTL: refreshTTL,
	}
}

// generateJTI creates a unique JWT ID
func (j *JWTServiceImpl) generateJTI() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// GenerateAccessToken implements domain.TokenService
func (j *JWTServiceImpl) GenerateAccessToken(userID uint, role string, sessionID string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"user_id":    userID,
		"role":       role,
		"session_id": sessionID,
		"iss":        j.issuer,
		"iat":        now.Unix(),
		"exp":        now.Add(j.accessTokenTTL).Unix(),
		"jti":        j.generateJTI(), // Unique JWT ID ensures token uniqueness
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secretKey)
}

// GenerateRefreshToken implements domain.TokenService
func (j *JWTServiceImpl) GenerateRefreshToken(userID uint, role string, sessionID string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"user_id":    userID,
		"role":       role,
		"session_id": sessionID,
		"iss":        j.issuer,
		"iat":        now.Unix(),
		"exp":        now.Add(j.refreshTokenTTL).Unix(),
		"jti":        j.generateJTI(), // Unique JWT ID ensures token uniqueness
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secretKey)
}

// ValidateAccessToken implements domain.TokenService
func (j *JWTServiceImpl) ValidateAccessToken(tokenString string) (*domain.TokenClaims, error) {
	return j.validateToken(tokenString)
}

// ValidateRefreshToken implements domain.TokenService
func (j *JWTServiceImpl) ValidateRefreshToken(tokenString string) (*domain.TokenClaims, error) {
	return j.validateToken(tokenString)
}

// validateToken validates a JWT token and returns claims
func (j *JWTServiceImpl) validateToken(tokenString string) (*domain.TokenClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, domain.ErrTokenMalformed
		}
		return j.secretKey, nil
	})

	if err != nil {
		return nil, domain.ErrTokenInvalid
	}

	if !token.Valid {
		return nil, domain.ErrTokenInvalid
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, domain.ErrTokenMalformed
	}

	// Extract claims
	userID, ok := claims["user_id"].(float64)
	if !ok {
		return nil, domain.ErrTokenMalformed
	}

	role, ok := claims["role"].(string)
	if !ok {
		return nil, domain.ErrTokenMalformed
	}

	iat, ok := claims["iat"].(float64)
	if !ok {
		return nil, domain.ErrTokenMalformed
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, domain.ErrTokenMalformed
	}

	// Check expiration
	if time.Unix(int64(exp), 0).Before(time.Now()) {
		return nil, domain.ErrTokenExpired
	}

	tokenClaims := &domain.TokenClaims{
		UserID:    uint(userID),
		Role:      role,
		IssuedAt:  int64(iat),
		ExpiresAt: int64(exp),
	}

	// Extract session ID if present (for refresh tokens)
	if sessionID, ok := claims["session_id"].(string); ok {
		tokenClaims.SessionID = sessionID
	}

	return tokenClaims, nil
}