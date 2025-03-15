package token

import (
	"time"

	"github.com/golang-jwt/jwt"
)

type TokenManager interface {
	GenerateToken(subject string, expirationTime time.Duration) (string, error)
	ParseToken(tokenString string) (*jwt.StandardClaims, error)
	IsTokenBlacklisted(token string) bool
	AddToken(token string, email string, expirationTime time.Time)
	GetToken(email string, token string) (*TokenData, error)
	DeleteToken(token string) error
}
