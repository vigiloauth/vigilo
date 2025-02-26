package security

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/vigiloauth/vigilo/identity/config"
)

// GenerateJWT generates a JWT token for the given email address.
// It uses the provided JWT configuration to sign the token.
func GenerateJWT(email string, jwtConfig config.JWTConfig) (string, error) {
	claims := &jwt.StandardClaims{
		Subject:   email,
		ExpiresAt: time.Now().Add(jwtConfig.ExpirationTime).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwtConfig.SigningMethod, claims)
	tokenString, err := token.SignedString([]byte(jwtConfig.Secret))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
