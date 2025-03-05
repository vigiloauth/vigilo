package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/identity/config"
)

// GenerateJWT generates a JWT token for the given email address.
// It uses the provided JWT configuration to sign the token.
func GenerateJWT(email string, jwtConfig config.JWTConfig) (string, error) {
	claims := &jwt.StandardClaims{
		Subject:   email,
		ExpiresAt: time.Now().Add(jwtConfig.ExpirationTime()).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwtConfig.SigningMethod(), claims)
	tokenString, err := token.SignedString([]byte(jwtConfig.Secret()))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ParseJWT parses and validates a JWT token and returns the claims.
func ParseJWT(tokenString string, jwtConfig config.JWTConfig) (*jwt.StandardClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(jwtConfig.Secret()), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
