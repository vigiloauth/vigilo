package token

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/identity/config"
)

type TokenService struct {
	jwtConfig *config.JWTConfig
}

func NewTokenService(jwtConfig *config.JWTConfig) *TokenService {
	return &TokenService{jwtConfig: jwtConfig}
}

func (ts *TokenService) GenerateToken(subject string, expirationTime time.Duration) (string, error) {
	claims := &jwt.StandardClaims{
		Subject:   subject,
		ExpiresAt: time.Now().Add(expirationTime).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	token := jwt.NewWithClaims(ts.jwtConfig.SigningMethod(), claims)
	tokenString, err := token.SignedString([]byte(ts.jwtConfig.Secret()))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (ts *TokenService) ParseToken(tokenString string) (*jwt.StandardClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(ts.jwtConfig.Secret()), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
