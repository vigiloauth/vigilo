package token

import (
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
)

type TokenService struct {
	jwtConfig  *config.JWTConfig
	tokenStore TokenStore
}

func NewTokenService(tokenStore TokenStore) *TokenService {
	return &TokenService{
		jwtConfig:  config.GetServerConfig().JWTConfig(),
		tokenStore: tokenStore,
	}
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
		return "", errors.Wrap(err, "Failed to retrieve the signed token")
	}

	return tokenString, nil
}

func (ts *TokenService) ParseToken(tokenString string) (*jwt.StandardClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.NewTokenGenerationError()
		}
		return []byte(ts.jwtConfig.Secret()), nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "Failed parse JWT with claims")
	}

	if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.NewInvalidTokenError()
}

func (ts *TokenService) IsTokenBlacklisted(token string) bool {
	return ts.tokenStore.IsTokenBlacklisted(token)
}

func (ts *TokenService) AddToken(token string, email string, expirationTime time.Time) {
	ts.tokenStore.AddToken(token, email, expirationTime)
}

func (ts *TokenService) GetToken(email string, token string) (*TokenData, error) {
	retrievedToken, err := ts.tokenStore.GetToken(token, email)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to retrieve token")
	}
	return retrievedToken, nil
}

func (ts *TokenService) DeleteToken(token string) error {
	return ts.tokenStore.DeleteToken(token)
}
