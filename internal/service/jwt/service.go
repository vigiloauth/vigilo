package service

import (
	"context"
	"crypto/rsa"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/jwt"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ domain.JWTService = (*jwtService)(nil)

type jwtService struct {
	publicKey  *rsa.PublicKey
	privateKey *rsa.PrivateKey
	keyID      string

	logger *config.Logger
	module string
}

func NewJWTService() domain.JWTService {
	return &jwtService{
		publicKey:  config.GetServerConfig().TokenConfig().PublicKey(),
		privateKey: config.GetServerConfig().TokenConfig().SecretKey(),
		keyID:      config.GetServerConfig().TokenConfig().KeyID(),
		logger:     config.GetServerConfig().Logger(),
		module:     "JWT Service",
	}
}

func (s *jwtService) ParseWithClaims(ctx context.Context, tokenString string) (*tokens.TokenClaims, error) {
	requestID := utils.GetRequestID(ctx)

	tokenClaims, err := jwt.ParseWithClaims(tokenString, &tokens.TokenClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			s.logger.Error(s.module, requestID, "[ParseWithClaims]: Unexpected signing method received")
			return nil, errors.New(errors.ErrCodeTokenParsing, "unexpected signing method")
		}
		return s.publicKey, nil
	})

	if err != nil {
		s.logger.Error(s.module, requestID, "[ParseWithClaims]: An error occurred parsing the token: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeTokenParsing, "failed to parse JWT with claims")
	}

	if claims, ok := tokenClaims.Claims.(*tokens.TokenClaims); ok && tokenClaims.Valid {
		return claims, nil
	}

	return nil, errors.New(errors.ErrCodeInvalidToken, "provided token is invalid")
}

func (s *jwtService) SignToken(ctx context.Context, claims *tokens.TokenClaims) (string, error) {
	jwtClaims := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	jwtClaims.Header["kid"] = s.keyID
	return jwtClaims.SignedString(s.privateKey)
}
