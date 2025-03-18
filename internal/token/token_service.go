package token

import (
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var _ TokenManager = (*TokenService)(nil)

// TokenService implements the TokenManager interface using JWT.
type TokenService struct {
	jwtConfig  *config.JWTConfig // JWT configuration.
	tokenStore TokenStore        // Token store for blacklisting and retrieval.
}

// NewTokenService creates a new TokenService instance.
//
// Parameters:
//
//	tokenStore TokenStore: The token store to use.
//
// Returns:
//
//	*TokenService: A new TokenService instance.
func NewTokenService(tokenStore TokenStore) *TokenService {
	return &TokenService{
		jwtConfig:  config.GetServerConfig().JWTConfig(),
		tokenStore: tokenStore,
	}
}

// GenerateToken generates a JWT token for the given subject and expiration time.
//
// Parameters:
//
//	subject string: The subject of the token (e.g., user email).
//	expirationTime time.Duration: The duration for which the token is valid.
//
// Returns:
//
//	string: The generated JWT token string.
//	error: An error if token generation fails.
func (ts *TokenService) GenerateToken(subject string, expirationTime time.Duration) (string, error) {
	claims := &jwt.StandardClaims{
		Subject:   subject,
		ExpiresAt: time.Now().Add(expirationTime).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	token := jwt.NewWithClaims(ts.jwtConfig.SigningMethod(), claims)
	tokenString, err := token.SignedString([]byte(ts.jwtConfig.Secret()))
	if err != nil {
		return "", errors.Wrap(err, errors.ErrCodeTokenParsing, "failed to retrieve the signed token")
	}

	return tokenString, nil
}

// ParseToken parses and validates a JWT token string.
//
// Parameters:
//
//	tokenString string: The JWT token string to parse.
//
// Returns:
//
//	*jwt.StandardClaims: The parsed standard claims from the token.
//	error: An error if token parsing or validation fails.
func (ts *TokenService) ParseToken(tokenString string) (*jwt.StandardClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New(errors.ErrCodeTokenCreation, "failed to generate token")
		}
		return []byte(ts.jwtConfig.Secret()), nil
	})

	if err != nil {
		wrappedErr := errors.New(errors.ErrCodeTokenParsing, "failed to parse token")
		return nil, errors.Wrap(wrappedErr, errors.ErrCodeTokenParsing, "failed to parse JWT with claims")
	}

	if claims, ok := token.Claims.(*jwt.StandardClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New(errors.ErrCodeInvalidToken, "provided token is invalid")
}

// IsTokenBlacklisted checks if a token is blacklisted.
//
// Parameters:
//
//	token string: The token string to check.
//
// Returns:
//
//	bool: True if the token is blacklisted, false otherwise.
func (ts *TokenService) IsTokenBlacklisted(token string) bool {
	return ts.tokenStore.IsTokenBlacklisted(token)
}

// AddToken adds a token to the token store.
//
// Parameters:
//
//	token string: The token string to add.
//	email string: The email associated with the token.
//	expirationTime time.Time: The token's expiration time.
func (ts *TokenService) AddToken(token string, email string, expirationTime time.Time) {
	ts.tokenStore.AddToken(token, email, expirationTime)
}

// GetToken retrieves a token from the token store and validates it.
//
// Parameters:
//
//	email string: The email to validate against.
//	token string: The token string to retrieve.
//
// Returns:
//
//	*TokenData: The TokenData if the token is valid, or nil if not found or invalid.
//	error: An error if the token is not found, expired, or the email doesn't match.
func (ts *TokenService) GetToken(email string, token string) (*TokenData, error) {
	retrievedToken, err := ts.tokenStore.GetToken(token, email)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeTokenNotFound, "failed to retrieve token")
	}
	return retrievedToken, nil
}

// DeleteToken removes a token from the token store.
//
// Parameters:
//
//	token string: The token string to delete.
//
// Returns:
//
//	error: An error if the token deletion fails.
func (ts *TokenService) DeleteToken(token string) error {
	return ts.tokenStore.DeleteToken(token)
}

// IsTokenExpired checks if a token is expired.
//
// Parameters:
//
//	token string: The token string to check.
//
// Returns:
//
//	bool: True if the token is expired, false otherwise.
func (ts *TokenService) IsTokenExpired(token string) bool {
	claims, err := ts.ParseToken(token)
	if err != nil {
		return true
	}
	if claims == nil {
		return true
	}
	return time.Now().Unix() > claims.ExpiresAt
}
