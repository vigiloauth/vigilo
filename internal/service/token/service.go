package service

import (
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/identity/config"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
)

// Ensure TokenService implements the TokenManager interface.
var _ token.TokenService = (*TokenServiceImpl)(nil)

const tokenIssuer string = "vigilo-auth-server"

// TokenServiceImpl implements the TokenManager interface using JWT.
type TokenServiceImpl struct {
	tokenConfig *config.TokenConfig
	tokenRepo   token.TokenRepository
}

// NewTokenServiceImpl creates a new TokenService instance.
//
// Parameters:
//
//	tokenRepo TokenRepository: The token store to use.
//
// Returns:
//
//	*TokenService: A new TokenService instance.
func NewTokenServiceImpl(tokenRepo token.TokenRepository) *TokenServiceImpl {
	return &TokenServiceImpl{
		tokenConfig: config.GetServerConfig().TokenConfig(),
		tokenRepo:   tokenRepo,
	}
}

// GenerateToken generates and saves a JWT token for the given subject and expiration time.
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
func (ts *TokenServiceImpl) GenerateToken(subject string, expirationTime time.Duration) (string, error) {
	tokenString, err := ts.generateAndStoreToken(subject, "", expirationTime)
	if err != nil {
		return "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate token")
	}

	return tokenString, nil
}

// GenerateTokenPair generates an access & refresh token.
//
// Parameters:
//
//	userID string: The ID of the user. Will be used as the subject.
//	clientID string: The ID of the client. Will be used as the audience.
//
// Returns:
//
//	string: The access token.
//	string: The refresh token.
//	error: An error if an error occurs while generating the tokens.
func (ts *TokenServiceImpl) GenerateTokenPair(userID, clientID string) (string, string, error) {
	accessToken, err := ts.generateAndStoreToken(userID, clientID, ts.tokenConfig.AccessTokenDuration())
	if err != nil {
		return "", "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate access token")
	}

	refreshToken, err := ts.generateAndStoreToken(userID, clientID, ts.tokenConfig.RefreshTokenDuration())
	if err != nil {
		return "", "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate refresh token")
	}

	return accessToken, refreshToken, nil
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
func (ts *TokenServiceImpl) ParseToken(tokenString string) (*jwt.StandardClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New(errors.ErrCodeTokenParsing, "failed to parse token")
		}
		return []byte(ts.tokenConfig.Secret()), nil
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
func (ts *TokenServiceImpl) IsTokenBlacklisted(token string) bool {
	return ts.tokenRepo.IsTokenBlacklisted(token)
}

// SaveToken adds a token to the token store.
//
// Parameters:
//
//	token string: The token string to add.
//	id string: The id associated with the token.
//	expirationTime time.Time: The token's expiration time.
func (ts *TokenServiceImpl) SaveToken(token string, id string, expirationTime time.Time) {
	ts.tokenRepo.SaveToken(token, id, expirationTime)
}

// GetToken retrieves a token from the token store and validates it.
//
// Parameters:
//
//	id string: The id to validate against.
//	token string: The token string to retrieve.
//
// Returns:
//
//	*TokenData: The TokenData if the token is valid, or nil if not found or invalid.
//	error: An error if the token is not found, expired, or the id doesn't match.
func (ts *TokenServiceImpl) GetToken(id string, token string) (*token.TokenData, error) {
	retrievedToken, err := ts.tokenRepo.GetToken(token, id)
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
func (ts *TokenServiceImpl) DeleteToken(token string) error {
	return ts.tokenRepo.DeleteToken(token)
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
func (ts *TokenServiceImpl) IsTokenExpired(token string) bool {
	claims, err := ts.ParseToken(token)
	if err != nil {
		return true
	}
	if claims == nil {
		return true
	}
	return time.Now().Unix() > claims.ExpiresAt
}

// ValidateToken checks to see if a token is blacklisted or expired.
//
// Parameters:
//
//	token string: The token string to check.
//
// Returns:
//
//	error: An error if the token is blacklisted or expired.
func (ts *TokenServiceImpl) ValidateToken(token string) error {
	if ts.IsTokenExpired(token) {
		return errors.New(errors.ErrCodeExpiredToken, "the token is expired")
	} else if ts.IsTokenBlacklisted(token) {
		return errors.New(errors.ErrCodeUnauthorized, "the token is blacklisted")
	}
	return nil
}

// generateAndStoreToken creates a signed JWT (JSON Web Token) with standard claims
// and then saves it to the TokenRepository.
//
// Parameters:
//
//	subject string: The subject (typically user ID) for whom the token is generated.
//	audience string: The intended recipient of the token (usually client ID).
//
// Returns:
//
//	string: A signed JWT token string.
//	error: An error if token generation or signing fails.
func (ts *TokenServiceImpl) generateAndStoreToken(subject, audience string, duration time.Duration) (string, error) {
	tokenExpiration := time.Now().Add(duration)
	claims := &jwt.StandardClaims{
		Subject:   subject,
		Issuer:    tokenIssuer,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: tokenExpiration.Unix(),
	}

	if audience != "" {
		claims.Audience = audience
	}

	token := jwt.NewWithClaims(ts.tokenConfig.SigningMethod(), claims)
	signedToken, err := token.SignedString([]byte(ts.tokenConfig.Secret()))
	if err != nil {
		return "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate token")
	}

	ts.tokenRepo.SaveToken(signedToken, subject, tokenExpiration)
	return signedToken, nil
}
