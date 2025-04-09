package service

import (
	"math/rand"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	"github.com/vigiloauth/vigilo/internal/crypto"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
)

// Ensure TokenService implements the TokenManager interface.
var _ token.TokenService = (*TokenServiceImpl)(nil)
var logger = config.GetServerConfig().Logger()

const tokenIssuer string = "vigilo-auth-server"
const module string = "Token Service"

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
		logger.Error(module, "GenerateToken: Failed to generate token for subject=[%s]: %v", common.TruncateSensitive(subject), err)
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
		logger.Error(module, "GenerateTokenPair: Failed to generate access token for user=[%s], client=[%s]: %v",
			common.TruncateSensitive(userID),
			common.TruncateSensitive(clientID),
			err,
		)
		return "", "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate access token")
	}

	refreshToken, err := ts.generateAndStoreToken(userID, clientID, ts.tokenConfig.RefreshTokenDuration())
	if err != nil {
		logger.Error(module, "GenerateTokenPair: Failed to generate refresh token for user=[%s], client=[%s]: %v",
			common.TruncateSensitive(userID),
			common.TruncateSensitive(clientID),
			err,
		)
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
		return []byte(ts.tokenConfig.SecretKey()), nil
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
	hashedToken := crypto.HashSHA256(token)
	return ts.tokenRepo.IsTokenBlacklisted(hashedToken)
}

func (ts *TokenServiceImpl) BlacklistToken(token string) error {
	hashedToken := crypto.HashSHA256(token)
	return ts.tokenRepo.BlacklistToken(hashedToken)
}

// SaveToken adds a token to the token store.
//
// Parameters:
//
//	token string: The token string to add.
//	id string: The id associated with the token.
//	expirationTime time.Time: The token's expiration time.
func (ts *TokenServiceImpl) SaveToken(token string, id string, expirationTime time.Time) {
	hashedToken := crypto.HashSHA256(token)
	ts.tokenRepo.SaveToken(hashedToken, id, expirationTime)
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
	hashedToken := crypto.HashSHA256(token)
	retrievedToken, err := ts.tokenRepo.GetToken(hashedToken, id)
	if err != nil {
		logger.Error(module, "GetToken: Failed to retrieve token for ID=[%s]: %v", common.TruncateSensitive(id), err)
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

// DeleteToken removes a token from the token repository asynchronously.
//
// Parameters:
//
//	token string: The token string to delete.
//
// Returns:
//
//	error: An error if the token deletion fails.
func (ts *TokenServiceImpl) DeleteTokenAsync(token string) <-chan error {
	logger.Info(module, "DeleteTokenAsync: Deleting token=[%s] asynchronously", common.TruncateSensitive(token))
	errChan := make(chan error, 1)

	go func() {
		maxRetries := 5
		var deleteErr error

		for i := range maxRetries {
			if err := ts.tokenRepo.DeleteToken(token); err == nil {
				errChan <- nil
				return
			} else {
				deleteErr = err
			}

			backoff := time.Duration(100*(1<<i)) * time.Millisecond
			jitter := time.Duration(rand.Intn(100)) * time.Millisecond
			time.Sleep(backoff + jitter)
		}

		logger.Error(module, "DeleteTokenAsync: Failed to delete token=[%s] after %d retries: %v", common.TruncateSensitive(token), maxRetries, deleteErr)
		errChan <- deleteErr
	}()

	logger.Info(module, "DeleteTokenAsync: Token deleted successfully")
	return errChan
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
		logger.Warn(module, "IsTokenExpired: Token=[%s] is expired", common.TruncateSensitive(token))
		return true
	}
	if claims == nil {
		logger.Warn(module, "IsTokenExpired: Token=[%s] is expired", common.TruncateSensitive(token))
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
	if _, err := ts.ParseToken(token); err != nil {
		return errors.New(errors.ErrCodeInvalidGrant, "invalid token format")
	}
	if ts.IsTokenExpired(token) {
		logger.Warn(module, "ValidateToken: Token=[%s] is expired", common.TruncateSensitive(token))
		return errors.New(errors.ErrCodeExpiredToken, "the token is expired")
	} else if ts.IsTokenBlacklisted(token) {
		logger.Warn(module, "ValidateToken: Token=[%s] is blacklisted", common.TruncateSensitive(token))
		return errors.New(errors.ErrCodeUnauthorized, "the token is blacklisted")
	}
	return nil
}

// GenerateRefreshAndAccessTokens generates new tokens with the given subject.
//
// Parameters:
//
//	subject string: The subject for the token claims.
//
//	Returns:
//
//	refreshToken string: A new refresh token.
//	accessToken string: A new access token.
//	error: An error if an error occurs during generation.
func (ts *TokenServiceImpl) GenerateRefreshAndAccessTokens(subject string) (string, string, error) {
	refreshToken, err := ts.generateAndStoreToken(subject, "", config.GetServerConfig().TokenConfig().RefreshTokenDuration())
	if err != nil {
		return "", "", err
	}

	accessToken, err := ts.generateAndStoreToken(subject, "", config.GetServerConfig().TokenConfig().AccessTokenDuration())
	if err != nil {
		return "", "", err
	}

	return refreshToken, accessToken, nil
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
	maximumRetries := 5
	currentRetry := 0

	for currentRetry < maximumRetries {
		tokenExpiration := time.Now().Add(duration)
		claims, err := ts.generateStandardClaims(subject, audience, tokenExpiration.Unix())
		if err != nil {
			logger.Warn(module, "Failed to generate JWT Standard Claims. Incrementing retry count")
			currentRetry++
			continue
		}

		token := jwt.NewWithClaims(ts.tokenConfig.SigningMethod(), claims)
		signedToken, err := token.SignedString([]byte(ts.tokenConfig.SecretKey()))
		if err != nil {
			logger.Warn(module, "Failed to sign token. Incrementing retry count")
			currentRetry++
			continue
		}

		hashedToken := crypto.HashSHA256(signedToken)
		ts.tokenRepo.SaveToken(hashedToken, subject, tokenExpiration)
		logger.Info(module, "Successfully generated token after %d retries", currentRetry)
		return signedToken, nil
	}

	return "", errors.New(errors.ErrCodeInternalServerError, "failed to generate and store after maximum retries reached")
}

func (ts *TokenServiceImpl) generateStandardClaims(subject, audience string, tokenExpiration int64) (*jwt.StandardClaims, error) {
	claims := &jwt.StandardClaims{
		Subject:   subject,
		Issuer:    tokenIssuer,
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: tokenExpiration,
	}

	tokenID, err := crypto.GenerateRandomString(32)
	if err != nil || ts.tokenRepo.ExistsByTokenID(tokenID) {
		logger.Warn(module, "failed to generate JWT Standard Claims: %v", err)
		return nil, err
	} else {
		claims.Id = tokenID
	}

	if audience != "" {
		claims.Audience = audience
	}

	return claims, nil
}
