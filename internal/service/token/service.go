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

// Ensure TokenService implements the TokenService interface.
var _ token.TokenService = (*tokenService)(nil)
var logger = config.GetServerConfig().Logger()

const tokenIssuer string = "vigilo-auth-server"
const module string = "Token Service"

type tokenService struct {
	tokenRepo            token.TokenRepository
	secretKey            string
	signingMethod        jwt.SigningMethod
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration
}

// NewTokenService creates a new TokenService instance.
//
// Parameters:
//
//	tokenRepo TokenRepository: The token store to use.
//
// Returns:
//
//	*TokenService: A new TokenService instance.
func NewTokenService(tokenRepo token.TokenRepository) token.TokenService {
	return &tokenService{
		tokenRepo:            tokenRepo,
		secretKey:            config.GetServerConfig().TokenConfig().SecretKey(),
		signingMethod:        config.GetServerConfig().TokenConfig().SigningMethod(),
		accessTokenDuration:  config.GetServerConfig().TokenConfig().AccessTokenDuration(),
		refreshTokenDuration: config.GetServerConfig().TokenConfig().RefreshTokenDuration(),
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
func (ts *tokenService) GenerateToken(subject, scopes string, expirationTime time.Duration) (string, error) {
	tokenString, err := ts.generateAndStoreToken(subject, "", scopes, expirationTime)
	if err != nil {
		logger.Error(module, "GenerateToken: Failed to generate token for subject=[%s]: %v", common.TruncateSensitive(subject), err)
		return "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate token")
	}

	return tokenString, nil
}

// GenerateTokensWithAudience generates an access & refresh token.
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
func (ts *tokenService) GenerateTokensWithAudience(userID, clientID, scopes string) (string, string, error) {
	accessToken, err := ts.generateAndStoreToken(userID, clientID, scopes, ts.accessTokenDuration)
	if err != nil {
		logger.Error(module, "GenerateTokenPair: Failed to generate access token for user=[%s], client=[%s]: %v",
			common.TruncateSensitive(userID),
			common.TruncateSensitive(clientID),
			err,
		)
		return "", "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate access token")
	}

	refreshToken, err := ts.generateAndStoreToken(userID, clientID, scopes, ts.refreshTokenDuration)
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
func (ts *tokenService) ParseToken(tokenString string) (*token.TokenClaims, error) {
	tokenClaims, err := jwt.ParseWithClaims(tokenString, &token.TokenClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New(errors.ErrCodeTokenParsing, "failed to parse token")
		}
		return []byte(ts.secretKey), nil
	})

	if err != nil {
		wrappedErr := errors.New(errors.ErrCodeTokenParsing, "failed to parse token")
		return nil, errors.Wrap(wrappedErr, errors.ErrCodeTokenParsing, "failed to parse JWT with claims")
	}

	if claims, ok := tokenClaims.Claims.(*token.TokenClaims); ok && tokenClaims.Valid {
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
func (ts *tokenService) IsTokenBlacklisted(token string) bool {
	hashedToken := crypto.EncodeSHA256(token)
	return ts.tokenRepo.IsTokenBlacklisted(hashedToken)
}

// BlacklistToken adds the specified token to the blacklist, preventing it from being used
// for further authentication or authorization. The token is marked as invalid, even if it
// has not yet expired.
//
// Parameters:
//
//		token (string): The token to be blacklisted. This is the token that will no longer
//	    be valid for further use.
//
// Returns:
//
//		error: An error if the token is not found in the token store or if it has already
//	    expired, in which case it cannot be blacklisted.
func (ts *tokenService) BlacklistToken(token string) error {
	hashedToken := crypto.EncodeSHA256(token)
	return ts.tokenRepo.BlacklistToken(hashedToken)
}

// SaveToken adds a token to the token store.
//
// Parameters:
//
//	token string: The token string to add.
//	id string: The id associated with the token.
//	expirationTime time.Time: The token's expiration time.
func (ts *tokenService) SaveToken(token string, id string, expirationTime time.Time) {
	hashedToken := crypto.EncodeSHA256(token)
	ts.tokenRepo.SaveToken(hashedToken, id, expirationTime)
}

// GetToken retrieves a token from the token store and validates it.
//
// Parameters:
//
//	token string: The token string to retrieve.
//
// Returns:
//
//	*TokenData: The TokenData if the token is valid, or nil if not found or invalid.
//	error: An error if the token is not found, expired, or the id doesn't match.
func (ts *tokenService) GetToken(token string) (*token.TokenData, error) {
	hashedToken := crypto.EncodeSHA256(token)
	retrievedToken := ts.tokenRepo.GetToken(hashedToken)
	if retrievedToken == nil {
		return nil, errors.New(errors.ErrCodeTokenNotFound, "failed to retrieve token")
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
func (ts *tokenService) DeleteToken(token string) error {
	hashedToken := crypto.EncodeSHA256(token)
	return ts.tokenRepo.DeleteToken(hashedToken)
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
func (ts *tokenService) DeleteTokenAsync(token string) <-chan error {
	logger.Info(module, "DeleteTokenAsync: Deleting token=[%s] asynchronously", common.TruncateSensitive(token))
	errChan := make(chan error, 1)

	go func() {
		maxRetries := 5
		var deleteErr error

		for i := range maxRetries {
			hashedToken := crypto.EncodeSHA256(token)
			if err := ts.tokenRepo.DeleteToken(hashedToken); err == nil {
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
func (ts *tokenService) IsTokenExpired(token string) bool {
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
func (ts *tokenService) ValidateToken(token string) error {
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
//	accessToken string: A new access token.
//	refreshToken string: A new refresh token.
//	error: An error if an error occurs during generation.
func (ts *tokenService) GenerateRefreshAndAccessTokens(subject, scopes string) (string, string, error) {
	refreshToken, err := ts.generateAndStoreToken(subject, "", scopes, ts.refreshTokenDuration)
	if err != nil {
		return "", "", err
	}

	accessToken, err := ts.generateAndStoreToken(subject, "", scopes, ts.accessTokenDuration)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
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
func (ts *tokenService) generateAndStoreToken(subject, audience, scopes string, duration time.Duration) (string, error) {
	maximumRetries := 5
	currentRetry := 0

	for currentRetry < maximumRetries {
		tokenExpiration := time.Now().Add(duration)
		claims, err := ts.generateStandardClaims(subject, audience, scopes, tokenExpiration.Unix())
		if err != nil {
			logger.Warn(module, "Failed to generate JWT Standard Claims. Incrementing retry count")
			currentRetry++
			continue
		}

		token := jwt.NewWithClaims(ts.signingMethod, claims)
		signedToken, err := token.SignedString([]byte(ts.secretKey))
		if err != nil {
			logger.Warn(module, "Failed to sign token. Incrementing retry count")
			currentRetry++
			continue
		}

		hashedToken := crypto.EncodeSHA256(signedToken)
		ts.tokenRepo.SaveToken(hashedToken, subject, tokenExpiration)
		logger.Info(module, "Successfully generated token after %d retries", currentRetry)
		return signedToken, nil
	}

	return "", errors.New(errors.ErrCodeInternalServerError, "failed to generate and store after maximum retries reached")
}

func (ts *tokenService) generateStandardClaims(subject, audience, scopes string, tokenExpiration int64) (*token.TokenClaims, error) {
	claims := &token.TokenClaims{
		StandardClaims: &jwt.StandardClaims{
			Subject:   subject,
			Issuer:    tokenIssuer,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: tokenExpiration,
		},
		Scopes: scopes,
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
