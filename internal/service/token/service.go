package service

import (
	"context"
	"math/rand"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/idp/config"
	"github.com/vigiloauth/vigilo/internal/crypto"
	token "github.com/vigiloauth/vigilo/internal/domain/token"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/utils"
)

// Ensure TokenService implements the TokenService interface.
var _ token.TokenService = (*tokenService)(nil)

type tokenService struct {
	tokenRepo            token.TokenRepository
	secretKey            string
	tokenIssuer          string
	signingMethod        jwt.SigningMethod
	accessTokenDuration  time.Duration
	refreshTokenDuration time.Duration

	logger *config.Logger
	module string
}

// NewTokenService creates a new TokenService instance.
//
// Parameters:
//   - tokenRepo TokenRepository: The token store to use.
//
// Returns:
//   - *TokenService: A new TokenService instance.
func NewTokenService(tokenRepo token.TokenRepository) token.TokenService {
	return &tokenService{
		tokenRepo:            tokenRepo,
		secretKey:            config.GetServerConfig().TokenConfig().SecretKey(),
		tokenIssuer:          config.GetServerConfig().TokenConfig().Issuer(),
		signingMethod:        config.GetServerConfig().TokenConfig().SigningMethod(),
		accessTokenDuration:  config.GetServerConfig().TokenConfig().AccessTokenDuration(),
		refreshTokenDuration: config.GetServerConfig().TokenConfig().RefreshTokenDuration(),
		logger:               config.GetServerConfig().Logger(),
		module:               "Token Service",
	}
}

// GenerateToken generates a JWT token for the given subject and expiration time.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - subject string: The subject of the token (e.g., user email).
//   - scopes string: The scopes to be added to the token (can be an empty string if none are needed)..
//   - roles string: The roles to be added to the token (can be an empty string if none are needed).
//   - expirationTime time.Duration: The duration for which the token is valid.
//
// Returns:
//   - string: The generated JWT token string.
//   - error: An error if token generation fails.
func (ts *tokenService) GenerateToken(ctx context.Context, subject, scopes, roles string, expirationTime time.Duration) (string, error) {
	requestID := utils.GetRequestID(ctx)
	tokenString, err := ts.generateAndStoreToken(ctx, subject, "", scopes, roles, expirationTime)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[GenerateToken]: Failed to generate token: %v", err)
		return "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate token")
	}

	return tokenString, nil
}

// GenerateTokensWithAudience generates an access & refresh token.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - userID string: The ID of the user. Will be used as the subject.
//   - clientID string: The ID of the client. Will be used as the audience.
//   - scopes string: The scopes to be added to the token (can be an empty string if none are needed)..
//   - roles string: The roles to be added to the token (can be an empty string if none are needed).
//
// Returns:
//   - string: The access token.
//   - string: The refresh token.
//   - error: An error if an error occurs while generating the tokens.
func (ts *tokenService) GenerateTokensWithAudience(ctx context.Context, userID, clientID, scopes, roles string) (string, string, error) {
	requestID := utils.GetRequestID(ctx)
	accessToken, err := ts.generateAndStoreToken(ctx, userID, clientID, scopes, roles, ts.accessTokenDuration)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[GenerateTokenPair]: Failed to generate access token for user=[%s], client=[%s]: %v",
			utils.TruncateSensitive(userID),
			utils.TruncateSensitive(clientID),
			err,
		)
		return "", "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate access token")
	}

	refreshToken, err := ts.generateAndStoreToken(ctx, userID, clientID, scopes, roles, ts.refreshTokenDuration)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[GenerateTokenPair]: Failed to generate refresh token for user=[%s], client=[%s]: %v",
			utils.TruncateSensitive(userID),
			utils.TruncateSensitive(clientID),
			err,
		)
		return "", "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate refresh token")
	}

	return accessToken, refreshToken, nil
}

// ParseToken parses and validates a JWT token string.
//
// Parameters:
//   - tokenString string: The JWT token string to parse.
//
// Returns:
//   - *TokenClaims: The parsed standard claims from the token.
//   - error: An error if token parsing or validation fails.
func (ts *tokenService) ParseToken(tokenString string) (*token.TokenClaims, error) {
	tokenClaims, err := jwt.ParseWithClaims(tokenString, &token.TokenClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New(errors.ErrCodeTokenParsing, "failed to parse token")
		}
		return []byte(ts.secretKey), nil
	})

	if err != nil {
		ts.logger.Error(ts.module, "", "[ParseToken]: An error occurred parsing token: %v", err)
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
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token string to check.
//
// Returns:
//   - bool: True if the token is blacklisted, false otherwise.
//   - error: An error if querying the database fails.
func (ts *tokenService) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	requestID := utils.GetRequestID(ctx)
	hashedToken := crypto.EncodeSHA256(token)

	isBlacklisted, err := ts.tokenRepo.IsTokenBlacklisted(ctx, hashedToken)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[IsTokenBlacklisted]: An error occurred searching for the token: %v", err)
		return false, errors.NewInternalServerError()
	}
	return isBlacklisted, nil
}

// BlacklistToken adds the specified token to the blacklist, preventing it from being used
// for further authentication or authorization. The token is marked as invalid, even if it
// has not yet expired.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token to be blacklisted. This is the token that will no longer be valid for further use.
//
// Returns:
//   - error: An error if the token is not found in the token store or if it has already expired, in which case it cannot be blacklisted.
func (ts *tokenService) BlacklistToken(ctx context.Context, token string) error {
	requestID := utils.GetRequestID(ctx)

	hashedToken := crypto.EncodeSHA256(token)
	err := ts.tokenRepo.BlacklistToken(ctx, hashedToken)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[BlacklistToken]: An error occurred blacklisting a token: %v", err)
		return errors.NewInternalServerError()
	}

	return nil
}

// SaveToken adds a token to the token store.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token string to add.
//   - id string: The id associated with the token.
//   - expirationTime time.Time: The token's expiration time.
//
// Returns:
//   - error: If a database error occurs.
func (ts *tokenService) SaveToken(ctx context.Context, token string, id string, expirationTime time.Time) error {
	requestID := utils.GetRequestID(ctx)
	hashedToken := crypto.EncodeSHA256(token)

	err := ts.tokenRepo.SaveToken(ctx, hashedToken, id, expirationTime)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[SaveToken]: An error occurred saving the token: %v", err)
		return errors.NewInternalServerError()
	}

	return nil
}

// GetToken retrieves a token from the token store and validates it.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token string to retrieve.
//
// Returns:
//   - *TokenData: The TokenData if the token is valid, or nil if not found or invalid.
//   - error: An error if the token is not found, expired, or the subject doesn't match.
func (ts *tokenService) GetToken(ctx context.Context, token string) (*token.TokenData, error) {
	requestID := utils.GetRequestID(ctx)
	hashedToken := crypto.EncodeSHA256(token)

	retrievedToken, err := ts.tokenRepo.GetToken(ctx, hashedToken)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[GetToken]: Failed to retrieve token: %v", err)
		return nil, errors.NewInternalServerError()
	}

	if retrievedToken == nil {
		return nil, errors.New(errors.ErrCodeTokenNotFound, "failed to retrieve token")
	}

	return retrievedToken, nil
}

// DeleteToken removes a token from the token repository.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token string to delete.
//
// Returns:
//   - error: An error if the token deletion fails.
func (ts *tokenService) DeleteToken(ctx context.Context, token string) error {
	requestID := utils.GetRequestID(ctx)
	hashedToken := crypto.EncodeSHA256(token)

	err := ts.tokenRepo.DeleteToken(ctx, hashedToken)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[DeleteToken]: An error occurred deleting a token: %v", err)
		return errors.NewInternalServerError()
	}

	return nil
}

// DeleteToken removes a token from the token repository asynchronously.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token string to delete.
//
// Returns:
//   - error: An error if the token deletion fails.
func (ts *tokenService) DeleteTokenAsync(ctx context.Context, token string) <-chan error {
	errChan := make(chan error, 1)
	requestID := utils.GetRequestID(ctx)

	go func() {
		maxRetries := 5
		var deleteErr error

		for i := range maxRetries {
			hashedToken := crypto.EncodeSHA256(token)
			if err := ts.tokenRepo.DeleteToken(ctx, hashedToken); err == nil {
				errChan <- nil
				return
			} else {
				deleteErr = err
			}

			backoff := time.Duration(100*(1<<i)) * time.Millisecond
			jitter := time.Duration(rand.Intn(100)) * time.Millisecond
			time.Sleep(backoff + jitter)
		}

		ts.logger.Error(ts.module, requestID, "[DeleteTokenAsync]: Failed to delete token=[%s] after %d retries: %v", utils.TruncateSensitive(token), maxRetries, deleteErr)
		errChan <- deleteErr
	}()

	return errChan
}

// IsTokenExpired checks to see if the provided token is expired.
//
// Parameters:
//   - token string: The token string
//
// Returns:
//   - bool: True is expired, otherwise false.
func (ts *tokenService) IsTokenExpired(token string) bool {
	claims, err := ts.ParseToken(token)
	if err != nil {
		ts.logger.Warn(ts.module, "", "[IsTokenExpired]: Token=[%s] is expired", utils.TruncateSensitive(token))
		return true
	}
	if claims == nil {
		ts.logger.Warn(ts.module, "", "[IsTokenExpired]: Token=[%s] is expired", utils.TruncateSensitive(token))
		return true
	}

	return time.Now().Unix() > claims.ExpiresAt
}

// ValidateToken checks to see if a token is blacklisted or expired.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token string to check.
//
// Returns:
//   - error: An error if the token is blacklisted or expired.
func (ts *tokenService) ValidateToken(ctx context.Context, token string) error {
	requestID := utils.GetRequestID(ctx)

	if _, err := ts.ParseToken(token); err != nil {
		ts.logger.Error(ts.module, requestID, "[ValidateToken]: An error occurred parsing the token: %v", err)
		return errors.New(errors.ErrCodeInvalidGrant, "invalid token format")
	} else if ts.IsTokenExpired(token) {
		ts.logger.Warn(ts.module, "[ValidateToken]: Token=[%s] is expired", utils.TruncateSensitive(token))
		return errors.New(errors.ErrCodeExpiredToken, "the token is expired")
	}

	isTokenBlacklisted, err := ts.IsTokenBlacklisted(ctx, token)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[ValidateToken]: An error occurred validating the token: %v", err)
		return err
	} else if isTokenBlacklisted {
		ts.logger.Warn(ts.module, requestID, "[ValidateToken]: Token is blacklisted")
		return errors.New(errors.ErrCodeUnauthorized, "the token is blacklisted")
	}

	return nil
}

// GenerateRefreshAndAccessTokens generates new tokens with the given subject.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - subject string: The subject for the token claims.
//   - scopes string: The scopes to be added to the token (can be an empty string if none are needed)..
//   - roles string: The roles to be added to the token (can be an empty string if none are needed).
//
// Returns:
//   - accessToken string: A new access token.
//   - refreshToken string: A new refresh token.
//   - error: An error if an error occurs during generation.
func (ts *tokenService) GenerateRefreshAndAccessTokens(ctx context.Context, subject, scopes, roles string) (string, string, error) {
	requestID := utils.GetRequestID(ctx)

	refreshToken, err := ts.generateAndStoreToken(ctx, subject, "", scopes, roles, ts.refreshTokenDuration)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[GenerateRefreshAndAccessToken]: An error occurred generating a refresh token: %v", err)
		return "", "", err
	}

	accessToken, err := ts.generateAndStoreToken(ctx, subject, "", scopes, roles, ts.accessTokenDuration)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[GenerateRefreshAndAccessToken]: An error occurred generating an access token: %v", err)
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// DeleteExpiredTokens retrieves expired tokens from the repository and deletes them.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//
// Returns:
//   - error: An error if retrieval or deletion fails.
func (ts *tokenService) DeleteExpiredTokens(ctx context.Context) error {
	tokens, err := ts.tokenRepo.GetExpiredTokens(ctx)
	if err != nil {
		ts.logger.Error(ts.module, "", "[DeleteExpiredTokens]: An error occurred retrieving expired tokens: %v", err)
		return err
	}

	for _, token := range tokens {
		if err := ts.tokenRepo.DeleteToken(ctx, token.Token); err != nil {
			ts.logger.Error(ts.module, "", "[DeleteExpiredTokens]: An error occurred deleting expired tokens: %v", err)
			return err
		}
	}

	return nil
}

func (ts *tokenService) generateAndStoreToken(ctx context.Context, subject, audience, scopes, roles string, duration time.Duration) (string, error) {
	maximumRetries := 5
	currentRetry := 0

	for currentRetry < maximumRetries {
		tokenExpiration := time.Now().Add(duration)
		claims, err := ts.generateStandardClaims(ctx, subject, audience, scopes, roles, tokenExpiration.Unix())
		if err != nil {
			ts.logger.Warn(ts.module, "", "Failed to generate JWT Standard Claims. Incrementing retry count")
			currentRetry++
			continue
		}

		token := jwt.NewWithClaims(ts.signingMethod, claims)
		signedToken, err := token.SignedString([]byte(ts.secretKey))
		if err != nil {
			ts.logger.Warn(ts.module, "", "Failed to sign token. Incrementing retry count")
			currentRetry++
			continue
		}

		hashedToken := crypto.EncodeSHA256(signedToken)
		ts.tokenRepo.SaveToken(ctx, hashedToken, subject, tokenExpiration)
		ts.logger.Info(ts.module, "", "Successfully generated token after %d retries", currentRetry)
		return signedToken, nil
	}

	return "", errors.New(errors.ErrCodeInternalServerError, "failed to generate and store after maximum retries reached")
}

func (ts *tokenService) generateStandardClaims(ctx context.Context, subject, audience, scopes, roles string, tokenExpiration int64) (*token.TokenClaims, error) {
	claims := &token.TokenClaims{
		StandardClaims: &jwt.StandardClaims{
			Subject:   subject,
			Issuer:    ts.tokenIssuer,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: tokenExpiration,
		},
		Scopes: scopes,
		Roles:  roles,
	}

	requestID := utils.GetRequestID(ctx)
	tokenID, err := crypto.GenerateRandomString(32)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "Failed to generate token ID: %v", err)
		return nil, errors.NewInternalServerError()
	}

	existsByID, err := ts.tokenRepo.ExistsByTokenID(ctx, tokenID)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "An error occurred retrieving the token: %v", err)
		return nil, err
	} else if existsByID {
		ts.logger.Warn(ts.module, requestID, "Failed to generate standard claims. Token already exists.")
		return nil, nil
	} else {
		claims.Id = tokenID
	}

	if audience != "" {
		claims.Audience = audience
	}

	return claims, nil
}
