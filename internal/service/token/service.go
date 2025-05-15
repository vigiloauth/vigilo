package service

import (
	"context"
	"crypto/rsa"
	"math/rand"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/square/go-jose/v3"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/crypto"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

// Ensure TokenService implements the TokenService interface.
var _ token.TokenService = (*tokenService)(nil)

type tokenService struct {
	tokenRepo            token.TokenRepository
	privateKey           *rsa.PrivateKey
	publicKey            *rsa.PublicKey
	keyID                string
	issuer               string
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
		privateKey:           config.GetServerConfig().TokenConfig().SecretKey(),
		publicKey:            config.GetServerConfig().TokenConfig().PublicKey(),
		keyID:                config.GetServerConfig().TokenConfig().KeyID(),
		issuer:               config.GetServerConfig().URL() + "/oauth2",
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
	tokenString, err := ts.generateAndStoreToken(ctx, subject, "", scopes, roles, "", expirationTime)
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
	accessToken, err := ts.generateAndStoreToken(ctx, userID, clientID, scopes, roles, "", ts.accessTokenDuration)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[GenerateTokenPair]: Failed to generate access token for user=[%s], client=[%s]: %v",
			utils.TruncateSensitive(userID),
			utils.TruncateSensitive(clientID),
			err,
		)
		return "", "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate access token")
	}

	refreshToken, err := ts.generateAndStoreToken(ctx, userID, clientID, scopes, roles, "", ts.refreshTokenDuration)
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

// GenerateIDToken creates an ID token for the specified user and client.
//
// The ID token is a JWT that contains claims about the authentication of the user.
// It includes information such as the user ID, client ID, scopes, and nonce for
// replay protection. The token is generated and then stored in the token store.
//
// Parameters:
//   - ctx context.Context: Context for the request, containing the request ID for logging.
//   - userID string: The unique identifier of the user.
//   - clientID string: The client application identifier requesting the token.
//   - scopes string: Space-separated list of requested scopes.
//   - nonce string: A random string used to prevent replay attacks.
//
// Returns:
//   - string: The signed ID token as a JWT string.
//   - error: An error if token generation fails.
func (ts *tokenService) GenerateIDToken(ctx context.Context, userID, clientID, scopes, nonce string) (string, error) {
	requestID := utils.GetRequestID(ctx)
	ts.logger.Debug(ts.module, requestID, "[GenerateIDToken]: Generating ID token. ClientID: %s, UserID: %s",
		utils.TruncateSensitive(clientID),
		utils.TruncateSensitive(userID),
	)

	idToken, err := ts.generateAndStoreToken(ctx, userID, clientID, scopes, "", nonce, ts.refreshTokenDuration)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[GenerateIDToken]: Failed to generate ID token: %v", err)
		return "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate ID token")
	}

	return idToken, nil
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
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New(errors.ErrCodeTokenParsing, "unexpected signing method")
		}
		return ts.publicKey, nil
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

// ParseAndValidateToken parses and validates a JWT token string, handling both encrypted and non-encrypted tokens.
//
// This function first attempts to parse the token directly. If parsing succeeds, the token is considered
// valid and non-encrypted. If parsing fails, the function attempts to decrypt the token first and then
// parse the decrypted token.
//
// Parameters:
//   - ctx ctx.Context: Context for the request, containing the request ID for logging.
//   - tokenString string: The JWT token string to parse and validate.
//
// Returns:
//   - *token.TokenClaims: The parsed token claims if successful.
//   - error: An error if token parsing, decryption, or validation fails.
//
// The function first tries to parse the token directly using ts.ParseToken. If this fails, it assumes
// the token is encrypted and attempts to decrypt it using ts.DecryptToken before parsing it again.
func (ts *tokenService) ParseAndValidateToken(ctx context.Context, tokenString string) (*token.TokenClaims, error) {
	requestID := utils.GetRequestID(ctx)
	ts.logger.Debug(ts.module, requestID, "[ParseAndValidateToken]: Beginning token validation process")
	ts.logger.Debug(ts.module, requestID, "[ParseAndValidateToken]: Attempting to parse token directly")

	claims, err := ts.ParseToken(tokenString)
	if err == nil {
		ts.logger.Debug(ts.module, requestID, "[ParseAndValidateToken]: Token is valid and not encrypted")
		ts.logger.Debug(ts.module, requestID, "[ParseAndValidateToken]: Token parsed successfully - Subject: %s, Expires: %v",
			utils.TruncateSensitive(claims.Subject),
			time.Unix(claims.ExpiresAt, 0))
		return claims, nil
	}

	ts.logger.Warn(ts.module, requestID, "[ParseAndValidateToken]: Failed to parse token directly, assuming it is encrypted: %v", err)
	ts.logger.Debug(ts.module, requestID, "[ParseAndValidateToken]: Attempting to decrypt token")

	decryptedToken, err := ts.DecryptToken(ctx, tokenString)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[ParseAndValidateToken]: Failed to decrypt token: %v", err)
		return nil, errors.New(errors.ErrCodeInvalidToken, "failed to parse or decrypt token")
	}

	ts.logger.Debug(ts.module, requestID, "[ParseAndValidateToken]: Token decryption successful")
	ts.logger.Debug(ts.module, requestID, "[ParseAndValidateToken]: Attempting to parse decrypted token")

	claims, err = ts.ParseToken(decryptedToken)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[ParseAndValidateToken]: Failed to parse decrypted token: %v", err)
		return nil, errors.New(errors.ErrCodeInvalidToken, "failed to parse decrypted token")
	}

	ts.logger.Debug(ts.module, requestID, "[ParseAndValidateToken]: Decrypted token parsed successfully - Subject: %s, Expires: %v",
		utils.TruncateSensitive(claims.Subject),
		time.Unix(claims.ExpiresAt, 0))

	ts.logger.Debug(ts.module, requestID, "[ParseAndValidateToken]: Token validation process completed successfully")
	return claims, nil
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
		return false, errors.Wrap(err, errors.ErrCodeInternalServerError, "an error occurred searching for the token")
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
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "an error occurred blacklisting the token")
	}

	return nil
}

// GetTokenData retrieves the token data from the token repository.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - token string: The token string to retrieve.
//
// Returns:
//   - *TokenData: The TokenData if the token is valid, or nil if not found or invalid.
//   - error: An error if the token is not found, expired, or the subject doesn't match.
func (ts *tokenService) GetTokenData(ctx context.Context, token string) (*token.TokenData, error) {
	requestID := utils.GetRequestID(ctx)
	hashedToken := crypto.EncodeSHA256(token)

	retrievedToken, err := ts.tokenRepo.GetToken(ctx, hashedToken)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[GetToken]: Failed to retrieve token: %v", err)
		return nil, errors.Wrap(err, "", "failed to retrieve token")
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
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "an error occurred deleting the given token")
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
	claims, err := ts.ParseAndValidateToken(context.TODO(), token)
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

	if ts.IsTokenExpired(token) {
		ts.logger.Warn(ts.module, "[ValidateToken]: Token=[%s] is expired", utils.TruncateSensitive(token))
		return errors.New(errors.ErrCodeExpiredToken, "the token is expired")
	} else if _, err := ts.ParseAndValidateToken(ctx, token); err != nil {
		ts.logger.Error(ts.module, requestID, "[ValidateToken]: An error occurred parsing the token: %v", err)
		return errors.New(errors.ErrCodeInvalidGrant, "invalid token format")
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

	refreshToken, err := ts.generateAndStoreToken(ctx, subject, "", scopes, roles, "", ts.refreshTokenDuration)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[GenerateRefreshAndAccessToken]: An error occurred generating a refresh token: %v", err)
		return "", "", err
	}

	accessToken, err := ts.generateAndStoreToken(ctx, subject, "", scopes, roles, "", ts.accessTokenDuration)
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
		return errors.Wrap(err, "", "an error occurred retrieving expired tokens")
	}

	for _, token := range tokens {
		if err := ts.tokenRepo.DeleteToken(ctx, token.Token); err != nil {
			ts.logger.Error(ts.module, "", "[DeleteExpiredTokens]: An error occurred deleting expired tokens: %v", err)
			return errors.Wrap(err, errors.ErrCodeInternalServerError, "an error occurred deleting expired tokens")
		}
	}

	return nil
}

// EncryptToken encrypts a signed JWT token using a specified encryption algorithm.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - signedToken string: The signed JWT token to be encrypted.
//
// Returns:
//   - string: The encrypted token in JWE (JSON Web Encryption) format.
//   - error: An error if the encryption process fails.
func (ts *tokenService) EncryptToken(ctx context.Context, signedToken string) (string, error) {
	requestID := utils.GetRequestID(ctx)
	encrypter, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.RSA_OAEP,
			Key:       ts.publicKey,
		}, nil,
	)

	if err != nil {
		ts.logger.Error(ts.module, requestID, "[EncryptToken]: An error occurred creating a new encrypter: %v", err)
		return "", errors.NewInternalServerError()
	}

	encrypted, err := encrypter.Encrypt([]byte(signedToken))
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[EncryptToken]: Failed to encrypt token: %v", err)
		return "", errors.NewInternalServerError()
	}

	serializedToken, err := encrypted.CompactSerialize()
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[EncryptToken]: Failed to serialize encrypted token: %v", err)
		return "", errors.NewInternalServerError()
	}

	return serializedToken, nil
}

// DecryptToken decrypts an encrypted JWT token back to its original signed form.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - encryptedToken string: The encrypted JWT token in JWE format.
//
// Returns:
//   - string: The decrypted signed JWT token.
//   - error: An error if the decryption process fails.
func (ts *tokenService) DecryptToken(ctx context.Context, encryptedToken string) (string, error) {
	requestID := utils.GetRequestID(ctx)

	token := strings.TrimPrefix(encryptedToken, "bearer ")
	object, err := jose.ParseEncrypted(token)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[DecryptToken]: Failed to parse encrypted token: %v", err)
		return "", errors.New(errors.ErrCodeInvalidToken, "failed to parse encrypted token")
	}

	decrypted, err := object.Decrypt(ts.privateKey)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[DecryptToken]: Failed to decrypt token: %v", err)
		return "", errors.New(errors.ErrCodeInvalidToken, "failed to decrypt token")
	}

	return string(decrypted), nil
}

func (ts *tokenService) generateAndStoreToken(ctx context.Context, subject, audience, scopes, roles, nonce string, duration time.Duration) (string, error) {
	maximumRetries := 5
	currentRetry := 0

	for currentRetry < maximumRetries {
		tokenExpiration := time.Now().Add(duration)
		claims, err := ts.generateStandardClaims(ctx, subject, audience, scopes, roles, nonce, tokenExpiration.Unix())
		if err != nil {
			ts.logger.Warn(ts.module, "", "Failed to generate JWT Standard Claims. Incrementing retry count")
			currentRetry++
			continue
		}

		jwtClaims := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		jwtClaims.Header["kid"] = ts.keyID

		signedToken, err := jwtClaims.SignedString(ts.privateKey)
		if err != nil {
			ts.logger.Warn(ts.module, "", "Failed to sign token. Incrementing retry count")
			currentRetry++
			continue
		}

		hashedToken := crypto.EncodeSHA256(signedToken)
		tokenData := &token.TokenData{
			Token:     hashedToken,
			ID:        subject,
			ExpiresAt: tokenExpiration,
			TokenID:   ts.keyID,
			Claims:    claims,
		}

		ts.tokenRepo.SaveToken(ctx, hashedToken, subject, tokenData, tokenExpiration)
		ts.logger.Info(ts.module, "", "Successfully generated token after %d retries", currentRetry)
		return signedToken, nil
	}

	return "", errors.New(errors.ErrCodeInternalServerError, "failed to generate and store after maximum retries reached")
}

func (ts *tokenService) generateStandardClaims(ctx context.Context, subject, audience, scopes, roles, nonce string, tokenExpiration int64) (*token.TokenClaims, error) {
	claims := &token.TokenClaims{
		StandardClaims: &jwt.StandardClaims{
			Subject:   subject,
			Issuer:    ts.issuer,
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
		claims.StandardClaims.Audience = audience
	}
	if nonce != "" {
		claims.Nonce = nonce
	}

	return claims, nil
}
