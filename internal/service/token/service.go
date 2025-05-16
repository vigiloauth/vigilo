package service

import (
	"context"
	"crypto/rsa"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/crypto"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
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

// GenerateAccessToken generates an access token for the given subject and expiration time.
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
func (ts *tokenService) GenerateAccessToken(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string) (string, error) {
	requestID := utils.GetRequestID(ctx)

	token, err := ts.generateAndStoreToken(ctx, subject, audience, scopes, roles, nonce, ts.accessTokenDuration, time.Time{})
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[GenerateAccessToken]: Failed to generate access token claims: %v", err)
		return "", errors.NewInternalServerError()
	}

	return token, nil
}

// GenerateToken generates a refresh token for the given subject and expiration time.
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
func (ts *tokenService) GenerateRefreshToken(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string) (string, error) {
	requestID := utils.GetRequestID(ctx)

	token, err := ts.generateAndStoreToken(ctx, subject, audience, scopes, roles, nonce, ts.refreshTokenDuration, time.Time{})
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[GenerateAccessToken]: Failed to generate refresh token claims: %v", err)
		return "", errors.NewInternalServerError()
	}

	return token, nil
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
//   - authTime *Time: Time at which the user was authenticated. The value of time can be nil as it only applies when a request with "max_age" was given
//
// Returns:
//   - string: The signed ID token as a JWT string.
//   - error: An error if token generation fails.
func (ts *tokenService) GenerateIDToken(ctx context.Context, userID string, clientID string, scopes types.Scope, nonce string, authTime time.Time) (string, error) {
	requestID := utils.GetRequestID(ctx)

	idToken, err := ts.generateAndStoreToken(ctx, userID, clientID, scopes, "", nonce, ts.refreshTokenDuration, authTime)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[GenerateIDToken]: Failed to generate ID token: %v", err)
		return "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate ID token")
	}

	return idToken, nil
}

// ParseToken parses and validates a JWT token string, handling both encrypted and non-encrypted tokens.
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
func (ts *tokenService) ParseToken(ctx context.Context, tokenString string) (*token.TokenClaims, error) {
	requestID := utils.GetRequestID(ctx)

	claims, err := ts.parseToken(tokenString)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[ParseToken]: Failed to parse token: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to parse token")
	}

	ts.logger.Debug(ts.module, requestID, "[ParseToken]: Token validation process completed successfully")
	return claims, nil
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

	if ts.isTokenExpired(token) {
		ts.logger.Warn(ts.module, "[ValidateToken]: Token=[%s] is expired", utils.TruncateSensitive(token))
		return errors.New(errors.ErrCodeExpiredToken, "the token is expired")
	}

	isTokenBlacklisted, err := ts.isTokenBlacklisted(ctx, token)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[ValidateToken]: An error occurred validating the token: %v", err)
		return err
	} else if isTokenBlacklisted {
		ts.logger.Warn(ts.module, requestID, "[ValidateToken]: Token is blacklisted")
		return errors.New(errors.ErrCodeUnauthorized, "the token is blacklisted")
	}

	return nil
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

func (ts *tokenService) parseToken(tokenString string) (*token.TokenClaims, error) {
	tokenClaims, err := jwt.ParseWithClaims(tokenString, &token.TokenClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, errors.New(errors.ErrCodeTokenParsing, "unexpected signing method")
		}
		return ts.publicKey, nil
	})

	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeTokenParsing, "failed to parse JWT with claims")
	}

	if claims, ok := tokenClaims.Claims.(*token.TokenClaims); ok && tokenClaims.Valid {
		return claims, nil
	}

	return nil, errors.New(errors.ErrCodeInvalidToken, "provided token is invalid")
}

func (ts *tokenService) isTokenExpired(token string) bool {
	claims, err := ts.ParseToken(context.TODO(), token)
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

func (ts *tokenService) isTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	requestID := utils.GetRequestID(ctx)
	hashedToken := crypto.EncodeSHA256(token)

	isBlacklisted, err := ts.tokenRepo.IsTokenBlacklisted(ctx, hashedToken)
	if err != nil {
		ts.logger.Error(ts.module, requestID, "[IsTokenBlacklisted]: An error occurred searching for the token: %v", err)
		return false, errors.Wrap(err, errors.ErrCodeInternalServerError, "an error occurred searching for the token")
	}

	return isBlacklisted, nil
}

func (ts *tokenService) generateAndStoreToken(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string, duration time.Duration, authTime time.Time) (string, error) {
	const maxRetries = 5

	var lastErr error
	for i := range maxRetries {
		signedToken, err := ts.attemptTokenGeneration(ctx, subject, audience, scopes, roles, nonce, duration, authTime)
		if err == nil {
			ts.logger.Info(ts.module, "", "Successfully generated token after %d retries", i)
			return signedToken, nil
		}
		lastErr = err
		ts.logger.Warn(ts.module, "", "Failed to generate token (attempt %d/%d): %v", i+1, maxRetries, err)
	}

	return "", errors.Wrap(lastErr, errors.ErrCodeInternalServerError, "failed to generate token after maximum retries")
}

func (ts *tokenService) attemptTokenGeneration(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string, duration time.Duration, authTime time.Time) (string, error) {
	tokenExpiration := time.Now().Add(duration)
	claims, err := ts.generateStandardClaims(ctx, subject, audience, scopes, roles, nonce, tokenExpiration.Unix(), authTime)
	if err != nil {
		return "", err
	}

	jwtClaims := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	jwtClaims.Header["kid"] = ts.keyID

	signedToken, err := jwtClaims.SignedString(ts.privateKey)
	if err != nil {
		return "", err
	}

	hashedToken := crypto.EncodeSHA256(signedToken)
	tokenData := &token.TokenData{
		Token:     hashedToken,
		ID:        subject,
		ExpiresAt: tokenExpiration,
		TokenID:   ts.keyID,
		Claims:    claims,
	}

	return signedToken, ts.tokenRepo.SaveToken(ctx, hashedToken, subject, tokenData, tokenExpiration)
}

func (ts *tokenService) generateStandardClaims(ctx context.Context, subject string, audience string, scopes types.Scope, roles string, nonce string, tokenExpiration int64, authTime time.Time) (*token.TokenClaims, error) {
	claims := &token.TokenClaims{
		StandardClaims: &jwt.StandardClaims{
			Subject:   subject,
			Issuer:    ts.issuer,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: tokenExpiration,
		},
		Roles: roles,
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
		return nil, errors.New(errors.ErrCodeInternalServerError, "token ID already exists")
	} else {
		claims.Id = tokenID
	}

	if audience != "" {
		claims.StandardClaims.Audience = audience
	}
	if nonce != "" {
		claims.Nonce = nonce
	}
	if !authTime.IsZero() {
		claims.AuthTime = authTime.Unix()
	}
	if scopes != "" {
		claims.Scopes = scopes
	}

	return claims, nil
}
