package service

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/crypto"
	claims "github.com/vigiloauth/vigilo/v2/internal/domain/claims"
	jwtService "github.com/vigiloauth/vigilo/v2/internal/domain/jwt"
	token "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ token.TokenCreator = (*tokenCreator)(nil)

type tokenCreator struct {
	repo                 token.TokenRepository
	jwtService           jwtService.JWTService
	issuer               string
	accessTokenDuration  int64
	refreshTokenDuration int64
	keyID                string

	logger *config.Logger
	module string
}

func NewTokenCreator(
	repo token.TokenRepository,
	jwtService jwtService.JWTService,
) token.TokenCreator {
	accessTokenDuration := time.Now().Add(config.GetServerConfig().TokenConfig().AccessTokenDuration()).Unix()
	refreshTokenDuration := time.Now().Add(config.GetServerConfig().TokenConfig().RefreshTokenDuration()).Unix()

	return &tokenCreator{
		repo:                 repo,
		jwtService:           jwtService,
		issuer:               config.GetServerConfig().URL() + "/oauth2",
		accessTokenDuration:  accessTokenDuration,
		refreshTokenDuration: refreshTokenDuration,
		keyID:                config.GetServerConfig().TokenConfig().KeyID(),

		logger: config.GetServerConfig().Logger(),
		module: "Token Creator",
	}
}

// CreateAccessToken generates an access token for the given subject and expiration time.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - subject string: The subject of the token (e.g., user email).
//   - audience string: The audience of the token (e.g., client ID).
//   - scopes types.Scope: The scopes to be added to the token (can be an empty string if none are needed)..
//   - roles string: The roles to be added to the token (can be an empty string if none are needed).
//   - nonce string: A random string used to prevent replay attacks provided by the client.
//
// Returns:
//   - string: The generated JWT token string.
//   - error: An error if token generation fails.
func (t *tokenCreator) CreateAccessToken(
	ctx context.Context,
	subject string,
	audience string,
	scopes types.Scope,
	roles string,
	nonce string,
) (string, error) {
	requestID := utils.GetRequestID(ctx)

	accessToken, err := t.generateAndStoreToken(
		ctx,
		subject,
		audience,
		scopes,
		roles,
		nonce,
		t.accessTokenDuration,
		time.Time{},
		nil,
	)

	if err != nil {
		t.logger.Error(t.module, requestID, "[CreateAccessToken]: Failed to create access token: %v", err)
		return "", errors.Wrap(err, "", "failed to create access token")
	}

	return accessToken, nil
}

// CreateRefreshToken generates an access token for the given subject and expiration time.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - subject string: The subject of the token (e.g., user email).
//   - audience string: The audience of the token (e.g., client ID).
//   - scopes types.Scope: The scopes to be added to the token (can be an empty string if none are needed)..
//   - roles string: The roles to be added to the token (can be an empty string if none are needed).
//   - nonce string: A random string used to prevent replay attacks provided by the client.
//
// Returns:
//   - string: The generated JWT token string.
//   - error: An error if token generation fails.
func (t *tokenCreator) CreateRefreshToken(
	ctx context.Context,
	subject string,
	audience string,
	scopes types.Scope,
	roles string,
	nonce string,
) (string, error) {
	requestID := utils.GetRequestID(ctx)

	refreshToken, err := t.generateAndStoreToken(
		ctx,
		subject,
		audience,
		scopes,
		roles,
		nonce,
		t.refreshTokenDuration,
		time.Time{},
		nil,
	)

	if err != nil {
		t.logger.Error(t.module, requestID, "[CreateRefreshToken]: Failed to create refresh token: %v", err)
		return "", errors.Wrap(err, "", "failed to create refresh token")
	}

	return refreshToken, nil
}

// CreateAccessTokenWithClaims generates an access token for the given subject and expiration time.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - subject string: The subject of the token (e.g., user email).
//   - audience string: The audience of the token (e.g., client ID).
//   - scopes types.Scope: The scopes to be added to the token (can be an empty string if none are needed)..
//   - roles string: The roles to be added to the token (can be an empty string if none are needed).
//   - nonce string: A random string used to prevent replay attacks provided by the client.
//   - requestedClaims *claims.ClaimsRequest: The requested claims
//
// Returns:
//   - string: The generated JWT token string.
//   - error: An error if token generation fails.
func (t *tokenCreator) CreateAccessTokenWithClaims(
	ctx context.Context,
	subject string,
	audience string,
	scopes types.Scope,
	roles string,
	nonce string,
	requestedClaims *claims.ClaimsRequest,
) (string, error) {
	requestID := utils.GetRequestID(ctx)

	accessToken, err := t.generateAndStoreToken(
		ctx,
		subject,
		audience,
		scopes,
		roles,
		nonce,
		t.accessTokenDuration,
		time.Time{},
		nil,
	)

	if err != nil {
		t.logger.Error(t.module, requestID, "[CreateAccessTokenWithClaims]: Failed to create access token with claims: %v", err)
		return "", errors.Wrap(err, "", "failed to create access token")
	}

	return accessToken, nil
}

// CreateIDToken creates an ID token for the specified user and client.
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
func (t *tokenCreator) CreateIDToken(
	ctx context.Context,
	userID string,
	clientID string,
	scopes types.Scope,
	nonce string,
	authTime time.Time,
) (string, error) {
	requestID := utils.GetRequestID(ctx)

	IDToken, err := t.generateAndStoreToken(
		ctx,
		userID,
		clientID,
		scopes,
		"",
		nonce,
		t.accessTokenDuration,
		authTime,
		nil,
	)

	if err != nil {
		t.logger.Error(t.module, requestID, "[CreateIDToken]: Failed to create ID token: %v", err)
		return "", errors.Wrap(err, "", "failed to create ID token")
	}

	return IDToken, nil
}

func (t *tokenCreator) generateAndStoreToken(
	ctx context.Context,
	subject string,
	audience string,
	scopes types.Scope,
	roles string,
	nonce string,
	duration int64,
	authTime time.Time,
	claims *claims.ClaimsRequest,
) (string, error) {
	requestID := utils.GetRequestID(ctx)
	const maxRetries int = 5
	var lastErr error

	for i := range maxRetries {
		signedToken, err := t.attemptTokenGeneration(
			ctx,
			subject,
			audience,
			scopes,
			roles,
			nonce,
			duration,
			authTime,
			claims,
		)

		if err == nil {
			return signedToken, nil
		}

		lastErr = err
		t.logger.Warn(t.module, requestID, "[generateAndStoreToken]: Failed to generate token (attempt %d/%d): %v", i+1, maxRetries, err)
	}

	return "", errors.Wrap(lastErr, errors.ErrCodeInternalServerError, "failed to generate token after maximum retries")
}

func (t *tokenCreator) attemptTokenGeneration(
	ctx context.Context,
	subject string,
	audience string,
	scopes types.Scope,
	roles string,
	nonce string,
	duration int64,
	authTime time.Time,
	claims *claims.ClaimsRequest,
) (string, error) {
	requestID := utils.GetRequestID(ctx)

	standardClaims, err := t.generateStandardClaims(
		ctx,
		subject,
		audience,
		scopes,
		roles,
		nonce,
		duration,
		authTime,
		claims,
	)

	if err != nil {
		t.logger.Error(t.module, requestID, "[attemptTokenGeneration]: An error occurred generating standard claims: %v", err)
		return "", err
	}

	signedToken, err := t.jwtService.SignToken(ctx, standardClaims)
	if err != nil {
		t.logger.Error(t.module, requestID, "[attemptTokenGeneration]: Failed to sign token: %v", err)
		return "", err
	}

	hashedToken := crypto.EncodeSHA256(signedToken)
	tokenData := &token.TokenData{
		Token:       hashedToken,
		ID:          subject,
		ExpiresAt:   duration,
		TokenID:     t.keyID,
		TokenClaims: standardClaims,
	}

	if err := t.repo.SaveToken(ctx, hashedToken, subject, tokenData, time.Now().Add(time.Duration(duration))); err != nil {
		t.logger.Error(t.module, requestID, "[attemptTokenGeneration]: Failed to save token: %v", err)
		return "", err
	}

	return signedToken, nil
}

func (t *tokenCreator) generateStandardClaims(
	ctx context.Context,
	subject string,
	audience string,
	scopes types.Scope,
	roles string,
	nonce string,
	duration int64,
	authTime time.Time,
	claims *claims.ClaimsRequest,
) (*token.TokenClaims, error) {
	requestID := utils.GetRequestID(ctx)

	tokenID, err := crypto.GenerateRandomString(32)
	if err != nil {
		t.logger.Error(t.module, requestID, "[generateStandardClaims]: Failed to generate token ID: %v", err)
		return nil, errors.NewInternalServerError()
	}

	tokenClaims := &token.TokenClaims{
		Roles: roles,
		StandardClaims: &jwt.StandardClaims{
			Subject:   subject,
			Issuer:    t.issuer,
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: duration,
		},
	}

	existsByID, err := t.repo.ExistsByTokenID(ctx, tokenID)
	if err != nil {
		t.logger.Error(t.module, requestID, "[generateStandardClaims]: An error occurred retrieving the token: %v", err)
		return nil, err
	} else if existsByID {
		t.logger.Warn(t.module, requestID, "[generateStandardClaims]: Failed to generate standard claims. Token already exists.")
		return nil, errors.New(errors.ErrCodeInternalServerError, "token ID already exists")
	} else {
		tokenClaims.Id = tokenID
	}

	if audience != "" {
		tokenClaims.StandardClaims.Audience = audience
	}
	if nonce != "" {
		tokenClaims.Nonce = nonce
	}
	if !authTime.IsZero() {
		tokenClaims.AuthTime = authTime.Unix()
	}
	if scopes != "" {
		tokenClaims.Scopes = scopes
	}
	if claims != nil {
		tokenClaims.RequestedClaims = claims
	}

	return tokenClaims, nil
}
