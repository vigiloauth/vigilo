package service

import (
	"context"
	"net/http"
	"strings"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	clients "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	tokens "github.com/vigiloauth/vigilo/v2/internal/domain/token"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

var _ clients.ClientAuthenticator = (*clientAuthenticator)(nil)

type clientAuthenticator struct {
	clientRepo     clients.ClientRepository
	tokenValidator tokens.TokenValidator
	tokenParser    tokens.TokenParser
	logger         *config.Logger
	module         string
}

func NewClientAuthenticator(
	clientRepo clients.ClientRepository,
	tokenValidator tokens.TokenValidator,
	tokenParser tokens.TokenParser,
) clients.ClientAuthenticator {
	return &clientAuthenticator{
		clientRepo:     clientRepo,
		tokenValidator: tokenValidator,
		tokenParser:    tokenParser,
		logger:         config.GetServerConfig().Logger(),
		module:         "Client Request Authenticator",
	}
}

// AuthenticateRequest validates the incoming HTTP request to ensure the client has the required scope.
//
// Parameters:
//   - ctx context.Context: The context for managing timeouts and cancellations.
//   - r *http.Request: The HTTP request to authenticate.
//   - requiredScope types.Scope: The scope required to access the requested resource.
//
// Returns:
//   - error: An error if authentication fails or the required scope is not met.
func (c *clientAuthenticator) AuthenticateRequest(
	ctx context.Context,
	r *http.Request,
	requiredScope types.Scope,
) error {
	authHeader := r.Header.Get(constants.AuthorizationHeader)

	switch {
	case strings.HasPrefix(authHeader, constants.BasicAuthHeader):
		return c.authenticateWithBasicAuth(ctx, r, requiredScope)
	case strings.HasPrefix(authHeader, constants.BearerAuthHeader):
		return c.authenticateWithBearerToken(ctx, r, requiredScope)
	default:
		return errors.New(errors.ErrCodeInvalidClient, "failed to authorize client: missing authorization header")
	}
}

// AuthenticateClient authenticates the client using provided credentials
// and authorizes access by validating required grant types and scopes.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - clientID string: The ID of the client.
//   - clientSecret string: The client secret.
//   - requestedGrant string: The requested grant type to validate.
//   - scopes string: The scopes to validate.
//
// Returns:
//   - error: An error if authentication or authorization fails.
func (c *clientAuthenticator) AuthenticateClient(
	ctx context.Context,
	clientID string,
	clientSecret string,
	requestedGrant string,
	requestedScopes types.Scope,
) error {
	requestID := utils.GetRequestID(ctx)

	existingClient, err := c.clientRepo.GetClientByID(ctx, clientID)
	if err != nil {
		c.logger.Error(c.module, requestID, "[AuthenticateClient]: Failed to retrieve client by ID: %v", err)
		return errors.Wrap(err, "", "failed to retrieve client")
	}

	if clientSecret != "" {
		if !existingClient.IsConfidential() {
			return errors.New(errors.ErrCodeUnauthorizedClient, "client is not confidential")
		} else if !existingClient.SecretsMatch(clientSecret) {
			return errors.New(errors.ErrCodeInvalidClient, "invalid credentials")
		}
	}

	scopesArr := strings.Split(requestedScopes.String(), " ")
	if !existingClient.CanRequestScopes {
		for _, scope := range scopesArr {
			if !existingClient.HasScope(types.Scope(scope)) {
				return errors.New(errors.ErrCodeInsufficientScope, "client does not have the required scope(s)")
			}
		}
	}

	if requestedGrant != "" && !existingClient.HasGrantType(requestedGrant) {
		return errors.New(errors.ErrCodeUnauthorizedClient, "client does not have the required grant type")
	}

	return nil
}

func (c *clientAuthenticator) authenticateWithBearerToken(
	ctx context.Context,
	r *http.Request,
	requiredScope types.Scope,
) error {
	requestID := utils.GetRequestID(ctx)

	bearerToken, err := web.ExtractBearerToken(r)
	if err != nil {
		c.logger.Error(c.module, requestID, "[authenticateWithBearerToken]: Failed to extract bearer token from header: %v", err)
		return errors.Wrap(err, errors.ErrCodeInvalidGrant, "failed to extract bearer token from header")
	}

	if err := c.tokenValidator.ValidateToken(ctx, bearerToken); err != nil {
		c.logger.Error(c.module, requestID, "[authenticateWithBearerToken]: Failed to validate token: %v", err)
		return errors.Wrap(err, "", "failed to validate bearer token")
	}

	claims, err := c.tokenParser.ParseToken(ctx, bearerToken)
	if err != nil {
		c.logger.Error(c.module, requestID, "[authenticateWithBearerToken]: Failed to parse bearer token: %v", err)
		return errors.Wrap(err, "", "failed to parse bearer token")
	}

	clientID := claims.StandardClaims.Audience
	if err := c.AuthenticateClient(ctx, clientID, "", "", requiredScope); err != nil {
		c.logger.Error(c.module, requestID, "[authenticateWithBearerToken]: Failed to authenticate client: %v", err)
		return errors.Wrap(err, "", "failed to authenticate client")
	}

	return nil
}

func (c *clientAuthenticator) authenticateWithBasicAuth(
	ctx context.Context,
	r *http.Request,
	requiredScope types.Scope,
) error {
	requestID := utils.GetRequestID(ctx)

	clientID, clientSecret, err := web.ExtractClientBasicAuth(r)
	if err != nil {
		c.logger.Error(c.module, requestID, "[authenticateWithBasicAuth]: Failed to retrieve client credentials: %v", err)
		return errors.Wrap(err, "", "failed to extract client credentials from auth header")
	}

	if err := c.AuthenticateClient(ctx, clientID, clientSecret, "", requiredScope); err != nil {
		c.logger.Error(c.module, requestID, "[authenticateWithBasicAuth]: Failed to authenticate client: %v", err)
		return errors.Wrap(err, "", "failed to authenticate client")
	}

	return nil
}
