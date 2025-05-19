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

var _ clients.ClientRequestAuthenticator = (*clientRequestAuthenticator)(nil)

type clientRequestAuthenticator struct {
	clientService clients.ClientService
	tokenService  tokens.TokenService
	logger        *config.Logger
	module        string
}

func NewClientRequestAuthenticator(
	clientService clients.ClientService,
	tokenService tokens.TokenService,
) clients.ClientRequestAuthenticator {
	return &clientRequestAuthenticator{
		clientService: clientService,
		tokenService:  tokenService,
		logger:        config.GetServerConfig().Logger(),
		module:        "Client Request Authenticator",
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
func (c *clientRequestAuthenticator) AuthenticateRequest(
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

func (c *clientRequestAuthenticator) authenticateWithBearerToken(
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

	if err := c.tokenService.ValidateToken(ctx, bearerToken); err != nil {
		c.logger.Error(c.module, requestID, "[authenticateWithBearerToken]: Failed to validate token: %v", err)
		return errors.Wrap(err, "", "failed to validate bearer token")
	}

	claims, err := c.tokenService.ParseToken(ctx, bearerToken)
	if err != nil {
		c.logger.Error(c.module, requestID, "[authenticateWithBearerToken]: Failed to parse bearer token: %v", err)
		return errors.New(errors.ErrCodeInternalServerError, "failed to parse bearer token")
	}

	clientID := claims.Audience
	if err := c.clientService.AuthenticateClient(ctx, clientID, "", "", requiredScope); err != nil {
		c.logger.Error(c.module, requestID, "[authenticateWithBearerToken]: Failed to authenticate client: %v", err)
		return errors.Wrap(err, "", "failed to authenticate client")
	}

	return nil
}

func (c *clientRequestAuthenticator) authenticateWithBasicAuth(
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

	if err := c.clientService.AuthenticateClient(ctx, clientID, clientSecret, "", requiredScope); err != nil {
		c.logger.Error(c.module, requestID, "[authenticateWithBasicAuth]: Failed to authenticate client: %v", err)
		return errors.Wrap(err, "", "failed to authenticate client")
	}

	return nil
}
