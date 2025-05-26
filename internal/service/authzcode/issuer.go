package service

import (
	"context"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ domain.AuthorizationCodeIssuer = (*authorizationCodeIssuer)(nil)

type authorizationCodeIssuer struct {
	creator domain.AuthorizationCodeCreator
	logger  *config.Logger
	module  string
}

func NewAuthorizationCodeIssuer(
	creator domain.AuthorizationCodeCreator,
) domain.AuthorizationCodeIssuer {
	return &authorizationCodeIssuer{
		creator: creator,
		logger:  config.GetServerConfig().Logger(),
		module:  "Authorization Code Issuer",
	}
}

// IssueAuthorizationCode generates an authorization code for the given client request.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - req *ClientAuthorizationRequest: The request containing the metadata to generate an authorization code.
//
// Returns:
//   - string: The generated authorization code.
//   - error: An error if code generation fails.
func (c *authorizationCodeIssuer) IssueAuthorizationCode(
	ctx context.Context,
	req *client.ClientAuthorizationRequest,
) (string, error) {
	requestID := utils.GetRequestID(ctx)

	code, err := c.creator.GenerateAuthorizationCode(ctx, req)
	if err != nil {
		c.logger.Error(c.module, requestID, "[IssueAuthorizationCode] Error generating authorization code: %v", err)
		return "", errors.Wrap(err, "", "failed to generate authorization code")
	}

	return code, nil
}
