package service

import (
	"context"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ authz.AuthorizationCodeManager = (*authorizationCodeService)(nil)

type authorizationCodeService struct {
	repo         authz.AuthorizationCodeRepository
	codeLifeTime time.Duration
	logger       *config.Logger
	module       string
}

func NewAuthorizationCodeManager(
	repo authz.AuthorizationCodeRepository,
) authz.AuthorizationCodeManager {
	return &authorizationCodeService{
		repo:         repo,
		codeLifeTime: config.GetServerConfig().AuthorizationCodeDuration(),
		logger:       config.GetServerConfig().Logger(),
		module:       "Authorization Code Service",
	}

}

// RevokeAuthorizationCode explicitly invalidates a code.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - code string: The authorization code to revoke.
//
// Returns:
//   - error: An error if revocation fails.
func (c *authorizationCodeService) RevokeAuthorizationCode(ctx context.Context, code string) error {
	requestID := utils.GetRequestID(ctx)

	codeData, err := c.repo.GetAuthorizationCode(ctx, code)
	if err != nil {
		c.logger.Error(c.module, requestID, "[RevokeAuthorizationCode]: Failed to retrieve authorization code: %v", err)
		return err
	}

	codeData.Used = true
	if err := c.repo.UpdateAuthorizationCode(ctx, code, codeData); err != nil {
		c.logger.Error(c.module, "", "[ValidateAuthorizationCode]: Failed to update authorization code: %v", err)
		return errors.NewInternalServerError()
	}

	return nil
}

// UpdateAuthorizationCode updates the provided authorization code data in the repository.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - authData (*authz.AuthorizationCodeData): The authorization code data to be updated.
//
// Returns:
//   - error: An error if updated the authorization code fails, or nil if the operation succeeds.
func (c *authorizationCodeService) UpdateAuthorizationCode(ctx context.Context, authData *authz.AuthorizationCodeData) error {
	requestID := utils.GetRequestID(ctx)
	if err := c.repo.UpdateAuthorizationCode(ctx, authData.Code, authData); err != nil {
		c.logger.Error(c.module, requestID, "[UpdateAuthorizationCode]: Failed to update authorization code: %v", err)
		return err
	}

	return nil
}

// GetAuthorizationCode retrieves the authorization code data for a given code.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - code string: The authorization code to retrieve.
//
// Returns:
//   - *AuthorizationCodeData: The authorization code data if found, or nil if no matching code exists.
func (c *authorizationCodeService) GetAuthorizationCode(ctx context.Context, code string) (*authz.AuthorizationCodeData, error) {
	retrievedCode, err := c.repo.GetAuthorizationCode(ctx, code)
	if err != nil {
		c.logger.Error(c.module, "", "[GetAuthorizationCode]: An error occurred retrieving the authorization code: %v", err)
		return nil, errors.Wrap(err, "", "error retrieving the authorization code")
	}

	return retrievedCode, nil
}
