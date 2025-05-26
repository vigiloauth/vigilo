package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	crypto "github.com/vigiloauth/vigilo/v2/internal/domain/crypto"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ domain.AuthorizationCodeCreator = (*authorizationCodeCreator)(nil)

type authorizationCodeCreator struct {
	repo          domain.AuthorizationCodeRepository
	cryptographer crypto.Cryptographer

	codeLifeTime time.Duration
	logger       *config.Logger
	module       string
}

func NewAuthorizationCodeCreator(
	repo domain.AuthorizationCodeRepository,
	cryptographer crypto.Cryptographer,
) domain.AuthorizationCodeCreator {
	return &authorizationCodeCreator{
		repo:          repo,
		cryptographer: cryptographer,

		codeLifeTime: config.GetServerConfig().AuthorizationCodeDuration(),
		logger:       config.GetServerConfig().Logger(),
		module:       "Authorization Code Creator",
	}
}

// GenerateAuthorizationCode creates a new authorization code and stores it with associated data.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - req *ClientAuthorizationRequest: The request containing the metadata to generate an authorization code.
//
// Returns:
//   - string: The generated authorization code.
//   - error: An error if code generation fails.
func (c *authorizationCodeCreator) GenerateAuthorizationCode(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error) {
	requestID := utils.GetRequestID(ctx)

	codeData := &domain.AuthorizationCodeData{
		UserID:                 req.UserID,
		ClientID:               req.ClientID,
		RedirectURI:            req.RedirectURI,
		Scope:                  req.Scope,
		CreatedAt:              time.Now(),
		Used:                   false,
		Nonce:                  req.Nonce,
		UserAuthenticationTime: req.UserAuthenticationTime.UTC(),
	}

	if req.ClaimsRequest != nil {
		codeData.ClaimsRequest = req.ClaimsRequest
	}

	if req.ACRValues != "" {
		codeData.ACRValues = req.ACRValues
	}

	if err := c.handlePKCECreation(requestID, codeData, req); err != nil {
		c.logger.Error(c.module, requestID, "[GenerateAuthorizationCode] Error handling PKCE creation: %v", err)
		return "", errors.Wrap(err, "", "Failed to handle PKCE creation")
	}

	expirationTime := codeData.CreatedAt.Add(c.codeLifeTime)
	if err := c.repo.StoreAuthorizationCode(ctx, codeData.Code, codeData, expirationTime); err != nil {
		c.logger.Error(c.module, requestID, "[GenerateAuthorizationCode] Error creating authorization code in repository: %v", err)
		return "", errors.Wrap(err, errors.ErrCodeInternalServerError, "Failed to create authorization code in repository")
	}

	return codeData.Code, nil
}

func (c *authorizationCodeCreator) handlePKCECreation(
	requestID string,
	codeData *domain.AuthorizationCodeData,
	req *client.ClientAuthorizationRequest,
) error {
	if req.Client.RequiresPKCE {
		code, err := c.generateAuthorizationCodeForPKCE(requestID, req)
		if err != nil {
			c.logger.Error(c.module, requestID, "[handlePKCECreation] Error generating PKCE authorization code: %v", err)
			return errors.Wrap(err, "", "Failed to generate PKCE authorization code")
		}

		codeData.Code = code
		codeData.CodeChallenge = req.CodeChallenge
		codeData.CodeChallengeMethod = req.CodeChallengeMethod
	} else {
		code, err := c.cryptographer.GenerateRandomString(32)
		if err != nil {
			c.logger.Error(c.module, requestID, "[handlePKCECreation] Error generating random string for authorization code: %v", err)
			return errors.Wrap(err, "", "Failed to generate authorization code")
		}
		codeData.Code = code
	}

	return nil
}

func (c *authorizationCodeCreator) generateAuthorizationCodeForPKCE(
	requestID string,
	req *client.ClientAuthorizationRequest,
) (string, error) {
	baseAuthorizationCode, err := c.cryptographer.GenerateRandomString(32)
	if err != nil {
		c.logger.Error(c.module, requestID, "[generateAuthorizationCodeForPKCE] Error generating random string for PKCE authorization code: %v", err)
		return "", errors.Wrap(err, "", "Failed to generate PKCE authorization code")
	}

	combinedAuthorizationCode := fmt.Sprintf("%s|%s|%s", baseAuthorizationCode, req.CodeChallenge, req.CodeChallengeMethod)
	encodedAuthorizationCode := base64.RawURLEncoding.EncodeToString([]byte(combinedAuthorizationCode))
	return encodedAuthorizationCode, nil
}
