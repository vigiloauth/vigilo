package service

import (
	"context"
	"fmt"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/constants"
	domain "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/types"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ domain.AuthorizationCodeValidator = (*authorizationCodeValidator)(nil)

type authorizationCodeValidator struct {
	repo                domain.AuthorizationCodeRepository
	clientValidator     client.ClientValidator
	clientAuthenticator client.ClientAuthenticator
	logger              *config.Logger
	module              string
}

func NewAuthorizationCodeValidator(
	repo domain.AuthorizationCodeRepository,
	clientValidator client.ClientValidator,
	clientAuthenticator client.ClientAuthenticator,
) domain.AuthorizationCodeValidator {
	return &authorizationCodeValidator{
		repo:                repo,
		clientValidator:     clientValidator,
		clientAuthenticator: clientAuthenticator,
		logger:              config.GetServerConfig().Logger(),
		module:              "Authorization Code Issuer",
	}
}

// ValidateRequest checks the validity of the client authorization request.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - req *ClientAuthorizationRequest: The request to validate.
//
// Returns:
//   - error: An error if the request is invalid.
func (c *authorizationCodeValidator) ValidateRequest(
	ctx context.Context,
	req *client.ClientAuthorizationRequest,
) error {
	requestID := utils.GetRequestID(ctx)

	if err := c.clientValidator.ValidateAuthorizationRequest(ctx, req); err != nil {
		c.logger.Error(c.module, requestID, "[IssueAuthorizationCode] Error validating authorization request: %v", err)
		return errors.Wrap(err, "", "failed to validate authorization request")
	}

	clientAuthRequest := &client.ClientAuthenticationRequest{
		ClientID:        req.ClientID,
		ClientSecret:    req.Client.Secret,
		RequestedScopes: req.Scope,
		RedirectURI:     req.RedirectURI,
		RequestedGrant:  constants.AuthorizationCodeGrantType,
	}

	if err := c.clientAuthenticator.AuthenticateClient(ctx, clientAuthRequest); err != nil {
		c.logger.Error(c.module, requestID, "[IssueAuthorizationCode] Error authenticating client: %v", err)
		return errors.Wrap(err, "", "failed to authenticate client")
	}

	return nil
}

// ValidateAuthorizationCode checks if a code is valid and returns the associated data.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - code string: The authorization code to validate.
//   - clientID string: The client requesting validation.
//   - redirectURI string: The redirect URI to verify.
//
// Returns:
//   - error: An error if validation fails.
func (c *authorizationCodeValidator) ValidateAuthorizationCode(
	ctx context.Context,
	code string,
	clientID string,
	redirectURI string,
) error {
	requestID := utils.GetRequestID(ctx)

	codeData, err := c.repo.GetAuthorizationCode(ctx, code)
	if err != nil {
		c.logger.Error(c.module, requestID, "[ValidateAuthorizationCode] Error retrieving authorization code: %v", err)
		return errors.Wrap(err, "", "failed to retrieve authorization code")
	}

	if codeData.Used {
		c.logger.Error(c.module, requestID, "[ValidateAuthorizationCode] Authorization code has already been used")
		return errors.New(errors.ErrCodeInvalidGrant, "authorization code has already been used")
	} else if codeData.ClientID != clientID {
		c.logger.Error(c.module, requestID, "[ValidateAuthorizationCode] Authorization code client ID and request client ID do not match")
		return errors.New(errors.ErrCodeInvalidGrant, "authorization code client ID and request client ID do not match")
	} else if codeData.RedirectURI != redirectURI {
		c.logger.Error(c.module, requestID, "[ValidateAuthorizationCode] Authorization code redirect URI and request redirect URI do not match")
		return errors.New(errors.ErrCodeInvalidGrant, "authorization code redirect URI and request redirect URI do not match")
	}

	return nil
}

// ValidatePKCE validates the PKCE (Proof Key for Code Exchange) parameters during the token exchange process.
//
// This method checks if the provided code verifier matches the code challenge stored in the authorization code data.
// It supports the "S256" (SHA-256) and "plain" code challenge methods.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - authzCodeData (*authz.AuthorizationCodeData): The authorization code data containing the code challenge and method.
//   - codeVerifier (string): The code verifier provided by the client during the token exchange.
//
// Returns:
//   - error: An error if the validation fails, including cases where the code verifier does not match the code challenge
//     or if the code challenge method is unsupported. Returns nil if validation succeeds.
func (c *authorizationCodeValidator) ValidatePKCE(
	ctx context.Context,
	authzCodeData *domain.AuthorizationCodeData,
	codeVerifier string,
) error {
	requestID := utils.GetRequestID(ctx)

	if authzCodeData.CodeChallengeMethod == types.SHA256CodeChallengeMethod {
		hashedVerifier := utils.EncodeSHA256(codeVerifier)
		if hashedVerifier != authzCodeData.CodeChallenge {
			c.logger.Error(c.module, requestID, "[ValidatePKCE]: The provided code challenge does not match with the code verifier.")
			return errors.New(errors.ErrCodeInvalidGrant, "invalid code verifier")
		}

	} else if authzCodeData.CodeChallengeMethod == types.PlainCodeChallengeMethod {
		if codeVerifier != authzCodeData.CodeChallenge {
			c.logger.Error(c.module, requestID, "[ValidatePKCE]: The provided code challenge does not match with the code verifier.")
			return errors.New(errors.ErrCodeInvalidGrant, "invalid code verifier")
		}

	} else {
		return errors.New(errors.ErrCodeUnauthorized, fmt.Sprintf("unsupported code challenge method: %v", authzCodeData.CodeChallengeMethod))
	}

	return nil
}
