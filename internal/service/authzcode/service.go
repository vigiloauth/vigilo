package service

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	"github.com/vigiloauth/vigilo/v2/internal/crypto"
	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	user "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
)

var _ authz.AuthorizationCodeService = (*authorizationCodeService)(nil)

type authorizationCodeService struct {
	authzCodeRepo authz.AuthorizationCodeRepository
	userService   user.UserService
	clientService client.ClientService
	codeLifeTime  time.Duration

	logger *config.Logger
	module string
}

// NewAuthorizationCodeService creates a new instance of AuthorizationCodeServiceImpl.
//
// Parameters:
//   - authzCodeRepo AuthorizationCodeRepository: Persistence layer for authorization codes.
//   - userService UserService: Service layer for user management.
//   - clientService ClientService: Service layer for client management.
//
// Returns:
//   - *AuthorizationCodeServiceImpl: A new instance of AuthorizationCodeServiceImpl.
func NewAuthorizationCodeService(
	authzCodeRepo authz.AuthorizationCodeRepository,
	userService user.UserService,
	clientService client.ClientService,
) authz.AuthorizationCodeService {
	return &authorizationCodeService{
		authzCodeRepo: authzCodeRepo,
		userService:   userService,
		clientService: clientService,
		codeLifeTime:  config.GetServerConfig().AuthorizationCodeDuration(),
		logger:        config.GetServerConfig().Logger(),
		module:        "Authorization Code Service",
	}

}

// GenerateAuthorizationCode creates a new authorization code and stores it with associated data.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - request *ClientAuthorizationRequest: The request containing the metadata to generate an authorization code.
//
// Returns:
//   - string: The generated authorization code.
//   - error: An error if code generation fails.
func (c *authorizationCodeService) GenerateAuthorizationCode(ctx context.Context, req *client.ClientAuthorizationRequest) (string, error) {
	requestID := utils.GetRequestID(ctx)
	if err := req.Validate(); err != nil {
		c.logger.Error(c.module, requestID, "[GenerateAuthorizationCode]: Failed to validate authorization request: %v", err)
		return "", errors.Wrap(err, "", "failed to generate authorization code")
	}

	if err := c.validateUserAndClient(ctx, req); err != nil {
		return "", err
	}

	authData := &authz.AuthorizationCodeData{
		UserID:      req.UserID,
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		Scope:       req.Scope,
		CreatedAt:   time.Now(),
		Used:        false,
		Nonce:       req.Nonce,
	}

	if err := c.handlePKCE(req, authData); err != nil {
		return "", err
	}

	if err := c.SaveAuthorizationCode(ctx, authData); err != nil {
		c.logger.Error(c.module, requestID, "[GenerateAuthorizationCode]: Failed to save authorization code: %v", err)
		return "", errors.Wrap(err, "", "failed to store authorization code")
	}

	c.logger.Info(c.module, requestID, "[GenerateAuthorizationCode]: Authorization code successfully generated for user=[%s] and client=[%s]",
		utils.TruncateSensitive(req.UserID),
		utils.TruncateSensitive(req.ClientID),
	)

	return authData.Code, nil
}

// SaveAuthorizationCode stores the provided authorization code data in the repository.
//
// This method calculates the expiration time for the authorization code based on the
// configured code lifetime and stores the code along with its associated data in the
// authorization code repository.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - authData (*authz.AuthorizationCodeData): The authorization code data to be stored.
//
// Returns:
//   - error: An error if storing the authorization code fails, or nil if the operation succeeds.
func (c *authorizationCodeService) SaveAuthorizationCode(ctx context.Context, authData *authz.AuthorizationCodeData) error {
	requestID := utils.GetRequestID(ctx)

	expiration := authData.CreatedAt.Add(c.codeLifeTime)
	if err := c.authzCodeRepo.StoreAuthorizationCode(ctx, authData.Code, authData, expiration); err != nil {
		c.logger.Error(c.module, requestID, "[SaveAuthorizationCode]: Failed to store authorization code: %v", err)
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to store authorization code")
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
//   - *AuthorizationCodeData: The data associated with the code.
//   - error: An error if validation fails.
func (c *authorizationCodeService) ValidateAuthorizationCode(ctx context.Context, code, clientID, redirectURI string) (*authz.AuthorizationCodeData, error) {
	requestID := utils.GetRequestID(ctx)

	authData, err := c.authzCodeRepo.GetAuthorizationCode(ctx, code)
	if err != nil {
		c.logger.Error(c.module, requestID, "[ValidateAuthorizationCode]: Failed to retrieve authorization code: %v", err)
		return nil, errors.New(errors.ErrCodeUnauthorized, "invalid authorization code")
	}

	if err := authData.ValidateFields(clientID, redirectURI); err != nil {
		c.logger.Error(c.module, requestID, "[ValidateAuthorizationCode]: Failed to validate authorization code: %v", err)
		return nil, errors.Wrap(err, "", "failed to validate authorization code")
	}

	if err := c.markCodeAsUsed(ctx, code, authData); err != nil {
		c.logger.Error(c.module, requestID, "[ValidateAuthorizationCode]: Failed to mark authorization code as used: %v", err)
		return nil, err
	}

	return authData, nil
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
	if err := c.authzCodeRepo.DeleteAuthorizationCode(ctx, code); err != nil {
		c.logger.Error(c.module, "", "[RevokeAuthorizationCode]: Failed to revoke authorization code=[%s]: %v", utils.TruncateSensitive(code), err)
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
	retrievedCode, err := c.authzCodeRepo.GetAuthorizationCode(ctx, code)
	if err != nil {
		c.logger.Error(c.module, "", "[GetAuthorizationCode]: An error occurred retrieving the authorization code: %v", err)
		return nil, errors.Wrap(err, "", "error retrieving the authorization code")
	}

	return retrievedCode, nil
}

// ValidatePKCE validates the PKCE (Proof Key for Code Exchange) parameters during the token exchange process.
//
// This method checks if the provided code verifier matches the code challenge stored in the authorization code data.
// It supports the "S256" (SHA-256) and "plain" code challenge methods.
//
// Parameters:
//   - authzCodeData (*authz.AuthorizationCodeData): The authorization code data containing the code challenge and method.
//   - codeVerifier (string): The code verifier provided by the client during the token exchange.
//
// Returns:
//   - error: An error if the validation fails, including cases where the code verifier does not match the code challenge
//     or if the code challenge method is unsupported. Returns nil if validation succeeds.
func (c *authorizationCodeService) ValidatePKCE(authzCodeData *authz.AuthorizationCodeData, codeVerifier string) error {
	if authzCodeData.CodeChallengeMethod == authz.S256 {
		hashedVerifier := crypto.EncodeSHA256(codeVerifier)
		if hashedVerifier != authzCodeData.CodeChallenge {
			c.logger.Error(c.module, "", "[ValidatePKCE]: The provided code challenge does not match with the code verifier.")
			return errors.New(errors.ErrCodeInvalidGrant, "invalid code verifier")
		}

	} else if authzCodeData.CodeChallengeMethod == authz.Plain {
		if codeVerifier != authzCodeData.CodeChallenge {
			c.logger.Error(c.module, "", "[ValidatePKCE]: The provided code challenge does not match with the code verifier.")
			return errors.New(errors.ErrCodeInvalidGrant, "invalid code verifier")
		}

	} else {
		return errors.New(errors.ErrCodeUnauthorized, fmt.Sprintf("unsupported code challenge method: %v", authzCodeData.CodeChallengeMethod))
	}

	return nil
}

func (c authorizationCodeService) validateClientParameters(ctx context.Context, redirectURI, clientID, scopesString string) error {
	client, err := c.clientService.GetClientByID(ctx, clientID)
	if err != nil {
		c.logger.Error(c.module, "", "Failed to retrieve client: %v", err)
		return errors.New(errors.ErrCodeUnauthorizedClient, "invalid client credentials")
	}

	// Client registered with scopes so they must be used for this request.
	if !client.CanRequestScopes {
		scopes := strings.Split(scopesString, " ")
		for _, scope := range scopes {
			if !client.HasScope(scope) {
				c.logger.Error(c.module, "Failed to validate client: client is missing required scope=[%s]", scope)
				return errors.New(errors.ErrCodeInsufficientScope, "client is missing required scopes")
			}
		}
	}

	if err := c.clientService.ValidateClientRedirectURI(redirectURI, client); err != nil {
		return errors.Wrap(err, errors.ErrCodeInvalidRedirectURI, "invalid redirect URI")
	}

	return nil
}

func (c *authorizationCodeService) generateAuthorizationCodeForPKCE(req *client.ClientAuthorizationRequest) (string, error) {
	baseAuthzCode, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	combinedAuthzCode := fmt.Sprintf("%s|%s|%s", baseAuthzCode, req.CodeChallenge, req.CodeChallengeMethod)
	encodedAuthzCode := base64.RawURLEncoding.EncodeToString([]byte(combinedAuthzCode))
	return encodedAuthzCode, nil
}

func (c *authorizationCodeService) markCodeAsUsed(ctx context.Context, code string, authData *authz.AuthorizationCodeData) error {
	authData.Used = true
	if err := c.authzCodeRepo.UpdateAuthorizationCode(ctx, code, authData); err != nil {
		c.logger.Error(c.module, "", "[ValidateAuthorizationCode]: Failed to update authorization code: %v", err)
		return errors.NewInternalServerError()
	}

	return nil
}

func (c *authorizationCodeService) handlePKCE(req *client.ClientAuthorizationRequest, authData *authz.AuthorizationCodeData) error {
	if req.Client.RequiresPKCE {
		code, err := c.generateAuthorizationCodeForPKCE(req)
		if err != nil {
			return errors.NewInternalServerError()
		}
		authData.Code = code
		authData.CodeChallenge = req.CodeChallenge
		authData.CodeChallengeMethod = req.CodeChallengeMethod
	} else {
		code, err := crypto.GenerateRandomString(32)
		if err != nil {
			return errors.NewInternalServerError()
		}
		authData.Code = code
	}
	return nil
}

func (c *authorizationCodeService) validateUserAndClient(ctx context.Context, req *client.ClientAuthorizationRequest) error {
	if _, err := c.userService.GetUserByID(ctx, req.UserID); err != nil {
		c.logger.Error(c.module, "", "An error occurred retrieving the user by ID: %v", err)
		return errors.New(errors.ErrCodeUnauthorized, "invalid user credentials")
	}

	if err := c.validateClientParameters(ctx, req.RedirectURI, req.ClientID, req.Scope); err != nil {
		c.logger.Error(c.module, "", "Failed to validate client=[%s]: %v", utils.TruncateSensitive(req.ClientID), err)
		return errors.Wrap(err, "", "failed to validate client parameters")
	}

	return nil
}
