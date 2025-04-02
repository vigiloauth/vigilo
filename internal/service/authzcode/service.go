package service

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	"github.com/vigiloauth/vigilo/internal/crypto"
	authz "github.com/vigiloauth/vigilo/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var _ authz.AuthorizationCodeService = (*AuthorizationCodeServiceImpl)(nil)
var logger = config.GetServerConfig().Logger()

const module = "Authorization Code Service"

type AuthorizationCodeServiceImpl struct {
	authzCodeRepo authz.AuthorizationCodeRepository
	userService   user.UserService
	clientService client.ClientService
	codeLifeTime  time.Duration
}

// NewAuthorizationCodeServiceImpl creates a new instance of AuthorizationCodeServiceImpl.
//
// Parameters:
//
//	authzCodeRepo AuthorizationCodeRepository: Persistence layer for authorization codes.
//	userService UserService: Service layer for user management.
//	clientService ClientService: Service layer for client management.
//
// Returns:
//
//	*AuthorizationCodeServiceImpl: A new instance of AuthorizationCodeServiceImpl.
func NewAuthorizationCodeServiceImpl(
	authzCodeRepo authz.AuthorizationCodeRepository,
	userService user.UserService,
	clientService client.ClientService,
) *AuthorizationCodeServiceImpl {
	service := &AuthorizationCodeServiceImpl{
		authzCodeRepo: authzCodeRepo,
		userService:   userService,
		clientService: clientService,
		codeLifeTime:  config.GetServerConfig().AuthorizationCodeDuration(),
	}
	return service
}

// GenerateAuthorizationCode creates a new authorization code and stores it with associated data.
//
// Parameters:
//
//	request *ClientAuthorizationRequest: The request containing the metadata to generate an authorization code.
//
// Returns:
//
//		 string: The generated authorization code.
//	  error: An error if code generation fails.
func (c *AuthorizationCodeServiceImpl) GenerateAuthorizationCode(req *client.ClientAuthorizationRequest) (string, error) {
	if err := req.Validate(); err != nil {
		logger.Error(module, "GenerateAuthorizationCode: Failed to validate authorization request: %v", err)
		return "", errors.Wrap(err, "", "failed to generate authorization code")
	}

	if req.UserID == "" || req.ClientID == "" || req.RedirectURI == "" || req.Scope == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "missing one or more parameters")
		logger.Error(module, "GenerateAuthorizationCode: Failed to generate authorization code: %v", err)
		return "", err
	}

	logger.Info(module, "GenerateAuthorizationCode: Generating authorization code for user=[%s], client=[%s] with redirectURI=[%s], scopes[%s]",
		common.TruncateSensitive(req.UserID),
		common.TruncateSensitive(req.ClientID),
		common.SanitizeURL(req.RedirectURI),
		req.Scope,
	)

	if user := c.userService.GetUserByID(req.UserID); user == nil {
		logger.Error(module, "GenerateAuthorizationCode: Failed to retrieve user: invalid user ID")
		return "", errors.New(errors.ErrCodeUnauthorized, "invalid user_id")
	}

	if err := c.validateClientParameters(req.RedirectURI, req.ClientID, req.Scope); err != nil {
		logger.Error(module, "GenerateAuthorizationCode: Failed to validate client=[%s]: %v", common.TruncateSensitive(req.ClientID), err)
		return "", errors.Wrap(err, errors.ErrCodeInvalidClient, "invalid client")
	}

	authData := &authz.AuthorizationCodeData{
		UserID:      req.UserID,
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		Scope:       req.Scope,
		CreatedAt:   time.Now(),
		Used:        false,
	}

	if req.Client.RequiresPKCE() {
		code, err := c.generateAuthorizationCodeForPKCE(req)
		if err != nil {
			logger.Error(module, "Error occurred generating authorization code: %v", err)
			return "", errors.NewInternalServerError()
		}
		authData.Code = code
		authData.CodeChallenge = req.CodeChallenge
		authData.CodeChallengeMethod = req.CodeChallengeMethod
	} else {
		code, err := crypto.GenerateRandomString(32)
		if err != nil {
			logger.Error(module, "Error occurred generating authorization code: %v", err)
			return "", errors.NewInternalServerError()
		}
		authData.Code = code
	}

	expiresAt := authData.CreatedAt.Add(c.codeLifeTime)
	if err := c.authzCodeRepo.StoreAuthorizationCode(authData.Code, authData, expiresAt); err != nil {
		logger.Error(module, "GenerateAuthorizationCode: Failed to store authorization code: %v", err)
		return "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to store authorization code")
	}

	logger.Info(module, "GenerateAuthorizationCode: Authorization code successfully generated for user=[%s] and client=[%s]",
		common.TruncateSensitive(req.UserID),
		common.TruncateSensitive(req.ClientID),
	)

	return authData.Code, nil
}

// ValidateAuthorizationCode checks if a code is valid and returns associated data.
//
// Parameters:
//
//	code string: The authorization code to validate.
//	clientID string: The client requesting validation.
//	redirectURI string: The redirect URI to verify.
//
// Returns:
//
//	*AuthorizationCodeData: The data associated with the code.
//	error: An error if validation fails.
func (c *AuthorizationCodeServiceImpl) ValidateAuthorizationCode(code, clientID, redirectURI string) (*authz.AuthorizationCodeData, error) {
	if code == "" || clientID == "" || redirectURI == "" {
		err := errors.New(errors.ErrCodeEmptyInput, "missing one or more parameters")
		logger.Error(module, "ValidateAuthorizationCode: Failed to validate authorization code: %v", err)
		return nil, err
	}

	logger.Info(module, "ValidateAuthorizationCode: Attempting to validate authorization code=[%s] for client=[%s], redirectURI=[%s]",
		common.TruncateSensitive(code),
		common.TruncateSensitive(clientID),
		common.SanitizeURL(redirectURI),
	)

	authData, exists, err := c.authzCodeRepo.GetAuthorizationCode(code)
	if err != nil {
		logger.Error(module, "ValidateAuthorizationCode: Failed to retrieve authorization code: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to retrieve the authorization code")
	}
	if !exists {
		return nil, errors.New(errors.ErrCodeInvalidGrant, "authorization code not found or expired")
	}

	if authData.Used {
		err = errors.New(errors.ErrCodeInvalidGrant, "authorization code already used")
		logger.Error(module, "ValidateAuthorizationCode: Failed to validate authorization code: %v", err)
		return nil, err
	}

	if authData.ClientID != clientID {
		return nil, errors.New(errors.ErrCodeInvalidGrant, "authorization code client ID and request client ID do no match")
	}

	if authData.RedirectURI != redirectURI {
		return nil, errors.New(errors.ErrCodeInvalidGrant, "authorization code redirect URI and request redirect URI do no match")
	}

	// Mark the code as used
	authData.Used = true
	logger.Debug(module, "ValidateAuthorizationCode: Marking authorization code as used")
	if err := c.authzCodeRepo.UpdateAuthorizationCode(code, authData); err != nil {
		logger.Error(module, "ValidateAuthorizationCode: Failed to update authorization code: %v", err)
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to update authorization code")
	}

	logger.Info(module, "ValidateAuthorizationCode: Successfully validate authorization code for client=[%s]", common.TruncateSensitive(clientID))
	return authData, nil
}

// RevokeAuthorizationCode explicitly invalidates a code.
//
// Parameters:
//
//	code string: The authorization code to revoke.
//
// Returns:
//
//	error: An error if revocation fails.
func (c *AuthorizationCodeServiceImpl) RevokeAuthorizationCode(code string) error {
	if err := c.authzCodeRepo.DeleteAuthorizationCode(code); err != nil {
		logger.Error(module, "RevokeAuthorizationCode: Failed to revoke authorization code=[%s]: %v", common.TruncateSensitive(code), err)
		return err
	}

	logger.Info(module, "RevokeAuthorizationCode: Successfully revoked authorization code")
	return nil
}

// GetAuthorizationCode retrieves the authorization code data for a given code.
//
// Parameters:
//
//	code string: The authorization code to retrieve.
//
// Returns:
//
//	*AuthorizationCodeData: The authorization code data if found, or nil if no matching code exists.
func (c *AuthorizationCodeServiceImpl) GetAuthorizationCode(code string) (*authz.AuthorizationCodeData, error) {
	retrievedCode, isValid, err := c.authzCodeRepo.GetAuthorizationCode(code)
	if !isValid {
		return nil, errors.New(errors.ErrCodeUnauthorized, "the authorization code is no longer valid")
	}
	if err != nil {
		return nil, errors.Wrap(err, "", "error retrieving the authorization code")
	}
	return retrievedCode, nil
}

func (c AuthorizationCodeServiceImpl) validateClientParameters(redirectURI, clientID, scopesString string) error {
	client := c.clientService.GetClientByID(clientID)
	if client == nil {
		return errors.New(errors.ErrCodeUnauthorizedClient, "invalid client ID")
	}

	scopes := strings.Split(scopesString, " ")
	for _, scope := range scopes {
		if !client.HasScope(scope) {
			return errors.New(errors.ErrCodeInsufficientScope, "client is missing required scopes")
		}
	}

	if err := c.clientService.ValidateClientRedirectURI(redirectURI, client); err != nil {
		return errors.Wrap(err, errors.ErrCodeInvalidRedirectURI, "invalid redirect URI")
	}

	return nil
}

func (c *AuthorizationCodeServiceImpl) generateAuthorizationCodeForPKCE(req *client.ClientAuthorizationRequest) (string, error) {
	baseAuthzCode, err := crypto.GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	combinedAuthzCode := fmt.Sprintf("%s|%s|%s", baseAuthzCode, req.CodeChallenge, req.CodeChallengeMethod)
	encodedAuthzCode := base64.RawURLEncoding.EncodeToString([]byte(combinedAuthzCode))
	return encodedAuthzCode, nil
}
