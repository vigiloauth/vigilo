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
//	string: The generated authorization code.
//	error: An error if code generation fails.
func (c *AuthorizationCodeServiceImpl) GenerateAuthorizationCode(req *client.ClientAuthorizationRequest) (string, error) {
	if err := req.Validate(); err != nil {
		logger.Error(module, "GenerateAuthorizationCode: Failed to validate authorization request: %v", err)
		return "", errors.Wrap(err, "", "failed to generate authorization code")
	}

	if err := c.validateUserAndClient(req); err != nil {
		return "", err
	}

	authData := &authz.AuthorizationCodeData{
		UserID:      req.UserID,
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		Scope:       req.Scope,
		CreatedAt:   time.Now(),
		Used:        false,
	}

	if err := c.handlePKCE(req, authData); err != nil {
		return "", err
	}

	if err := c.SaveAuthorizationCode(authData); err != nil {
		logger.Error(module, "GenerateAuthorizationCode: Failed to save authorization code: %v", err)
		return "", err
	}

	logger.Info(module, "GenerateAuthorizationCode: Authorization code successfully generated for user=[%s] and client=[%s]",
		common.TruncateSensitive(req.UserID),
		common.TruncateSensitive(req.ClientID),
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
//
//	authData (*authz.AuthorizationCodeData): The authorization code data to be stored.
//
// Returns:
//
//	error: An error if storing the authorization code fails, or nil if the operation succeeds.
func (c *AuthorizationCodeServiceImpl) SaveAuthorizationCode(authData *authz.AuthorizationCodeData) error {
	expiration := authData.CreatedAt.Add(c.codeLifeTime)
	if err := c.authzCodeRepo.StoreAuthorizationCode(authData.Code, authData, expiration); err != nil {
		logger.Error(module, "SaveAuthorizationCode: Failed to store authorization code: %v", err)
		return errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to store authorization code")
	}
	return nil
}

// ValidateAuthorizationCode checks if a code is valid and returns the associated data.
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
	logger.Info(module, "ValidateAuthorizationCode: Attempting to validate authorization code=[%s] for client=[%s], redirectURI=[%s]",
		common.TruncateSensitive(code),
		common.TruncateSensitive(clientID),
		common.SanitizeURL(redirectURI),
	)

	authData, err := c.authzCodeRepo.GetAuthorizationCode(code)
	if err != nil {
		logger.Error(module, "ValidateAuthorizationCode: Failed to retrieve authorization code: %v", err)
		return nil, errors.New(errors.ErrCodeUnauthorized, "invalid authorization code")
	}

	if err := authData.ValidateFields(clientID, redirectURI); err != nil {
		logger.Error(module, "ValidateAuthorizationCode: Failed to validate authorization code: %v", err)
		return nil, errors.Wrap(err, "", "failed to validate authorization code")
	}

	if err := c.markCodeAsUsed(code, authData); err != nil {
		logger.Error(module, "ValidateAuthorizationCode: Failed to mark authorization code as used: %v", err)
		return nil, err
	}

	logger.Info(module, "ValidateAuthorizationCode: Successfully validated authorization code for client=[%s]", common.TruncateSensitive(clientID))
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
	retrievedCode, err := c.authzCodeRepo.GetAuthorizationCode(code)
	if err != nil {
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
//
//	authzCodeData (*authz.AuthorizationCodeData): The authorization code data containing the code challenge and method.
//	codeVerifier (string): The code verifier provided by the client during the token exchange.
//
// Returns:
//
//	error: An error if the validation fails, including cases where the code verifier does not match the code challenge
//	  or if the code challenge method is unsupported. Returns nil if validation succeeds.
func (c *AuthorizationCodeServiceImpl) ValidatePKCE(authzCodeData *authz.AuthorizationCodeData, codeVerifier string) error {
	if authzCodeData.CodeChallengeMethod == authz.S256 {
		hashedVerifier := crypto.HashSHA256(codeVerifier)
		if hashedVerifier != authzCodeData.CodeChallenge {
			return errors.New(errors.ErrCodeInvalidGrant, "invalid code verifier")
		}
	} else if authzCodeData.CodeChallengeMethod == authz.Plain {
		if codeVerifier != authzCodeData.CodeChallenge {
			return errors.New(errors.ErrCodeInvalidGrant, "invalid code verifier")
		}
	} else {
		return errors.New(errors.ErrCodeUnauthorized, fmt.Sprintf("unsupported code challenge method: %v", authzCodeData.CodeChallengeMethod))
	}

	return nil
}

func (c AuthorizationCodeServiceImpl) validateClientParameters(redirectURI, clientID, scopesString string) error {
	client := c.clientService.GetClientByID(clientID)
	if client == nil {
		logger.Error(module, "Failed to validate client: invalid client ID=[%s]", clientID)
		return errors.New(errors.ErrCodeUnauthorizedClient, "invalid client ID")
	}

	scopes := strings.Split(scopesString, " ")
	for _, scope := range scopes {
		if !client.HasScope(scope) {
			logger.Error(module, "Failed to validate client: client is missing required scope=[%s]", scope)
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

func (c *AuthorizationCodeServiceImpl) markCodeAsUsed(code string, authData *authz.AuthorizationCodeData) error {
	authData.Used = true
	logger.Debug(module, "ValidateAuthorizationCode: Marking authorization code as used")
	if err := c.authzCodeRepo.UpdateAuthorizationCode(code, authData); err != nil {
		logger.Error(module, "ValidateAuthorizationCode: Failed to update authorization code: %v", err)
		return errors.NewInternalServerError()
	}

	return nil
}

func (c *AuthorizationCodeServiceImpl) handlePKCE(req *client.ClientAuthorizationRequest, authData *authz.AuthorizationCodeData) error {
	if req.Client.RequiresPKCE() {
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

func (c *AuthorizationCodeServiceImpl) validateUserAndClient(req *client.ClientAuthorizationRequest) error {
	if user := c.userService.GetUserByID(req.UserID); user == nil {
		logger.Error(module, "Failed to retrieve user: invalid user ID=[%s]", req.UserID)
		return errors.New(errors.ErrCodeUnauthorized, fmt.Sprintf("invalid user ID: %s", common.TruncateSensitive(req.UserID)))
	}

	if err := c.validateClientParameters(req.RedirectURI, req.ClientID, req.Scope); err != nil {
		logger.Error(module, "Failed to validate client=[%s]: %v", common.TruncateSensitive(req.ClientID), err)
		return err
	}

	return nil
}
