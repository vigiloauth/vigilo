package service

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
	"sync/atomic"
	"time"

	authz "github.com/vigiloauth/vigilo/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	user "github.com/vigiloauth/vigilo/internal/domain/user"
	"github.com/vigiloauth/vigilo/internal/errors"
)

var _ authz.AuthorizationCodeService = (*AuthorizationCodeServiceImpl)(nil)

type AuthorizationCodeServiceImpl struct {
	authzCodeRepo authz.AuthorizationCodeRepository
	userService   user.UserService
	clientService client.ClientService
	codeLifeTime  atomic.Value
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
	duration := 10 * time.Minute
	service := &AuthorizationCodeServiceImpl{
		authzCodeRepo: authzCodeRepo,
		userService:   userService,
		clientService: clientService,
	}
	service.codeLifeTime.Store(duration)
	return service
}

// GenerateAuthorizationCode creates a new authorization code and stores it with associated data.
//
// Parameters:
//
//	userID string: The user who authorized the client.
//	clientID string: The client requesting authorization.
//	redirectURI string: The URI to redirect after authorization.
//	scope string: The authorized scope(s).
//
// Returns:
//
//	string: The generated authorization code.
//	error: An error if code generation fails.
func (c *AuthorizationCodeServiceImpl) GenerateAuthorizationCode(userID, clientID, redirectURI, scope string) (string, error) {
	if userID == "" || clientID == "" || redirectURI == "" || scope == "" {
		return "", errors.New(errors.ErrCodeEmptyInput, "missing one or more parameters")
	}

	if user := c.userService.GetUserByID(userID); user == nil {
		return "", errors.New(errors.ErrCodeUnauthorized, "invalid user_id")
	}

	if err := c.validateClient(redirectURI, clientID, scope); err != nil {
		return "", errors.Wrap(err, errors.ErrCodeInvalidClient, "invalid client")
	}

	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		return "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to generate authorization code")
	}

	code := base64.RawURLEncoding.EncodeToString(codeBytes)
	authData := &authz.AuthorizationCodeData{
		UserID:      userID,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       scope,
		CreatedAt:   time.Now(),
		Code:        code,
		Used:        false,
	}

	expiresAt := authData.CreatedAt.Add(c.codeLifeTime.Load().(time.Duration))
	if err := c.authzCodeRepo.StoreAuthorizationCode(code, authData, expiresAt); err != nil {
		return "", errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to store authorization code")
	}

	return code, nil
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
		return nil, errors.New(errors.ErrCodeEmptyInput, "missing one or more parameters")
	}

	authData, exists, err := c.authzCodeRepo.GetAuthorizationCode(code)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to retrieve the authorization code")
	}
	if !exists {
		return nil, errors.New(errors.ErrCodeInvalidGrant, "authorization code not found or expired")
	}

	if authData.Used {
		return nil, errors.New(errors.ErrCodeInvalidGrant, "authorization code already used")
	}

	if authData.ClientID != clientID {
		return nil, errors.New(errors.ErrCodeInvalidGrant, "authorization code client ID and request client ID do no match")
	}

	if authData.RedirectURI != redirectURI {
		return nil, errors.New(errors.ErrCodeInvalidGrant, "authorization code redirect URI and request redirect URI do no match")
	}

	// Mark the code as used
	authData.Used = true
	if err := c.authzCodeRepo.UpdateAuthorizationCode(code, authData); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to update authorization code")
	}

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
	return c.authzCodeRepo.DeleteAuthorizationCode(code)
}

// SetAuthorizationCodeLifeTime configures how long authorization codes remain valid.
//
// Parameters:
//
//	lifetime time.Duration: The validity period for new codes.
func (c *AuthorizationCodeServiceImpl) SetAuthorizationCodeLifeTime(lifetime time.Duration) {
	c.codeLifeTime.Store(lifetime)
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

func (c AuthorizationCodeServiceImpl) validateClient(redirectURI, clientID, scopesString string) error {
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

	if !client.IsConfidential() {
		return errors.New(errors.ErrCodeUnauthorizedClient, "client must be confidential to process the request")
	}

	if err := c.clientService.ValidateClientRedirectURI(redirectURI, client); err != nil {
		return errors.Wrap(err, errors.ErrCodeInvalidRedirectURI, "invalid redirect URI")
	}

	return nil
}
