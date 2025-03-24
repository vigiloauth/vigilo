package service

import (
	"crypto/rand"
	"encoding/base64"
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
func (c *AuthorizationCodeServiceImpl) ValidateAuthorizationCode(
	code, clientID, redirectURI string,
) (*authz.AuthorizationCodeData, error) {
	if code == "" || clientID == "" || redirectURI == "" {
		return nil, errors.New(errors.ErrCodeEmptyInput, "missing one or more parameters")
	}

	authData, exists, err := c.authzCodeRepo.GetAuthorizationCode(code)
	if err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to retrieve the authorization code")
	}
	if !exists {
		return nil, errors.New(errors.ErrCodeInvalidGrantType, "authorization code not found or expired")
	}

	if authData.ClientID != clientID {
		if err := c.authzCodeRepo.DeleteAuthorizationCode(code); err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to invalidate authorization code")
		}
		return nil, errors.New(errors.ErrCodeInvalidGrantType, "client ID mismatch")
	}

	if authData.RedirectURI != redirectURI {
		if err := c.authzCodeRepo.DeleteAuthorizationCode(code); err != nil {
			return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to invalidate authorization code")
		}
		return nil, errors.New(errors.ErrCodeInvalidGrantType, "redirect URI mismatch")
	}

	if err := c.authzCodeRepo.DeleteAuthorizationCode(code); err != nil {
		return nil, errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to invalidate authorization code")
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

func (c AuthorizationCodeServiceImpl) validateClient(redirectURI, clientID, scope string) error {
	client := c.clientService.GetClientByID(clientID)
	if client == nil {
		return errors.New(errors.ErrCodeUnauthorizedClient, "invalid client_id")
	}

	if !client.IsConfidential() {
		return errors.New(errors.ErrCodeUnauthorizedClient, "client must be confidential")
	}

	if !client.HasScope(scope) {
		return errors.New(errors.ErrCodeInvalidScope, "missing required scopes")
	}

	if err := c.clientService.ValidateClientRedirectURI(redirectURI, client); err != nil {
		return errors.Wrap(err, errors.ErrCodeInvalidRedirectURI, "invalid redirect_uri")
	}

	return nil
}
