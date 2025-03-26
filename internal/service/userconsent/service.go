package service

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/vigiloauth/vigilo/internal/common"
	"github.com/vigiloauth/vigilo/internal/crypto"
	authz "github.com/vigiloauth/vigilo/internal/domain/authzcode"
	clients "github.com/vigiloauth/vigilo/internal/domain/client"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	consent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

// Compile-time interface implementation check
var _ consent.UserConsentService = (*UserConsentServiceImpl)(nil)

// UserConsentServiceImpl implements the UserConsentService interface
// and manages user consent-related operations by coordinating
// between consent and user repositories.
type UserConsentServiceImpl struct {
	consentRepo      consent.UserConsentRepository
	userRepo         users.UserRepository
	sessionService   session.SessionService
	clientService    clients.ClientService
	authzCodeService authz.AuthorizationCodeService
}

// NewConsentServiceImpl creates a new instance of UserConsentServiceImpl.
//
// Parameters:
//
//   - consentStore: Repository for managing consent-related data
//   - userRepo: Repository for accessing user information
//
// Returns:
//
//   - A configured UserConsentServiceImpl instance
func NewConsentServiceImpl(
	consentRepo consent.UserConsentRepository,
	userRepo users.UserRepository,
	sessionService session.SessionService,
	clientService clients.ClientService,
	authzCodeService authz.AuthorizationCodeService,
) *UserConsentServiceImpl {
	return &UserConsentServiceImpl{
		consentRepo:      consentRepo,
		userRepo:         userRepo,
		sessionService:   sessionService,
		clientService:    clientService,
		authzCodeService: authzCodeService,
	}
}

// CheckUserConsent verifies if a user has previously granted consent to a client
// for the requested scope.
//
// Parameters:
//
//	userID string: The unique identifier of the user.
//	clientID string: The identifier of the client application requesting access.
//	scope string: The space-separated list of permissions being requested.
//
// Returns:
//
//	bool: True if consent exists, false if consent is needed.
//	error: An error if the consent check operation fails.
func (c *UserConsentServiceImpl) CheckUserConsent(userID, clientID, scope string) (bool, error) {
	if user := c.userRepo.GetUserByID(userID); user == nil {
		return false, errors.New(errors.ErrCodeAccessDenied, "user does not exist with the given ID")
	}

	return c.consentRepo.HasConsent(userID, clientID, scope)
}

// SaveUserConsent records a user's consent for a client application
// to access resources within the specified scope.
//
// Parameters:
//
//	userID string: The unique identifier of the user granting consent.
//	clientID string: The identifier of the client application receiving consent.
//	scope string: The space-separated list of permissions being granted.
//
// Returns:
//
//	error: An error if the consent cannot be saved, or nil if successful.
func (c *UserConsentServiceImpl) SaveUserConsent(userID, clientID, scope string) error {
	if user := c.userRepo.GetUserByID(userID); user == nil {
		return errors.New(errors.ErrCodeAccessDenied, "user does not exist with the given ID")
	}

	return c.consentRepo.SaveConsent(userID, clientID, scope)
}

// RevokeConsent removes a user's consent for a client.
//
// Parameters:
//
//	userID string: The ID of the user.
//	clientID string: The ID of the client application.
//
// Returns:
//
//	error: An error if the consent cannot be revoked, or nil if successful.
func (c *UserConsentServiceImpl) RevokeConsent(userID, clientID string) error {
	if user := c.userRepo.GetUserByID(userID); user == nil {
		return errors.New(errors.ErrCodeAccessDenied, "user does not exist with the given ID")
	}

	return c.consentRepo.RevokeConsent(userID, clientID)
}

// GetConsentDetails retrieves the details required for the user consent process.
//
// This method fetches information about the client application and the requested scopes,
// and prepares the response to be displayed to the user for consent.
//
// Parameters:
//
//   - userID string: The unique identifier of the user.
//   - clientID string: The identifier of the client application requesting access.
//   - redirectURI string: The redirect URI provided by the client application.
//   - scope string: The space-separated list of permissions being requested.
//   - r *http.Request: The HTTP request containing session and other metadata.
//
// Returns:
//
//   - *consent.UserConsentResponse: The response containing client and scope details for the consent process.
//   - error: An error if the details cannot be retrieved or prepared.
func (c *UserConsentServiceImpl) GetConsentDetails(userID, clientID, redirectURI, scope string, r *http.Request) (*consent.UserConsentResponse, error) {
	if clientID == "" || redirectURI == "" || scope == "" {
		return nil, errors.New(errors.ErrCodeBadRequest, "missing required OAuth parameters")
	}

	client := c.clientService.GetClientByID(clientID)
	if client == nil {
		return nil, errors.New(errors.ErrCodeInvalidClient, "invalid client_id")
	}

	state := crypto.GenerateUUID()
	sessionData, err := c.sessionService.GetSessionData(r)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to get session data")
	}

	sessionData.State = state
	sessionData.ClientID = clientID
	sessionData.RedirectURI = redirectURI

	if err := c.sessionService.UpdateSession(r, sessionData); err != nil {
		return nil, errors.Wrap(err, "", "failed to update session")
	}

	scopeList := strings.Split(scope, " ")
	return &consent.UserConsentResponse{
		ClientID:        clientID,
		ClientName:      client.Name,
		RedirectURI:     redirectURI,
		Scopes:          scopeList,
		ConsentEndpoint: web.OAuthEndpoints.UserConsent,
		State:           state,
	}, nil

}

// ProcessUserConsent processes the user's decision for the consent request.
//
// This method handles the user's approval or denial of the requested scopes,
// stores the consent decision if approved, and generates the appropriate response
// (e.g., an authorization code or an error redirect).
//
// Parameters:
//
//   - userID string: The unique identifier of the user.
//   - clientID string: The identifier of the client application requesting access.
//   - redirectURI string: The redirect URI provided by the client application.
//   - scope string: The space-separated list of permissions being requested.
//   - consentRequest *consent.UserConsentRequest: The user's consent decision and approved scopes.
//   - r *http.Request: The HTTP request containing session and other metadata.
//
// Returns:
//
//   - *consent.UserConsentResponse: The response containing the result of the consent process (e.g., success or denial).
//   - error: An error if the consent decision cannot be processed or stored.
func (c *UserConsentServiceImpl) ProcessUserConsent(
	userID, clientID, redirectURI, scope string,
	consentRequest *consent.UserConsentRequest, r *http.Request,
) (*consent.UserConsentResponse, error) {
	if clientID == "" || redirectURI == "" || scope == "" || consentRequest == nil {
		return nil, errors.New(errors.ErrCodeBadRequest, "missing required OAuth parameters")
	}

	sessionData, err := c.sessionService.GetSessionData(r)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to get session data")
	}

	state := sessionData.State
	if r.URL.Query().Get(common.State) != state {
		return nil, errors.New(errors.ErrCodeInvalidRequest, "state mismatch")
	}

	if !consentRequest.Approved {
		errorURL := fmt.Sprintf("%s?error=access_denied&error_description=%s",
			redirectURI, url.QueryEscape("User denied access to the requested scope"))

		if state != "" {
			errorURL = fmt.Sprintf("%s&state=%s", errorURL, url.QueryEscape(state))
		}

		return &consent.UserConsentResponse{
			Error:       errors.ErrCodeAccessDenied,
			RedirectURI: errorURL,
		}, nil
	}

	approvedScopes := scope
	if len(consentRequest.Scopes) > 0 {
		approvedScopes = strings.Join(consentRequest.Scopes, " ")
	}

	if err := c.SaveUserConsent(userID, clientID, approvedScopes); err != nil {
		return nil, errors.Wrap(err, "", "failed to save user consent")
	}

	code, err := c.authzCodeService.GenerateAuthorizationCode(userID, clientID, redirectURI, approvedScopes)
	if err != nil {
		return nil, errors.Wrap(err, "", "failed to generate authorization code")
	}

	sessionData.State = ""
	if err := c.sessionService.UpdateSession(r, sessionData); err != nil {
		return nil, errors.Wrap(err, "", "failed to update session")
	}

	redirectURL := fmt.Sprintf("%s?code=%s", redirectURI, url.QueryEscape(code))
	if state != "" {
		redirectURL = fmt.Sprintf("%s&state=%s", redirectURL, url.QueryEscape(state))
	}

	return &consent.UserConsentResponse{
		Success:     true,
		RedirectURI: redirectURL,
	}, nil
}
