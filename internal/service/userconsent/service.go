package service

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/vigiloauth/vigilo/identity/config"
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
var logger = config.GetServerConfig().Logger()

const module = "User Consent Service"

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

// NewUserConsentServiceImpl creates a new instance of UserConsentServiceImpl.
//
// Parameters:
//
//   - consentStore: Repository for managing consent-related data
//   - userRepo: Repository for accessing user information
//
// Returns:
//
//   - A configured UserConsentServiceImpl instance
func NewUserConsentServiceImpl(
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
		err := errors.New(errors.ErrCodeAccessDenied, "user does not exist with the given ID")
		logger.Error(module, "CheckUserConsent: Failed to check if user has granted consent: %v", err)
		return false, err
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
		err := errors.New(errors.ErrCodeAccessDenied, "user does not exist with the given ID")
		logger.Error(module, "SaveUserConsent: Failed to save user consent: %v", err)
		return err
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
		err := errors.New(errors.ErrCodeAccessDenied, "user does not exist with the given ID")
		logger.Error(module, "RevokeConsent: Failed to revoke user consent: %v", err)
		return err
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
	if err := c.validateRequest(userID, clientID, redirectURI, scope); err != nil {
		logger.Error(module, "GetConsentDetails: Failed to retrieve consent details: %v", err)
		wrappedErr := errors.Wrap(err, "", "invalid request parameters")
		return nil, wrappedErr
	}

	client := c.clientService.GetClientByID(clientID)
	if client == nil {
		err := errors.New(errors.ErrCodeInvalidClient, "invalid client ID")
		logger.Error(module, "GetConsentDetails: Failed to retrieve consent details: %v", err)
		return nil, err
	}

	state := crypto.GenerateUUID()
	sessionData, err := c.sessionService.GetSessionData(r)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to get session data")
		logger.Error(module, "GetConsentDetails: Failed to retrieve consent details: %v", err)
		return nil, wrappedErr
	}

	if err := c.updateSessionWithConsentDetails(r, sessionData, state, clientID, redirectURI); err != nil {
		logger.Error(module, "GetConsentDetails: Failed to update session: %v", err)
		return nil, err
	}

	scopeList := c.parseScopes(scope)
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
	if err := c.validateRequest(userID, clientID, redirectURI, scope); err != nil {
		wrappedErr := errors.Wrap(err, "", "invalid request parameters")
		logger.Error(module, "ProcessUserConsent: Failed to process user consent: %v", err)
		return nil, wrappedErr
	}

	sessionData, err := c.sessionService.ValidateSessionState(r)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to validate session state")
		logger.Error(module, "ProcessUserConsent: Failed to process user consent: %v", err)
		return nil, wrappedErr
	}

	if !consentRequest.Approved {
		logger.Info(module, "ProcessUserConsent: Creating error response for denied consent")
		return c.handleDeniedConsent(sessionData.State, redirectURI), nil
	}

	return c.processApprovedConsent(userID, clientID, redirectURI, scope, consentRequest, sessionData)
}

func (c *UserConsentServiceImpl) handleDeniedConsent(state, redirectURI string) *consent.UserConsentResponse {
	errorURL := fmt.Sprintf("%s?error=access_denied&error_description=%s",
		redirectURI, url.QueryEscape("user denied access to the requested scope"))

	if state != "" {
		errorURL = fmt.Sprintf("%s&state=%s", errorURL, url.QueryEscape(state))
	}

	return &consent.UserConsentResponse{
		Error:       errors.ErrCodeAccessDenied,
		RedirectURI: errorURL,
	}
}

func (c *UserConsentServiceImpl) validateRequest(userID, clientID, redirectURI, scope string) error {
	if userID == "" || clientID == "" || redirectURI == "" || scope == "" {
		logger.Error(module, "Missing required OAuth parameters in request")
		return errors.New(errors.ErrCodeBadRequest, "missing required OAuth parameters")
	}
	return nil
}

func (c *UserConsentServiceImpl) getApprovedScopes(defaultScopes string, requestScopes []string) string {
	if len(requestScopes) > 0 {
		return strings.Join(requestScopes, " ")
	}
	return defaultScopes
}

func (c *UserConsentServiceImpl) processApprovedConsent(
	userID, clientID, redirectURI, scope string,
	consentRequest *consent.UserConsentRequest,
	sessionData *session.SessionData,
) (*consent.UserConsentResponse, error) {
	approvedScopes := c.getApprovedScopes(scope, consentRequest.Scopes)
	if err := c.consentRepo.SaveConsent(userID, clientID, approvedScopes); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to save user consent")
		logger.Error(module, "Failed to save user consent")
		return nil, wrappedErr
	}

	authorizationCodeRequest := &clients.ClientAuthorizationRequest{
		ClientID:     clientID,
		UserID:       userID,
		Scope:        approvedScopes,
		RedirectURI:  redirectURI,
		ResponseType: clients.CodeResponseType,
	}

	client := c.clientService.GetClientByID(clientID)
	if client == nil {
		err := errors.New(errors.ErrCodeInvalidClient, "invalid client ID")
		logger.Error(module, "Failed to process user consent: %v", err)
		return nil, err
	}

	authorizationCodeRequest.Client = client
	code, err := c.authzCodeService.GenerateAuthorizationCode(authorizationCodeRequest)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to generate authorization code")
		logger.Error(module, "Failed to generate authorization code: %v", err)
		return nil, wrappedErr
	}

	if err := c.sessionService.ClearStateFromSession(sessionData); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to clear state from session")
		logger.Error(module, "Failed to clear state from session: %v", err)
		return nil, wrappedErr
	}

	logger.Info(module, "Building success response for approved consent")
	return c.buildSuccessResponse(redirectURI, code, sessionData.State), nil
}

func (c *UserConsentServiceImpl) buildSuccessResponse(redirectURI, code, state string) *consent.UserConsentResponse {
	logger.Debug(module, "Building success response with redirectURI=%s, code=%s, state=%s",
		common.SanitizeURL(redirectURI), common.TruncateSensitive(code), common.TruncateSensitive(state))

	redirectURL := fmt.Sprintf("%s?code=%s", redirectURI, url.QueryEscape(code))
	if state != "" {
		redirectURL = fmt.Sprintf("%s&state=%s", redirectURL, url.QueryEscape(state))
	}

	response := &consent.UserConsentResponse{
		Success:     true,
		RedirectURI: redirectURL,
	}

	return response
}

func (c *UserConsentServiceImpl) updateSessionWithConsentDetails(r *http.Request, sessionData *session.SessionData, state, clientID, redirectURI string) error {
	logger.Info(module, "Updating session with consent details for sessionID=%s, clientID=%s, redirectURI=%s",
		common.TruncateSensitive(sessionData.ID), common.TruncateSensitive(clientID), common.SanitizeURL(redirectURI))

	sessionData.State = state
	sessionData.ClientID = clientID
	sessionData.RedirectURI = redirectURI

	if err := c.sessionService.UpdateSession(r, sessionData); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to update session")
		logger.Error(module, "Failed to update session with consent details: %v", err.Error())
		return wrappedErr
	}

	logger.Info(module, "Session updated successfully for sessionID=%s", common.TruncateSensitive(sessionData.ID))
	return nil
}

func (c *UserConsentServiceImpl) parseScopes(scope string) []string {
	return strings.Split(scope, " ")
}
