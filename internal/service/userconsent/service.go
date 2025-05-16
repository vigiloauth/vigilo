package service

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/vigiloauth/vigilo/v2/idp/config"
	authz "github.com/vigiloauth/vigilo/v2/internal/domain/authzcode"
	clients "github.com/vigiloauth/vigilo/v2/internal/domain/client"
	session "github.com/vigiloauth/vigilo/v2/internal/domain/session"
	users "github.com/vigiloauth/vigilo/v2/internal/domain/user"
	consent "github.com/vigiloauth/vigilo/v2/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/v2/internal/errors"
	"github.com/vigiloauth/vigilo/v2/internal/utils"
	"github.com/vigiloauth/vigilo/v2/internal/web"
)

// Compile-time interface implementation check
var _ consent.UserConsentService = (*userConsentService)(nil)

// userConsentService implements the UserConsentService interface
// and manages user consent-related operations by coordinating
// between consent and user repositories.
type userConsentService struct {
	consentRepo      consent.UserConsentRepository
	userRepo         users.UserRepository
	sessionService   session.SessionService
	clientService    clients.ClientService
	authzCodeService authz.AuthorizationCodeService

	logger *config.Logger
	module string
}

// NewUserConsentService creates a new instance of UserConsentServiceImpl.
//
// Parameters:
//   - consentRepo UserConsentRepository: Repository for managing consent-related data
//   - userRepo UserRepository: Repository for accessing user information
//   - sessionService SessionService: Instance of the SessionService.
//   - clientService ClientService: Instance of the ClientService.
//   - authzCodeService AuthorizationCodeService: Instance of the AuthorizationCodeService.
//
// Returns:
//   - A configured UserConsentService instance
func NewUserConsentService(
	consentRepo consent.UserConsentRepository,
	userRepo users.UserRepository,
	sessionService session.SessionService,
	clientService clients.ClientService,
	authzCodeService authz.AuthorizationCodeService,
) consent.UserConsentService {
	return &userConsentService{
		consentRepo:      consentRepo,
		userRepo:         userRepo,
		sessionService:   sessionService,
		clientService:    clientService,
		authzCodeService: authzCodeService,
		logger:           config.GetServerConfig().Logger(),
		module:           "User Consent Service",
	}
}

// CheckUserConsent verifies if a user has previously granted consent to a client
// for the requested scope.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - userID string: The unique identifier of the user.
//   - clientID string: The identifier of the client application requesting access.
//   - scope string: The space-separated list of permissions being requested.
//
// Returns:
//   - bool: True if consent exists, false if consent is needed.
//   - error: An error if the consent check operation fails.
func (c *userConsentService) CheckUserConsent(ctx context.Context, userID, clientID, scope string) (bool, error) {
	requestID := utils.GetRequestID(ctx)
	if _, err := c.userRepo.GetUserByID(ctx, userID); err != nil {
		c.logger.Error(c.module, requestID, "[CheckUserConsent]: An error occurred retrieving a user by ID: %v", err)
		return false, errors.NewInternalServerError()
	}

	return c.consentRepo.HasConsent(ctx, userID, clientID, scope)
}

// SaveUserConsent records a user's consent for a client application
// to access resources within the specified scope.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - userID string: The unique identifier of the user granting consent.
//   - clientID string: The identifier of the client application receiving consent.
//   - scope string: The space-separated list of permissions being granted.
//
// Returns:
//   - error: An error if the consent cannot be saved, or nil if successful.
func (c *userConsentService) SaveUserConsent(ctx context.Context, userID, clientID, scope string) error {
	requestID := utils.GetRequestID(ctx)
	if _, err := c.userRepo.GetUserByID(ctx, userID); err != nil {
		c.logger.Error(c.module, requestID, "[SaveUserConsent]: An error occurred retrieving the user by ID: %v", err)
		return errors.NewInternalServerError()
	}

	return c.consentRepo.SaveConsent(ctx, userID, clientID, scope)
}

// RevokeConsent removes a user's consent for a client.
//
// Parameters:
//   - ctx Context: The context for managing timeouts and cancellations.
//   - userID string: The ID of the user.
//   - clientID string: The ID of the client application.
//
// Returns:
//   - error: An error if the consent cannot be revoked, or nil if successful.
func (c *userConsentService) RevokeConsent(ctx context.Context, userID, clientID string) error {
	requestID := utils.GetRequestID(ctx)
	if _, err := c.userRepo.GetUserByID(ctx, userID); err != nil {
		c.logger.Error(c.module, requestID, "[RevokeConsent]: An error occurred retrieving the user by ID: %v", err)
		return errors.Wrap(err, "", "failed to revoke user consent")
	}

	return c.consentRepo.RevokeConsent(ctx, userID, clientID)
}

// GetConsentDetails retrieves the details required for the user consent process.
//
// This method fetches information about the client application and the requested scopes,
// and prepares the response to be displayed to the user for consent.
//
// Parameters:
//   - userID string: The unique identifier of the user.
//   - clientID string: The identifier of the client application requesting access.
//   - redirectURI string: The redirect URI provided by the client application.
//   - scope string: The space-separated list of permissions being requested.
//   - r *http.Request: The HTTP request containing session and other metadata.
//
// Returns:
//   - *consent.UserConsentResponse: The response containing client and scope details for the consent process.
//   - error: An error if the details cannot be retrieved or prepared.
func (c *userConsentService) GetConsentDetails(userID, clientID, redirectURI, state, scope, responseType, nonce, display string, r *http.Request) (*consent.UserConsentResponse, error) {
	ctx := r.Context()
	requestID := utils.GetRequestID(ctx)

	if err := c.validateRequest(userID, clientID, redirectURI, scope); err != nil {
		c.logger.Error(c.module, requestID, "[GetConsentDetails]: Failed to retrieve consent details: %v", err)
		wrappedErr := errors.Wrap(err, "", "invalid request parameters")
		return nil, wrappedErr
	}

	client, err := c.clientService.GetClientByID(ctx, clientID)
	if err != nil {
		c.logger.Error(c.module, requestID, "[GetConsentDetails]: An error occurred retrieving client by ID: %v", err)
		return nil, err
	}

	sessionData, err := c.sessionService.GetSessionData(r)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to get session data")
		c.logger.Error(c.module, requestID, "[GetConsentDetails]: Failed to retrieve consent details: %v", err)
		return nil, wrappedErr
	}

	if err := c.updateSessionWithConsentDetails(r, sessionData, clientID, state, redirectURI); err != nil {
		c.logger.Error(c.module, requestID, "[GetConsentDetails]: Failed to update session: %v", err)
		return nil, err
	}

	approved, err := c.CheckUserConsent(ctx, userID, clientID, scope)
	if err != nil {
		c.logger.Error(c.module, requestID, "[GetConsentDetails]: Failed to check user consent: %v", err)
		return nil, err
	}

	if approved {
		c.logger.Debug(c.module, requestID, "[GetConsentDetails]: User has previously given consent. Processing approval.")
		consentRequest := &consent.UserConsentRequest{
			ResponseType: responseType,
			State:        state,
			Nonce:        nonce,
			Display:      display,
		}
		return c.processApprovedConsent(ctx, userID, clientID, redirectURI, scope, consentRequest)
	}

	scopeList := c.parseScopes(scope)
	return &consent.UserConsentResponse{
		Approved:        approved,
		ClientID:        clientID,
		ClientName:      client.Name,
		RedirectURI:     redirectURI,
		Scopes:          scopeList,
		State:           scope,
		ConsentEndpoint: web.OAuthEndpoints.UserConsent,
	}, nil
}

// ProcessUserConsent processes the user's decision for the consent request.
//
// This method handles the user's approval or denial of the requested scopes,
// stores the consent decision if approved, and generates the appropriate response
// (e.g., an authorization code or an error redirect).
//
// Parameters:
//   - userID string: The unique identifier of the user.
//   - clientID string: The identifier of the client application requesting access.
//   - redirectURI string: The redirect URI provided by the client application.
//   - scope string: The space-separated list of permissions being requested.
//   - consentRequest *consent.UserConsentRequest: The user's consent decision and approved scopes.
//   - r *http.Request: The HTTP request containing session and other metadata.
//
// Returns:
//   - *consent.UserConsentResponse: The response containing the result of the consent process (e.g., success or denial).
//   - error: An error if the consent decision cannot be processed or stored.
func (c *userConsentService) ProcessUserConsent(
	userID string,
	clientID string,
	redirectURI string,
	scope string,
	consentRequest *consent.UserConsentRequest,
	r *http.Request,
) (*consent.UserConsentResponse, error) {
	requestID := utils.GetRequestID(r.Context())
	if err := c.validateRequest(userID, clientID, redirectURI, scope); err != nil {
		wrappedErr := errors.Wrap(err, "", "invalid request parameters")
		c.logger.Error(c.module, requestID, "[ProcessUserConsent]: Failed to process user consent: %v", err)
		return nil, wrappedErr
	}

	if !consentRequest.Approved {
		c.logger.Warn(c.module, requestID, "[ProcessUserConsent]: Creating error response for denied consent")
		return c.handleDeniedConsent(consentRequest.State, redirectURI), nil
	}

	return c.processApprovedConsent(r.Context(), userID, clientID, redirectURI, scope, consentRequest)
}

func (c *userConsentService) handleDeniedConsent(state, redirectURI string) *consent.UserConsentResponse {
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

func (c *userConsentService) validateRequest(userID, clientID, redirectURI, scope string) error {
	if userID == "" || clientID == "" || redirectURI == "" || scope == "" {
		c.logger.Error(c.module, "", "Missing required OAuth parameters in request")
		return errors.New(errors.ErrCodeBadRequest, "missing required OAuth parameters")
	}

	return nil
}

func (c *userConsentService) getApprovedScopes(defaultScopes string, requestScopes []string) string {
	if len(requestScopes) > 0 {
		return strings.Join(requestScopes, " ")
	}

	return defaultScopes
}

func (c *userConsentService) processApprovedConsent(
	ctx context.Context,
	userID string,
	clientID string,
	redirectURI string,
	scope string,
	consentRequest *consent.UserConsentRequest,
) (*consent.UserConsentResponse, error) {
	requestID := utils.GetRequestID(ctx)

	approvedScopes := c.getApprovedScopes(scope, consentRequest.Scopes)
	if err := c.consentRepo.SaveConsent(ctx, userID, clientID, approvedScopes); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to save user consent")
		c.logger.Error(c.module, requestID, "Failed to save user consent")
		return nil, wrappedErr
	}

	c.logger.Debug(c.module, requestID, "Building success response for approved consent")
	return &consent.UserConsentResponse{
		Success:  true,
		Approved: true,
	}, nil
}

func (c *userConsentService) updateSessionWithConsentDetails(r *http.Request, sessionData *session.SessionData, clientID, state, redirectURI string) error {
	c.logger.Info(c.module, "", "Updating session with consent details for sessionID=%s, clientID=%s, redirectURI=%s",
		utils.TruncateSensitive(sessionData.ID), utils.TruncateSensitive(clientID), utils.SanitizeURL(redirectURI))

	sessionData.ClientID = clientID
	sessionData.RedirectURI = redirectURI
	sessionData.State = state

	if err := c.sessionService.UpdateSession(r, sessionData); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to update session")
		c.logger.Error(c.module, "", "Failed to update session with consent details: %v", err.Error())
		return wrappedErr
	}

	return nil
}

func (c *userConsentService) parseScopes(scope string) []string {
	return strings.Split(scope, " ")
}
