package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/vigiloauth/vigilo/identity/config"
	"github.com/vigiloauth/vigilo/internal/common"
	"github.com/vigiloauth/vigilo/internal/crypto"
	authz "github.com/vigiloauth/vigilo/internal/domain/authzcode"
	client "github.com/vigiloauth/vigilo/internal/domain/client"
	session "github.com/vigiloauth/vigilo/internal/domain/session"
	users "github.com/vigiloauth/vigilo/internal/domain/user"
	consent "github.com/vigiloauth/vigilo/internal/domain/userconsent"
	"github.com/vigiloauth/vigilo/internal/errors"
	"github.com/vigiloauth/vigilo/internal/web"
)

// UserHandler handles HTTP requests related to OAuth operations.
type OAuthHandler struct {
	userService    users.UserService
	sessionService session.SessionService
	clientService  client.ClientService
	consentService consent.UserConsentService
	codeService    authz.AuthorizationCodeService
	jwtConfig      *config.TokenConfig
}

// NewUserHandler creates a new instance of UserHandler.
//
// Parameters:
//
//	userService UserService: The user service.
//	sessionService Session: The session service.
//	clientService ClientService: The client service
//	consentService ConsentService: The consent service.
//	codeService AuthorizationCodeService: The authorization code service.
//
// Returns:
// *UserHandler: A new UserHandler instance.
func NewOAuthHandler(
	userService users.UserService,
	sessionService session.SessionService,
	clientService client.ClientService,
	consentService consent.UserConsentService,
	codeService authz.AuthorizationCodeService,
) *OAuthHandler {
	return &OAuthHandler{
		userService:    userService,
		sessionService: sessionService,
		clientService:  clientService,
		consentService: consentService,
		codeService:    codeService,
		jwtConfig:      config.GetServerConfig().TokenConfig(),
	}
}

// OAuthLogin handles login specifically for the OAuth authorization code flow
// It expects the same login credentials as the regular Login endpoint,
// but processes the OAuth context parameters and redirects accordingly
func (h *OAuthHandler) OAuthLogin(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	clientID := query.Get(common.ClientID)
	redirectURI := query.Get(common.RedirectURI)

	if clientID == "" || redirectURI == "" {
		web.WriteError(w, errors.New(errors.ErrCodeBadRequest, "missing required OAuth parameters"))
		return
	}

	request, err := web.DecodeJSONRequest[users.UserLoginRequest](w, r)
	if err != nil {
		err = errors.Wrap(err, errors.ErrCodeInternalServerError, "failed to decode request body")
		web.WriteError(w, err)
		return
	}

	if err := request.Validate(); err != nil {
		web.WriteError(w, err)
		return
	}

	user := &users.User{ID: request.ID, Email: request.Email, Password: request.Password}
	loginAttempt := users.NewUserLoginAttempt(
		r.RemoteAddr,
		r.Header.Get(common.XForwardedHeader),
		"", r.UserAgent(),
	)

	response, err := h.userService.AuthenticateUser(user, loginAttempt)
	if err != nil {
		web.WriteError(w, err)
		return
	}

	if err := h.sessionService.CreateSession(w, r, response.UserID, h.jwtConfig.ExpirationTime()); err != nil {
		web.WriteError(w, err)
		return
	}

	oauthRedirectURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s",
		web.OAuthEndpoints.Authorize,
		url.QueryEscape(clientID),
		url.QueryEscape(redirectURI))

	state := query.Get(common.State)
	if state != "" {
		oauthRedirectURL = fmt.Sprintf("%s&state=%s", oauthRedirectURL, url.QueryEscape(state))
	}

	scope := query.Get(common.Scope)
	if scope != "" {
		oauthRedirectURL = fmt.Sprintf("%s&scope=%s", oauthRedirectURL, url.QueryEscape(scope))
	}

	response.OAuthRedirectURL = oauthRedirectURL
	web.WriteJSON(w, http.StatusOK, response)
}

// UserConsent handles user consent decisions for OAuth authorization
func (h *OAuthHandler) UserConsent(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	clientID := query.Get(common.ClientID)
	redirectURI := query.Get(common.RedirectURI)
	scope := query.Get(common.Scope)

	if clientID == "" || redirectURI == "" || scope == "" {
		web.WriteError(w, errors.New(errors.ErrCodeBadRequest, "missing required OAuth parameters"))
		return
	}

	userID := h.sessionService.GetUserIDFromSession(r)
	if userID == "" {
		state := crypto.GenerateUUID()
		oauthLoginURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s&scope=%s&state=%s",
			web.OAuthEndpoints.Login,
			url.QueryEscape(clientID),
			url.QueryEscape(redirectURI),
			url.QueryEscape(scope),
			url.QueryEscape(state))

		web.WriteError(w, errors.NewLoginRequiredError(oauthLoginURL))
		return
	}

	// For GET requests, return client and scope information
	if r.Method == http.MethodGet {
		client := h.clientService.GetClientByID(clientID)
		if client == nil {
			web.WriteError(w, errors.New(errors.ErrCodeInvalidClient, "invalid client_id"))
			return
		}

		state := crypto.GenerateUUID()
		sessionData, err := h.sessionService.GetSessionData(r)
		if err != nil {
			wrappedErr := errors.Wrap(err, "", "failed to get session data")
			web.WriteError(w, wrappedErr)
			return
		}

		sessionData.State = state
		sessionData.ClientID = clientID
		sessionData.RedirectURI = redirectURI

		if err := h.sessionService.UpdateSession(r, sessionData); err != nil {
			wrappedErr := errors.Wrap(err, "", "failed to update session")
			web.WriteError(w, wrappedErr)
			return
		}

		scopeList := strings.Split(scope, " ")
		response := &consent.UserConsentResponse{
			ClientID:        clientID,
			ClientName:      client.Name,
			RedirectURI:     redirectURI,
			Scopes:          scopeList,
			ConsentEndpoint: web.OAuthEndpoints.UserConsent,
			State:           state,
		}

		web.WriteJSON(w, http.StatusOK, response)
		return
	}

	// For POST requests, process consent decision
	if r.Method != http.MethodPost {
		err := errors.New(errors.ErrCodeMethodNotAllowed, "method not allowed")
		web.WriteError(w, err)
		return
	}

	consentRequest, err := web.DecodeJSONRequest[consent.UserConsentRequest](w, r)
	if err != nil {
		err = errors.Wrap(err, errors.ErrCodeInvalidRequest, "failed to decode request body")
		web.WriteError(w, err)
		return
	}

	sessionData, err := h.sessionService.GetSessionData(r)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to get session data")
		web.WriteError(w, wrappedErr)
		return
	}

	state := sessionData.State
	if query.Get(common.State) != state {
		web.WriteError(w, errors.New(errors.ErrCodeInvalidRequest, "state mismatch"))
		return
	}

	if !consentRequest.Approved {
		errorURL := fmt.Sprintf("%s?error=access_denied&error_description=%s",
			redirectURI,
			url.QueryEscape("User denied access to the requested scope"))

		if state != "" {
			errorURL = fmt.Sprintf("%s&state=%s", errorURL, url.QueryEscape(state))
		}

		denialResponse := &consent.UserConsentDenialResponse{
			Error:       errors.ErrCodeAccessDenied,
			RedirectURL: errorURL,
		}

		web.WriteJSON(w, http.StatusOK, denialResponse)
		return
	}

	// Process approved scopes
	approvedScope := scope
	if len(consentRequest.Scopes) > 0 {
		// User approved specific scopes
		approvedScope = strings.Join(consentRequest.Scopes, " ")
	}

	// Store user consent using your ConsentService
	if err := h.consentService.SaveUserConsent(userID, clientID, approvedScope); err != nil {
		web.WriteError(w, errors.Wrap(err, "", "failed to store user consent"))
		return
	}

	// Generate authorization code
	code, err := h.codeService.GenerateAuthorizationCode(userID, clientID, redirectURI, approvedScope)
	if err != nil {
		web.WriteError(w, errors.Wrap(err, "", "failed to generate authorization code"))
		return
	}

	sessionData.State = ""
	if err := h.sessionService.UpdateSession(r, sessionData); err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to update session")
		web.WriteError(w, wrappedErr)
		return
	}

	// Create redirect URL with authorization code
	redirectURL := fmt.Sprintf("%s?code=%s", redirectURI, url.QueryEscape(code))
	if state != "" {
		redirectURL = fmt.Sprintf("%s&state=%s", redirectURL, url.QueryEscape(state))
	}

	successResponse := &consent.UserConsentSuccessResponse{
		Success:     true,
		RedirectURL: redirectURL,
	}

	web.WriteJSON(w, http.StatusOK, successResponse)
}
