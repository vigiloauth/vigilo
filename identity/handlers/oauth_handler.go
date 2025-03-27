package handlers

import (
	"fmt"
	"net/http"
	"net/url"

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

	request, err := web.DecodeJSONRequest[users.UserLoginRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		return
	}

	if err := request.Validate(); err != nil {
		web.WriteError(w, errors.NewRequestValidationError(err))
		return
	}

	response, err := h.userService.HandleOAuthLogin(
		request, clientID,
		redirectURI, r.RemoteAddr,
		r.Header.Get(common.XForwardedHeader),
		r.UserAgent(),
	)

	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to authenticate user")
		web.WriteError(w, wrappedErr)
		return
	}

	if err := h.sessionService.CreateSession(w, r, response.UserID, h.jwtConfig.ExpirationTime()); err != nil {
		web.WriteError(w, errors.NewSessionCreationError(err))
		return
	}

	response.OAuthRedirectURL = h.buildOAuthRedirectURL(query)
	web.WriteJSON(w, http.StatusOK, response)
}

// UserConsent handles user consent decisions for OAuth authorization
func (h *OAuthHandler) UserConsent(w http.ResponseWriter, r *http.Request) {
	query := r.URL.Query()
	clientID := query.Get(common.ClientID)
	redirectURI := query.Get(common.RedirectURI)
	scope := query.Get(common.Scope)

	// Validate required parameters
	if clientID == "" || redirectURI == "" || scope == "" {
		web.WriteError(w, errors.New(errors.ErrCodeBadRequest, "missing required OAuth parameters"))
		return
	}

	// Check if the user is logged in
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

	switch r.Method {
	case http.MethodGet:
		h.handleGetConsent(w, r, userID, clientID, redirectURI, scope)
	case http.MethodPost:
		h.handlePostConsent(w, r, userID, clientID, redirectURI, scope)
	default:
		web.WriteError(w, errors.NewMethodNotAllowedError(r.Method))
	}
}

// handleGetConsent handles GET requests for user consent
func (h *OAuthHandler) handleGetConsent(w http.ResponseWriter, r *http.Request, userID, clientID, redirectURI, scope string) {
	response, err := h.consentService.GetConsentDetails(userID, clientID, redirectURI, scope, r)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to retrieve consent details")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

// handlePostConsent handles POST requests for user consent
func (h *OAuthHandler) handlePostConsent(w http.ResponseWriter, r *http.Request, userID, clientID, redirectURI, scope string) {
	consentRequest, err := web.DecodeJSONRequest[consent.UserConsentRequest](w, r)
	if err != nil {
		web.WriteError(w, errors.NewRequestBodyDecodingError(err))
		web.WriteError(w, err)
		return
	}

	response, err := h.consentService.ProcessUserConsent(userID, clientID, redirectURI, scope, consentRequest, r)
	if err != nil {
		wrappedErr := errors.Wrap(err, "", "failed to process user consent")
		web.WriteError(w, wrappedErr)
		return
	}

	web.WriteJSON(w, http.StatusOK, response)
}

func (h *OAuthHandler) buildOAuthRedirectURL(query url.Values) string {
	redirectURL := fmt.Sprintf("%s?client_id=%s&redirect_uri=%s",
		web.OAuthEndpoints.Authorize,
		url.QueryEscape(common.ClientID),
		url.QueryEscape(common.RedirectURI))

	state := query.Get(common.State)
	if state != "" {
		redirectURL = fmt.Sprintf("%s&state=%s", redirectURL, url.QueryEscape(state))
	}

	scope := query.Get(common.Scope)
	if scope != "" {
		redirectURL = fmt.Sprintf("%s&scope=%s", redirectURL, url.QueryEscape(scope))
	}

	return redirectURL
}
